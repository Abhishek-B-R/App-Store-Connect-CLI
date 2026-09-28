package artifacts

import (
	"crypto/sha1" //nolint:gosec // SHA-1 matches the identity hash codesign and security print; it is not used for trust.
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"go.mozilla.org/pkcs7"
)

// Signature statuses reported for a main executable or a flat package.
const (
	SignatureSigned     = "signed"
	SignatureAdHoc      = "ad-hoc"
	SignatureUnsigned   = "unsigned"
	SignatureUnreadable = "unreadable"
)

const (
	maxLoadCommandBytes   = 4 << 20
	maxFatArchitectures   = 32
	maxSuperblobSlots     = 256
	maxSignatureCMSBytes  = 256 << 10
	maxXarSignerCertCount = 32

	loadCommandCodeSignature = 0x1d

	magicEmbeddedSignature = 0xfade0cc0
	magicBlobWrapper       = 0xfade0b01
	slotCodeDirectory      = 0x0
	slotAlternateFirst     = 0x1000
	slotAlternateLast      = 0x1004
	slotCMSSignature       = 0x10000
)

// oidUserID is the subject attribute Apple repeats the team identifier in.
var oidUserID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}

// SignerIdentity describes the leaf certificate embedded in a signature. It is
// read from the artifact and is not validated against a trust store.
type SignerIdentity struct {
	CommonName        string
	TeamID            string
	Organization      string
	IssuerCommonName  string
	SerialNumber      string
	NotBefore         string
	NotAfter          string
	SHA1Fingerprint   string
	SHA256Fingerprint string
}

// forwardReader reads a stream in increasing offset order. Seekable sources skip
// without reading; others discard the skipped bytes.
type forwardReader struct {
	source io.Reader
	pos    int64
	size   int64
	// capture, when set, receives the classified slice's code signature.
	capture *signatureCapture
}

func (reader *forwardReader) skipTo(offset int64) error {
	if offset < reader.pos {
		return fmt.Errorf("Mach-O signature offsets are out of order")
	}
	if offset > reader.size {
		return fmt.Errorf("Mach-O offset %d is beyond the executable", offset)
	}
	distance := offset - reader.pos
	if seeker, ok := reader.source.(io.Seeker); ok {
		if _, err := seeker.Seek(distance, io.SeekCurrent); err != nil {
			return err
		}
	} else if _, err := io.CopyN(io.Discard, reader.source, distance); err != nil {
		return err
	}
	reader.pos = offset
	return nil
}

func (reader *forwardReader) read(length int64) ([]byte, error) {
	if length < 0 || length > reader.size-reader.pos {
		return nil, fmt.Errorf("Mach-O executable is truncated")
	}
	data := make([]byte, int(length))
	if _, err := io.ReadFull(reader.source, data); err != nil {
		return nil, fmt.Errorf("Mach-O executable is truncated: %w", err)
	}
	reader.pos += length
	return data, nil
}

// readMachOSignature classifies the code signature of a thin or universal
// Mach-O executable and extracts the CMS signer's leaf certificate. For a
// universal binary it reads the slice stored first, so the source is consumed
// once, front to back. A non-nil error always comes with SignatureUnreadable.
func readMachOSignature(source io.Reader, size int64) (string, *SignerIdentity, error) {
	return readMachOSignatureCapture(source, size, nil)
}

// readMachOSignatureCapture is readMachOSignature that also keeps the code
// signature in capture when capture is non-nil.
func readMachOSignatureCapture(source io.Reader, size int64, capture *signatureCapture) (string, *SignerIdentity, error) {
	status, signer, err := readMachOSignatureStream(&forwardReader{source: source, size: size, capture: capture})
	if err != nil {
		return SignatureUnreadable, nil, err
	}
	return status, signer, nil
}

func readMachOSignatureStream(reader *forwardReader) (string, *SignerIdentity, error) {
	magic, err := reader.read(4)
	if err != nil {
		return "", nil, err
	}
	switch binary.BigEndian.Uint32(magic) {
	case 0xcafebabe, 0xcafebabf:
		return readFatSignature(reader, binary.BigEndian.Uint32(magic) == 0xcafebabf)
	}
	return readThinSignature(reader, magic, 0, reader.size)
}

func readFatSignature(reader *forwardReader, wide bool) (string, *SignerIdentity, error) {
	countBytes, err := reader.read(4)
	if err != nil {
		return "", nil, err
	}
	count := binary.BigEndian.Uint32(countBytes)
	if count == 0 || count > maxFatArchitectures {
		return "", nil, fmt.Errorf("universal binary declares %d architectures", count)
	}
	entrySize := int64(20)
	if wide {
		entrySize = 32
	}
	table, err := reader.read(int64(count) * entrySize)
	if err != nil {
		return "", nil, err
	}
	first, firstSize := uint64(0), uint64(0)
	for index := range int64(count) {
		entry := table[index*entrySize:]
		var offset, sliceSize uint64
		if wide {
			offset, sliceSize = binary.BigEndian.Uint64(entry[8:16]), binary.BigEndian.Uint64(entry[16:24])
		} else {
			offset, sliceSize = uint64(binary.BigEndian.Uint32(entry[8:12])), uint64(binary.BigEndian.Uint32(entry[12:16]))
		}
		if offset < uint64(reader.pos) || offset > uint64(reader.size) || sliceSize > uint64(reader.size)-offset {
			return "", nil, fmt.Errorf("universal binary slice is outside the executable")
		}
		if index == 0 || offset < first {
			first, firstSize = offset, sliceSize
		}
	}
	if err := reader.skipTo(int64(first)); err != nil {
		return "", nil, err
	}
	magic, err := reader.read(4)
	if err != nil {
		return "", nil, err
	}
	return readThinSignature(reader, magic, int64(first), int64(firstSize))
}

func readThinSignature(reader *forwardReader, magic []byte, base, sliceSize int64) (string, *SignerIdentity, error) {
	var order binary.ByteOrder
	var headerSize int64
	switch {
	case binary.LittleEndian.Uint32(magic) == 0xfeedface:
		order, headerSize = binary.LittleEndian, 28
	case binary.LittleEndian.Uint32(magic) == 0xfeedfacf:
		order, headerSize = binary.LittleEndian, 32
	case binary.BigEndian.Uint32(magic) == 0xfeedface:
		order, headerSize = binary.BigEndian, 28
	case binary.BigEndian.Uint32(magic) == 0xfeedfacf:
		order, headerSize = binary.BigEndian, 32
	default:
		return "", nil, fmt.Errorf("main executable is not a Mach-O file")
	}
	header, err := reader.read(headerSize - 4)
	if err != nil {
		return "", nil, err
	}
	commandCount := int64(order.Uint32(header[12:16]))
	commandBytes := int64(order.Uint32(header[16:20]))
	if commandBytes > maxLoadCommandBytes || commandBytes > sliceSize-headerSize || commandCount > commandBytes/8 {
		return "", nil, fmt.Errorf("Mach-O load commands exceed the read limit")
	}
	commands, err := reader.read(commandBytes)
	if err != nil {
		return "", nil, err
	}
	var dataOffset, dataSize int64
	found := false
	for index, offset := int64(0), int64(0); index < commandCount; index++ {
		if offset+8 > commandBytes {
			return "", nil, fmt.Errorf("Mach-O load command table is truncated")
		}
		command := order.Uint32(commands[offset:])
		commandSize := int64(order.Uint32(commands[offset+4:]))
		if commandSize < 8 || commandSize > commandBytes-offset {
			return "", nil, fmt.Errorf("Mach-O load command has an invalid size")
		}
		if command == loadCommandCodeSignature {
			if found {
				return "", nil, fmt.Errorf("Mach-O has multiple code signature commands")
			}
			if commandSize < 16 {
				return "", nil, fmt.Errorf("Mach-O code signature command is truncated")
			}
			found = true
			dataOffset = int64(order.Uint32(commands[offset+8:]))
			dataSize = int64(order.Uint32(commands[offset+12:]))
		}
		offset += commandSize
	}
	if !found {
		return SignatureUnsigned, nil, nil
	}
	if dataOffset < headerSize+commandBytes || dataSize < 12 || dataOffset > sliceSize || dataSize > sliceSize-dataOffset {
		return "", nil, fmt.Errorf("Mach-O code signature is outside the executable")
	}
	if err := reader.skipTo(base + dataOffset); err != nil {
		return "", nil, err
	}
	if reader.capture != nil {
		return captureSuperblob(reader, base, sliceSize, dataSize)
	}
	return readSuperblob(reader, dataSize)
}

func readSuperblob(reader *forwardReader, limit int64) (string, *SignerIdentity, error) {
	start := reader.pos
	header, err := reader.read(12)
	if err != nil {
		return "", nil, err
	}
	if binary.BigEndian.Uint32(header) != magicEmbeddedSignature {
		return "", nil, fmt.Errorf("code signature has an unknown superblob type")
	}
	length := int64(binary.BigEndian.Uint32(header[4:8]))
	count := int64(binary.BigEndian.Uint32(header[8:12]))
	if length < 12 || length > limit {
		return "", nil, fmt.Errorf("code signature superblob length is invalid")
	}
	if count > maxSuperblobSlots || 12+8*count > length {
		return "", nil, fmt.Errorf("code signature superblob index is invalid")
	}
	index, err := reader.read(8 * count)
	if err != nil {
		return "", nil, err
	}
	hasCodeDirectory := false
	cmsOffset := int64(-1)
	for slot := range count {
		kind := binary.BigEndian.Uint32(index[slot*8:])
		offset := int64(binary.BigEndian.Uint32(index[slot*8+4:]))
		if offset < 12+8*count || offset+8 > length {
			return "", nil, fmt.Errorf("code signature slot is outside the superblob")
		}
		switch {
		case kind == slotCodeDirectory || (kind >= slotAlternateFirst && kind <= slotAlternateLast):
			hasCodeDirectory = true
		case kind == slotCMSSignature:
			if cmsOffset >= 0 {
				return "", nil, fmt.Errorf("code signature has multiple CMS slots")
			}
			cmsOffset = offset
		}
	}
	if !hasCodeDirectory {
		return "", nil, fmt.Errorf("code signature has no code directory")
	}
	if cmsOffset < 0 {
		return SignatureAdHoc, nil, nil
	}
	if err := reader.skipTo(start + cmsOffset); err != nil {
		return "", nil, err
	}
	wrapper, err := reader.read(8)
	if err != nil {
		return "", nil, err
	}
	if binary.BigEndian.Uint32(wrapper) != magicBlobWrapper {
		return "", nil, fmt.Errorf("code signature CMS slot has an unknown blob type")
	}
	blobLength := int64(binary.BigEndian.Uint32(wrapper[4:8]))
	if blobLength < 8 || blobLength > length-cmsOffset {
		return "", nil, fmt.Errorf("code signature CMS blob length is invalid")
	}
	if blobLength == 8 {
		// codesign writes an empty wrapper for ad-hoc signatures.
		return SignatureAdHoc, nil, nil
	}
	if blobLength-8 > maxSignatureCMSBytes {
		return "", nil, fmt.Errorf("code signature CMS blob exceeds %d bytes", maxSignatureCMSBytes)
	}
	cms, err := reader.read(blobLength - 8)
	if err != nil {
		return "", nil, err
	}
	signer, err := signerFromCMS(cms)
	if err != nil {
		return "", nil, err
	}
	return SignatureSigned, signer, nil
}

func signerFromCMS(data []byte) (signer *SignerIdentity, err error) {
	defer func() {
		// The CMS parser indexes untrusted BER; keep a malformed blob from
		// taking down an otherwise readable inspection.
		if recovered := recover(); recovered != nil {
			signer, err = nil, fmt.Errorf("parse code signature CMS: malformed input")
		}
	}()
	parsed, err := pkcs7.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse code signature CMS: %w", err)
	}
	leaf := parsed.GetOnlySigner()
	if leaf == nil {
		return nil, fmt.Errorf("code signature CMS does not name exactly one signer certificate")
	}
	return signerIdentity(leaf), nil
}

func signerIdentity(certificate *x509.Certificate) *SignerIdentity {
	sha1Sum := sha1.Sum(certificate.Raw) //nolint:gosec // identity hash, not a trust decision.
	sha256Sum := sha256.Sum256(certificate.Raw)
	teamID := ""
	if len(certificate.Subject.OrganizationalUnit) > 0 {
		teamID = certificate.Subject.OrganizationalUnit[0]
	}
	if teamID == "" {
		for _, name := range certificate.Subject.Names {
			if value, ok := name.Value.(string); ok && name.Type.Equal(oidUserID) {
				teamID = value
				break
			}
		}
	}
	organization := ""
	if len(certificate.Subject.Organization) > 0 {
		organization = certificate.Subject.Organization[0]
	}
	serial := ""
	if certificate.SerialNumber != nil {
		serial = strings.ToUpper(certificate.SerialNumber.Text(16))
	}
	return &SignerIdentity{
		CommonName:        certificate.Subject.CommonName,
		TeamID:            teamID,
		Organization:      organization,
		IssuerCommonName:  certificate.Issuer.CommonName,
		SerialNumber:      serial,
		NotBefore:         certificate.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:          certificate.NotAfter.UTC().Format(time.RFC3339),
		SHA1Fingerprint:   fmt.Sprintf("%X", sha1Sum),
		SHA256Fingerprint: fmt.Sprintf("%X", sha256Sum),
	}
}

type xarSignature struct {
	xarHeapRange
	Certificates []string `xml:"KeyInfo>X509Data>X509Certificate"`
}

// xarSigner reads the leaf certificate from a xar table of contents. productsign
// writes the signing certificate first, followed by its issuers.
func xarSigner(signatures ...*xarSignature) (string, *SignerIdentity, error) {
	for _, signature := range signatures {
		if signature == nil {
			continue
		}
		if len(signature.Certificates) == 0 {
			return SignatureUnreadable, nil, fmt.Errorf("package signature has no certificates")
		}
		if len(signature.Certificates) > maxXarSignerCertCount {
			return SignatureUnreadable, nil, fmt.Errorf("package signature lists more than %d certificates", maxXarSignerCertCount)
		}
		encoded := strings.Join(strings.Fields(signature.Certificates[0]), "")
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return SignatureUnreadable, nil, fmt.Errorf("decode package signing certificate: %w", err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return SignatureUnreadable, nil, fmt.Errorf("parse package signing certificate: %w", err)
		}
		return SignatureSigned, signerIdentity(certificate), nil
	}
	return SignatureUnsigned, nil, nil
}
