package artifacts

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

const maxXarSignatureBytes = 16 << 10

// xarChecksumHash maps the header checksum algorithm to a hash. Apple's xar
// defines 3 as SHA-256 and 4 as SHA-512; the original xar format instead uses
// 3 for a hash named in the bytes after the fixed header, which is honored
// when such a name is present.
func xarChecksumHash(algorithm uint32, name string) (crypto.Hash, string, error) {
	switch algorithm {
	case 0:
		return 0, "", fmt.Errorf("package table of contents has no checksum")
	case 1:
		return crypto.SHA1, "sha1", nil
	case 2:
		return 0, "", errUnsupportedf("package table of contents checksum md5 is not supported")
	case 3:
		switch name {
		case "", "sha256":
			return crypto.SHA256, "sha256", nil
		case "sha384":
			return crypto.SHA384, name, nil
		case "sha512":
			return crypto.SHA512, name, nil
		}
		return 0, "", errUnsupportedf("package table of contents checksum %q is not supported", name)
	case 4:
		return crypto.SHA512, "sha512", nil
	}
	return 0, "", errUnsupportedf("package table of contents checksum algorithm %d is not supported", algorithm)
}

// verifyXarSignature checks the classic RSA signature of a flat package: the
// heap checksum must match the compressed table of contents, the signature
// must cover that checksum, and the signer must chain to an Apple root. File
// payloads are covered only through their table of contents checksums, which
// are not recomputed.
func verifyXarSignature(source io.ReaderAt, size int64, document *xarDocument, status string, signatureErr error, policy *trustPolicy) SignatureVerification {
	switch {
	case status == SignatureUnreadable:
		detail := "package signature could not be read"
		if signatureErr != nil {
			detail += ": " + signatureErr.Error()
		}
		return SignatureVerification{Status: VerificationUnsupported, Detail: detail}
	case document.Signature == nil && document.XSignature != nil:
		return SignatureVerification{Status: VerificationUnsupported, Detail: "package has only a CMS x-signature, which is not verified"}
	case document.Signature == nil:
		return SignatureVerification{Status: VerificationInvalid, Detail: "package is unsigned"}
	}
	checksum, err := verifiedXarChecksum(source, size, document)
	if err != nil {
		return failedVerification(err)
	}
	leaf, carried, err := verifyXarRSASignature(source, size, document, checksum)
	if err != nil {
		return failedVerification(err)
	}
	chain := policy.evaluateChain(leaf, carried)
	if chain.Status != VerificationValid {
		chain.Detail = "table of contents checksum and RSA signature verified, but " + chain.Detail
		return chain
	}
	chain.Detail = "table of contents checksum and RSA signature verified; " + chain.Detail + "; file payload checksums"
	if document.XSignature != nil {
		chain.Detail += ", the CMS x-signature,"
	}
	chain.Detail += " and revocation were not checked"
	return chain
}

type xarChecksum struct {
	hash  crypto.Hash
	value []byte
	heap  int64
}

func verifiedXarChecksum(source io.ReaderAt, size int64, document *xarDocument) (xarChecksum, error) {
	header := make([]byte, 28)
	if _, err := source.ReadAt(header, 0); err != nil {
		return xarChecksum{}, fmt.Errorf("read xar header: %w", err)
	}
	headerSize := int64(binary.BigEndian.Uint16(header[4:6]))
	tocCompressed := int64(binary.BigEndian.Uint64(header[8:16]))
	if headerSize < 28 || headerSize > size || tocCompressed < 0 || tocCompressed > maxXarTOCBytes || tocCompressed > size-headerSize {
		return xarChecksum{}, fmt.Errorf("xar header is malformed")
	}
	name := ""
	if headerSize > 28 {
		extra := make([]byte, min(headerSize-28, 64))
		if _, err := source.ReadAt(extra, 28); err != nil {
			return xarChecksum{}, fmt.Errorf("read xar header: %w", err)
		}
		if end := bytes.IndexByte(extra, 0); end >= 0 {
			extra = extra[:end]
		}
		name = strings.ToLower(string(extra))
	}
	hashAlgorithm, style, err := xarChecksumHash(binary.BigEndian.Uint32(header[24:28]), name)
	if err != nil {
		return xarChecksum{}, err
	}
	declared := document.Checksum
	if declared == nil || !strings.EqualFold(declared.Style, style) {
		return xarChecksum{}, fmt.Errorf("table of contents checksum does not match the header algorithm %s", style)
	}
	heap := headerSize + tocCompressed
	stored, err := readXarHeap(source, size, heap, *declared, int64(hashAlgorithm.Size()), "table of contents checksum")
	if err != nil {
		return xarChecksum{}, err
	}
	hasher := hashAlgorithm.New()
	if _, err := io.Copy(hasher, io.NewSectionReader(source, headerSize, tocCompressed)); err != nil {
		return xarChecksum{}, fmt.Errorf("read xar table of contents: %w", err)
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), stored) != 1 {
		return xarChecksum{}, fmt.Errorf("table of contents checksum does not match the table of contents")
	}
	return xarChecksum{hash: hashAlgorithm, value: stored, heap: heap}, nil
}

func readXarHeap(source io.ReaderAt, size, heap int64, location xarHeapRange, wantSize int64, name string) ([]byte, error) {
	if location.Offset < 0 || location.Size <= 0 || location.Size > maxXarSignatureBytes || (wantSize > 0 && location.Size != wantSize) {
		return nil, fmt.Errorf("%s has an invalid size", name)
	}
	if location.Offset > size-heap || location.Size > size-heap-location.Offset {
		return nil, fmt.Errorf("%s is outside the package", name)
	}
	data := make([]byte, location.Size)
	if _, err := source.ReadAt(data, heap+location.Offset); err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}

func verifyXarRSASignature(source io.ReaderAt, size int64, document *xarDocument, checksum xarChecksum) (*x509.Certificate, []*x509.Certificate, error) {
	signature := document.Signature
	if !strings.EqualFold(signature.Style, "RSA") {
		return nil, nil, errUnsupportedf("package signature style %q is not supported", signature.Style)
	}
	certificates, err := xarCertificates(signature)
	if err != nil {
		return nil, nil, err
	}
	public, ok := certificates[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errUnsupportedf("package signing certificate does not hold an RSA key")
	}
	value, err := readXarHeap(source, size, checksum.heap, signature.xarHeapRange, 0, "package signature")
	if err != nil {
		return nil, nil, err
	}
	// xar signs the checksum as a precomputed digest of its algorithm.
	if err := rsa.VerifyPKCS1v15(public, checksum.hash, checksum.value, value); err != nil {
		return nil, nil, fmt.Errorf("package RSA signature does not verify over the table of contents checksum")
	}
	return certificates[0], certificates[1:], nil
}

func xarCertificates(signature *xarSignature) ([]*x509.Certificate, error) {
	if len(signature.Certificates) == 0 || len(signature.Certificates) > maxXarSignerCertCount {
		return nil, fmt.Errorf("package signature lists %d certificates", len(signature.Certificates))
	}
	certificates := make([]*x509.Certificate, 0, len(signature.Certificates))
	for _, encoded := range signature.Certificates {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
		if err != nil {
			return nil, fmt.Errorf("decode package certificate: %w", err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse package certificate: %w", err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}
