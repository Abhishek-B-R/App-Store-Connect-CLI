package artifactstest

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // xar and code directories use SHA-1 as a format hash.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"sort"
	"strconv"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
)

// TrustChain is a throwaway root, intermediate, and RSA leaf. The leaf carries
// a critical Apple code-signing marker extension, like real Apple leaves.
type TrustChain struct {
	Root         *x509.Certificate
	Intermediate *x509.Certificate
	Leaf         *x509.Certificate
	LeafKey      *rsa.PrivateKey
}

var oidAppleDistributionMarker = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 4}

// NewTrustChain issues a chain whose leaf is valid from notBefore to notAfter.
func NewTrustChain(t testing.TB, notBefore, notAfter time.Time) TrustChain {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caStart, caEnd := notBefore.AddDate(-5, 0, 0), notAfter.AddDate(5, 0, 0)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root CA"},
		NotBefore: caStart, NotAfter: caEnd, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	root := createCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediate := createCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: IssuerCommonName},
		NotBefore: caStart, NotAfter: caEnd, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, root, &intermediateKey.PublicKey, rootKey)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := createCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: SignerCommonName, OrganizationalUnit: []string{TeamID}, Organization: []string{"Example Corp"}},
		NotBefore:    notBefore, NotAfter: notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{Id: oidAppleDistributionMarker, Critical: true, Value: []byte{0x05, 0x00}}},
	}, intermediate, &leafKey.PublicKey, intermediateKey)
	return TrustChain{Root: root, Intermediate: intermediate, Leaf: leaf, LeafKey: leafKey}
}

// CodeSignatureOptions describes a synthetic code signature.
type CodeSignatureOptions struct {
	// Chain signs the primary code directory; nil produces an ad-hoc signature.
	Chain *TrustChain
	// HashTypes lists the code directories to emit; the first is primary.
	// Supported values are 1 (SHA-1) and 2 (SHA-256). Defaults to {2}.
	HashTypes []uint8
	// InfoPlist and CodeResources are sealed in special slots 1 and 3.
	InfoPlist     []byte
	CodeResources []byte
	Entitlements  []byte
	// OmitCDHashes leaves alternate code directories out of the CMS.
	OmitCDHashes bool
}

// CodeSize is the length of the signed code region SignedMachO emits.
const CodeSize = 3*4096 + 1000

const signatureReserve = 32 << 10

// SignedMachO builds a thin executable with a real code signature over
// CodeSize bytes of code.
func SignedMachO(t testing.TB, options CodeSignatureOptions) []byte {
	t.Helper()
	hashTypes := options.HashTypes
	if len(hashTypes) == 0 {
		hashTypes = []uint8{2}
	}
	var code []byte
	code = binary.LittleEndian.AppendUint32(code, 0xfeedfacf)
	code = binary.LittleEndian.AppendUint32(code, 0x0100000c)
	code = binary.LittleEndian.AppendUint32(code, 0)
	code = binary.LittleEndian.AppendUint32(code, 2)
	code = binary.LittleEndian.AppendUint32(code, 1)
	code = binary.LittleEndian.AppendUint32(code, 16)
	code = binary.LittleEndian.AppendUint32(code, 0)
	code = binary.LittleEndian.AppendUint32(code, 0)
	code = binary.LittleEndian.AppendUint32(code, 0x1d)
	code = binary.LittleEndian.AppendUint32(code, 16)
	code = binary.LittleEndian.AppendUint32(code, CodeSize)
	code = binary.LittleEndian.AppendUint32(code, signatureReserve)
	for len(code) < CodeSize {
		code = append(code, byte(len(code)*7))
	}

	requirements := Blob(0xfade0c01, make([]byte, 4))
	special := map[int][]byte{2: requirements}
	if options.InfoPlist != nil {
		special[1] = options.InfoPlist
	}
	if options.CodeResources != nil {
		special[3] = options.CodeResources
	}
	var entitlements []byte
	if options.Entitlements != nil {
		entitlements = Blob(0xfade7171, options.Entitlements)
		special[5] = entitlements
	}
	directories := make([][]byte, 0, len(hashTypes))
	for _, hashType := range hashTypes {
		directories = append(directories, CodeDirectory(code, hashType, special))
	}

	slots := []Slot{{Kind: 0, Blob: directories[0]}, {Kind: 2, Blob: requirements}}
	if entitlements != nil {
		slots = append(slots, Slot{Kind: 5, Blob: entitlements})
	}
	for index, directory := range directories[1:] {
		slots = append(slots, Slot{Kind: uint32(0x1000 + index), Blob: directory})
	}
	var cms []byte
	if options.Chain != nil {
		cms = codeSigningCMS(t, *options.Chain, directories, hashTypes, options.OmitCDHashes)
	}
	slots = append(slots, CMSSlot(cms))
	signature := Superblob(slots...)
	if len(signature) > signatureReserve {
		t.Fatalf("signature is %d bytes; reserve is %d", len(signature), signatureReserve)
	}
	return append(append(code, signature...), make([]byte, signatureReserve-len(signature))...)
}

func hashSize(hashType uint8) int {
	if hashType == 1 {
		return 20
	}
	return 32
}

func sum(hashType uint8, data []byte) []byte {
	if hashType == 1 {
		digest := sha1.Sum(data) //nolint:gosec // format hash.
		return digest[:]
	}
	digest := sha256.Sum256(data)
	return digest[:]
}

// CodeDirectory encodes a version 0x20400 code directory over code in 4 KiB
// pages. special maps special slot numbers to the data they seal.
func CodeDirectory(code []byte, hashType uint8, special map[int][]byte) []byte {
	hashSize := hashSize(hashType)
	const identifier = "com.example.demo\x00"
	nSpecial := 0
	for index := range special {
		nSpecial = max(nSpecial, index)
	}
	nCode := (len(code) + 4095) / 4096
	header := 88
	hashOffset := header + len(identifier) + nSpecial*hashSize
	length := hashOffset + nCode*hashSize
	out := make([]byte, header, length)
	binary.BigEndian.PutUint32(out[0:], 0xfade0c02)
	binary.BigEndian.PutUint32(out[4:], uint32(length))
	binary.BigEndian.PutUint32(out[8:], 0x20400)
	binary.BigEndian.PutUint32(out[16:], uint32(hashOffset))
	binary.BigEndian.PutUint32(out[20:], uint32(header))
	binary.BigEndian.PutUint32(out[24:], uint32(nSpecial))
	binary.BigEndian.PutUint32(out[28:], uint32(nCode))
	binary.BigEndian.PutUint32(out[32:], uint32(len(code)))
	out[36], out[37], out[39] = byte(hashSize), hashType, 12
	out = append(out, identifier...)
	for index := nSpecial; index >= 1; index-- {
		if data, ok := special[index]; ok {
			out = append(out, sum(hashType, data)...)
		} else {
			out = append(out, make([]byte, hashSize)...)
		}
	}
	for start := 0; start < len(code); start += 4096 {
		out = append(out, sum(hashType, code[start:min(start+4096, len(code))])...)
	}
	return out
}

var oidAppleCDHashes = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}

func codeSigningCMS(t testing.TB, chain TrustChain, directories [][]byte, hashTypes []uint8, omitCDHashes bool) []byte {
	t.Helper()
	signed, err := pkcs7.NewSignedData(directories[0])
	if err != nil {
		t.Fatal(err)
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	config := pkcs7.SignerInfoConfig{}
	if len(directories) > 1 && !omitCDHashes {
		plist := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>cdhashes</key><array>`
		for index, directory := range directories {
			plist += "<data>" + base64.StdEncoding.EncodeToString(sum(hashTypes[index], directory)[:20]) + "</data>"
		}
		plist += `</array></dict></plist>`
		config.ExtraSignedAttributes = []pkcs7.Attribute{{Type: oidAppleCDHashes, Value: []byte(plist)}}
	}
	if err := signed.AddSignerChain(chain.Leaf, chain.LeafKey, []*x509.Certificate{chain.Intermediate}, config); err != nil {
		t.Fatal(err)
	}
	signed.Detach()
	data, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// SignedXar builds a flat package whose table of contents is checksummed with
// SHA-1 and signed with the chain's RSA leaf, as productsign does.
func SignedXar(t testing.TB, files map[string][]byte, chain TrustChain, created time.Time) []byte {
	t.Helper()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	const checksumSize, signatureSize = 20, 256
	var heap, filesXML bytes.Buffer
	for id, name := range names {
		data := files[name]
		offset := checksumSize + signatureSize + heap.Len()
		heap.Write(data)
		filesXML.WriteString(`<file id="` + strconv.Itoa(id+1) + `"><name>` + name + `</name><type>file</type><data><length>` + strconv.Itoa(len(data)) + `</length><offset>` + strconv.Itoa(offset) + `</offset><size>` + strconv.Itoa(len(data)) + `</size><encoding style="application/octet-stream"/></data></file>`)
	}
	toc := `<xar><toc><checksum style="sha1"><offset>0</offset><size>20</size></checksum>` +
		`<creation-time>` + created.UTC().Format("2006-01-02T15:04:05") + `</creation-time>` +
		`<signature style="RSA"><offset>20</offset><size>256</size><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` +
		wrapBase64(chain.Leaf.Raw) + `</X509Certificate><X509Certificate>` + wrapBase64(chain.Intermediate.Raw) +
		`</X509Certificate></X509Data></KeyInfo></signature>` + filesXML.String() + `</toc></xar>`
	var compressed bytes.Buffer
	encoder := zlib.NewWriter(&compressed)
	if _, err := encoder.Write([]byte(toc)); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	checksum := sha1.Sum(compressed.Bytes()) //nolint:gosec // xar format hash.
	signature, err := rsa.SignPKCS1v15(rand.Reader, chain.LeafKey, crypto.SHA1, checksum[:])
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 28)
	copy(header[:4], "xar!")
	binary.BigEndian.PutUint16(header[4:6], 28)
	binary.BigEndian.PutUint16(header[6:8], 1)
	binary.BigEndian.PutUint64(header[8:16], uint64(compressed.Len()))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(toc)))
	binary.BigEndian.PutUint32(header[24:28], 1)
	out := append(header, compressed.Bytes()...)
	out = append(out, checksum[:]...)
	out = append(out, signature...)
	return append(out, heap.Bytes()...)
}
