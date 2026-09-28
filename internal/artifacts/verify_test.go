package artifacts

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/artifacts/artifactstest"
)

var (
	validFrom  = time.Now().Add(-24 * time.Hour)
	validUntil = time.Now().AddDate(1, 0, 0)
)

func testPolicy(chain artifactstest.TrustChain) *trustPolicy {
	policy := &trustPolicy{roots: x509.NewCertPool(), rootNames: map[string]string{}, now: time.Now}
	policy.addRoot(chain.Root)
	return policy
}

var testInfoPlist = []byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.demo</string><key>CFBundleExecutable</key><string>Demo</string></dict></plist>`)

var testCodeResources = []byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>files</key><dict/></dict></plist>`)

// verificationIPA packages executable with the sealed bundle files.
func verificationIPA(t *testing.T, executable []byte, method uint16, overrides map[string][]byte) []byte {
	t.Helper()
	files := map[string][]byte{
		"Payload/Demo.app/Info.plist":                   testInfoPlist,
		"Payload/Demo.app/Demo":                         executable,
		"Payload/Demo.app/_CodeSignature/CodeResources": testCodeResources,
		"Payload/Demo.app/embedded.mobileprovision":     []byte("<plist version=\"1.0\"><dict><key>Entitlements</key><dict/></dict></plist>"),
		"Payload/Demo.app/PlugIns/Ext.appex/Info.plist": plistXML(t, map[string]any{"CFBundleIdentifier": "com.example.demo.ext"}),
	}
	for name, data := range overrides {
		if data == nil {
			delete(files, name)
			continue
		}
		files[name] = data
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, data := range files {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func verifyIPA(t *testing.T, ipa []byte, policy *trustPolicy) SignatureVerification {
	t.Helper()
	manifest, _ := inspectIPAVerifying(bytes.NewReader(ipa), int64(len(ipa)), false, false, policy)
	if manifest.SignatureVerification == nil {
		t.Fatal("verification result is missing")
	}
	return *manifest.SignatureVerification
}

func sealedOptions(chain *artifactstest.TrustChain) artifactstest.CodeSignatureOptions {
	return artifactstest.CodeSignatureOptions{
		Chain:         chain,
		InfoPlist:     testInfoPlist,
		CodeResources: testCodeResources,
		Entitlements:  []byte(`<plist version="1.0"><dict/></plist>`),
	}
}

func expectVerification(t *testing.T, got SignatureVerification, status, detail string) {
	t.Helper()
	if got.Status != status || !strings.Contains(got.Detail, detail) {
		t.Fatalf("verification=%+v; want %s containing %q", got, status, detail)
	}
}

func TestVerifyIPAAcceptsValidSignature(t *testing.T) {
	chain := artifactstest.NewTrustChain(t, validFrom, validUntil)
	for name, method := range map[string]uint16{"stored": zip.Store, "deflated": zip.Deflate} {
		t.Run(name, func(t *testing.T) {
			ipa := verificationIPA(t, artifactstest.SignedMachO(t, sealedOptions(&chain)), method, nil)
			expectVerification(t, verifyIPA(t, ipa, testPolicy(chain)), VerificationValid, "chain to Test Root CA verified at current time")
		})
	}
}

func TestVerifyIPAAcceptsBoundAlternateCodeDirectories(t *testing.T) {
	chain := artifactstest.NewTrustChain(t, validFrom, validUntil)
	options := sealedOptions(&chain)
	options.HashTypes = []uint8{1, 2}
	ipa := verificationIPA(t, artifactstest.SignedMachO(t, options), zip.Deflate, nil)
	expectVerification(t, verifyIPA(t, ipa, testPolicy(chain)), VerificationValid, "2 code directories and 4 code pages verified")

	options.OmitCDHashes = true
	ipa = verificationIPA(t, artifactstest.SignedMachO(t, options), zip.Deflate, nil)
	expectVerification(t, verifyIPA(t, ipa, testPolicy(chain)), VerificationInvalid, "not bound to the CMS signature")
}

func TestVerifyIPARejectsTampering(t *testing.T) {
	chain := artifactstest.NewTrustChain(t, validFrom, validUntil)
	policy := testPolicy(chain)
	signed := artifactstest.SignedMachO(t, sealedOptions(&chain))
	directoryAt := bytes.Index(signed, []byte("com.example.demo\x00"))
	entitlementsAt := bytes.Index(signed, []byte("<plist version=\"1.0\"><dict/></plist>"))
	if directoryAt < 0 || entitlementsAt < 0 {
		t.Fatal("fixture layout changed")
	}
	flip := func(offset int) []byte {
		tampered := append([]byte(nil), signed...)
		tampered[offset] ^= 0x01
		return tampered
	}
	tests := map[string]struct {
		executable []byte
		overrides  map[string][]byte
		detail     string
	}{
		"executable page":        {executable: flip(2 * 4096), detail: "code page 2 does not match"},
		"final partial page":     {executable: flip(artifactstest.CodeSize - 1), detail: "code page 3 does not match"},
		"code directory":         {executable: flip(directoryAt), detail: "CMS message digest does not match"},
		"entitlements blob":      {executable: flip(entitlementsAt + 10), detail: "entitlements blob does not match"},
		"Info.plist":             {executable: signed, overrides: map[string][]byte{"Payload/Demo.app/Info.plist": bytes.Replace(testInfoPlist, []byte("com.example.demo"), []byte("com.example.evil"), 1)}, detail: "Info.plist does not match"},
		"CodeResources":          {executable: signed, overrides: map[string][]byte{"Payload/Demo.app/_CodeSignature/CodeResources": append(append([]byte(nil), testCodeResources...), ' ')}, detail: "CodeResources does not match"},
		"unsealed Info.plist":    {executable: artifactstest.SignedMachO(t, artifactstest.CodeSignatureOptions{Chain: &chain, CodeResources: testCodeResources}), detail: "bundle Info.plist is not sealed"},
		"unsealed CodeResources": {executable: artifactstest.SignedMachO(t, artifactstest.CodeSignatureOptions{Chain: &chain, InfoPlist: testInfoPlist}), detail: "bundle CodeResources is not sealed"},
		"missing sealed file":    {executable: signed, overrides: map[string][]byte{"Payload/Demo.app/_CodeSignature/CodeResources": nil}, detail: "seals CodeResources, but the bundle has none"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ipa := verificationIPA(t, test.executable, zip.Deflate, test.overrides)
			expectVerification(t, verifyIPA(t, ipa, policy), VerificationInvalid, test.detail)
		})
	}
}

func TestVerifyIPAClassifiesChainProblems(t *testing.T) {
	chain := artifactstest.NewTrustChain(t, validFrom, validUntil)
	ipa := verificationIPA(t, artifactstest.SignedMachO(t, sealedOptions(&chain)), zip.Deflate, nil)
	apple := appleTrustPolicyForAnyOS(t)
	expectVerification(t, verifyIPA(t, ipa, apple), VerificationUntrustedChain, "does not chain to an embedded Apple root")

	stranger := artifactstest.NewTrustChain(t, validFrom, validUntil)
	expectVerification(t, verifyIPA(t, ipa, testPolicy(stranger)), VerificationUntrustedChain, "CMS signature and 1 code directory")

	expired := artifactstest.NewTrustChain(t, time.Now().AddDate(-2, 0, 0), time.Now().AddDate(-1, 0, 0))
	ipa = verificationIPA(t, artifactstest.SignedMachO(t, sealedOptions(&expired)), zip.Deflate, nil)
	expectVerification(t, verifyIPA(t, ipa, testPolicy(expired)), VerificationExpired, "not valid at current time")

	// Expired and untrusted reports the missing trust, not the expiry.
	expectVerification(t, verifyIPA(t, ipa, apple), VerificationUntrustedChain, "unknown authority")
}

func TestVerifyIPAClassifiesUnsignedAdHocAndUnreadable(t *testing.T) {
	chain := artifactstest.NewTrustChain(t, validFrom, validUntil)
	policy := testPolicy(chain)
	adHoc := artifactstest.SignedMachO(t, sealedOptions(nil))
	expectVerification(t, verifyIPA(t, verificationIPA(t, adHoc, zip.Deflate, nil), policy), VerificationUntrustedChain, "ad-hoc signature has no signing certificate")
	tamperedAdHoc := append([]byte(nil), adHoc...)
	tamperedAdHoc[5000] ^= 0x01
	expectVerification(t, verifyIPA(t, verificationIPA(t, tamperedAdHoc, zip.Deflate, nil), policy), VerificationInvalid, "code page 1")
	expectVerification(t, verifyIPA(t, verificationIPA(t, artifactstest.MachO(nil), zip.Deflate, nil), policy), VerificationInvalid, "no code signature")
	expectVerification(t, verifyIPA(t, verificationIPA(t, []byte("#!/bin/sh\n"), zip.Deflate, nil), policy), VerificationUnsupported, "code signature could not be read")
	expectVerification(t, verifyIPA(t, []byte("not a zip"), policy), VerificationUnsupported, "IPA could not be inspected")
}

func TestVerifyIPAHandlesMalformedSignaturesWithoutPanicking(t *testing.T) {
	chain := artifactstest.NewTrustChain(t, validFrom, validUntil)
	policy := testPolicy(chain)
	signed := artifactstest.SignedMachO(t, sealedOptions(&chain))
	superblobEnd := artifactstest.CodeSize + int(binary.BigEndian.Uint32(signed[artifactstest.CodeSize+4:]))
	for offset := artifactstest.CodeSize; offset < superblobEnd; offset += 5 {
		for _, value := range []byte{0x00, 0xff} {
			mutated := append([]byte(nil), signed...)
			mutated[offset] = value
			if result := verifyMachOBytes(mutated, policy); result.Status == "" || result.Detail == "" {
				t.Fatalf("offset %d: empty result %+v", offset, result)
			}
		}
	}
	for length := 0; length < len(signed); length += 509 {
		if result := verifyMachOBytes(signed[:length], policy); result.Status == VerificationValid {
			t.Fatalf("truncated to %d bytes verified as valid", length)
		}
	}
}

func TestVerifyPKG(t *testing.T) {
	chain := artifactstest.NewTrustChain(t, validFrom, validUntil)
	policy := testPolicy(chain)
	info := map[string][]byte{"PackageInfo": []byte(`<pkg-info version="1.0" identifier="com.example.pkg"/>`)}
	valid := artifactstest.SignedXar(t, info, chain, time.Now())
	verify := func(data []byte, policy *trustPolicy) SignatureVerification {
		t.Helper()
		manifest, _ := inspectPKGVerifying(bytes.NewReader(data), int64(len(data)), policy)
		if manifest.SignatureVerification == nil {
			t.Fatal("verification result is missing")
		}
		return *manifest.SignatureVerification
	}
	expectVerification(t, verify(valid, policy), VerificationValid, "chain to Test Root CA verified at current time")

	document, _, err := readXarFiles(bytes.NewReader(valid), int64(len(valid)))
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := verifiedXarChecksum(bytes.NewReader(valid), int64(len(valid)), document)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(offset int64) []byte {
		tampered := append([]byte(nil), valid...)
		tampered[offset] ^= 0x01
		return tampered
	}
	expectVerification(t, verify(flip(checksum.heap+5), policy), VerificationInvalid, "checksum does not match the table of contents")
	expectVerification(t, verify(flip(checksum.heap+30), policy), VerificationInvalid, "RSA signature does not verify")

	// A table of contents rewritten after signing no longer matches the checksum.
	resigned := artifactstest.SignedXar(t, map[string][]byte{"PackageInfo": []byte(`<pkg-info version="10.0" identifier="com.example.pkg"/>`)}, chain, time.Now())
	resignedDocument, _, _ := readXarFiles(bytes.NewReader(resigned), int64(len(resigned)))
	resignedChecksum, _ := verifiedXarChecksum(bytes.NewReader(resigned), int64(len(resigned)), resignedDocument)
	swapped := append(append([]byte(nil), resigned[:resignedChecksum.heap]...), valid[checksum.heap:]...)
	expectVerification(t, verify(swapped, policy), VerificationInvalid, "checksum does not match")

	expectVerification(t, verify(valid, appleTrustPolicyForAnyOS(t)), VerificationUntrustedChain, "does not chain to an embedded Apple root")
	expired := artifactstest.NewTrustChain(t, time.Now().AddDate(-2, 0, 0), time.Now().AddDate(-1, 0, 0))
	expectVerification(t, verify(artifactstest.SignedXar(t, info, expired, time.Now()), testPolicy(expired)), VerificationExpired, "not valid at current time")
	// A backdated creation time does not rescue an expired certificate.
	expectVerification(t, verify(artifactstest.SignedXar(t, info, expired, time.Now().AddDate(-1, -6, 0)), testPolicy(expired)), VerificationExpired, "not valid at current time")

	expectVerification(t, verify(writeXar(t, info), policy), VerificationInvalid, "package is unsigned")
	expectVerification(t, verify([]byte("xar!garbage"), policy), VerificationUnsupported, "table of contents could not be read")
	xSignatureOnly := writeXarWithTOCExtra(t, info, artifactstest.NewChain(t).XarSignature("x-signature"))
	expectVerification(t, verify(xSignatureOnly, policy), VerificationUnsupported, "only a CMS x-signature")
	unreadable := writeXarWithTOCExtra(t, info, `<signature style="RSA"><KeyInfo><X509Data><X509Certificate>AAAA</X509Certificate></X509Data></KeyInfo></signature>`)
	expectVerification(t, verify(unreadable, policy), VerificationUnsupported, "package signature could not be read")
	// A signature element over a header without a checksum cannot verify.
	unchecksummed := writeXarWithTOCExtra(t, info, artifactstest.NewChain(t).XarSignature("signature"))
	expectVerification(t, verify(unchecksummed, policy), VerificationInvalid, "has no checksum")

	for length := 0; length < len(valid); length += 97 {
		if result := verify(valid[:length], policy); result.Status == VerificationValid {
			t.Fatalf("truncated to %d bytes verified as valid", length)
		}
	}
}

func TestInspectWithoutVerificationLeavesResultUnset(t *testing.T) {
	chain := artifactstest.NewTrustChain(t, validFrom, validUntil)
	ipa := verificationIPA(t, artifactstest.SignedMachO(t, sealedOptions(&chain)), zip.Deflate, nil)
	manifest, err := InspectIPA(bytes.NewReader(ipa), int64(len(ipa)), false, false)
	if err != nil || manifest.SignatureVerification != nil || manifest.CodeSignature != SignatureSigned {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
	pkg := artifactstest.SignedXar(t, map[string][]byte{"PackageInfo": []byte(`<pkg-info identifier="com.example.pkg"/>`)}, chain, time.Now())
	pkgManifest, err := InspectPKG(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil || pkgManifest.SignatureVerification != nil || pkgManifest.PackageSignature != SignatureSigned {
		t.Fatalf("manifest=%+v err=%v", pkgManifest, err)
	}
}

func appleTrustPolicyForAnyOS(t *testing.T) *trustPolicy {
	t.Helper()
	policy, err := appleTrustPolicy()
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// The embedded certificates are pinned by SHA-256 so a changed PEM is a
// reviewable test change. Sources: macOS SystemRootCertificates.keychain for
// the roots, and Apple's certificate authority files for the intermediates.
func TestEmbeddedAppleCertificates(t *testing.T) {
	want := map[string]string{
		"root-apple-root-ca.pem":           "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
		"root-apple-root-ca-g3.pem":        "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
		"intermediate-apple-wwdr-g3.pem":   "dcf21878c77f4198e4b4614f03d696d89c66c66008d4244e1b99161aac91601f",
		"intermediate-apple-wwdr-g5.pem":   "53fd008278e5a595fe1e908ae9c5e5675f26243264a5a6438c023e3ce2870760",
		"intermediate-apple-wwdr-g6.pem":   "bdd4ed6e74691f0c2bfd01be0296197af1379e0418e2d300efa9c3bef642ca30",
		"intermediate-developer-id.pem":    "7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f",
		"intermediate-developer-id-g2.pem": "f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a",
	}
	entries, err := fs.ReadDir(appleCertificates, "applecerts")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		t.Fatalf("embedded %d certificates; want %d", len(entries), len(want))
	}
	policy := appleTrustPolicyForAnyOS(t)
	for _, entry := range entries {
		data, err := fs.ReadFile(appleCertificates, "applecerts/"+entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(data)
		if block == nil {
			t.Fatalf("%s is not PEM", entry.Name())
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(certificate.Raw)
		if hex.EncodeToString(digest[:]) != want[entry.Name()] {
			t.Fatalf("%s fingerprint = %x", entry.Name(), digest)
		}
		if strings.HasPrefix(entry.Name(), "intermediate-") {
			if _, err := certificate.Verify(x509.VerifyOptions{Roots: policy.roots, CurrentTime: certificate.NotBefore.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				t.Fatalf("%s does not chain to an embedded root: %v", entry.Name(), err)
			}
		} else if !bytes.Equal(certificate.RawSubject, certificate.RawIssuer) {
			t.Fatalf("%s is not self-signed", entry.Name())
		}
	}
	if len(policy.intermediates) != 5 || len(policy.rootNames) != 2 {
		t.Fatalf("policy has %d intermediates and %d roots", len(policy.intermediates), len(policy.rootNames))
	}
}

func TestXarChecksumHash(t *testing.T) {
	tests := []struct {
		algorithm uint32
		name      string
		want      string
		status    string
	}{
		{1, "", "sha1", ""},
		{3, "", "sha256", ""},
		{3, "sha512", "sha512", ""},
		{4, "", "sha512", ""},
		{0, "", "", VerificationInvalid},
		{2, "", "", VerificationUnsupported},
		{3, "whirlpool", "", VerificationUnsupported},
		{9, "", "", VerificationUnsupported},
	}
	for _, test := range tests {
		_, style, err := xarChecksumHash(test.algorithm, test.name)
		if test.status == "" {
			if err != nil || style != test.want {
				t.Fatalf("%d %q: style=%q err=%v", test.algorithm, test.name, style, err)
			}
			continue
		}
		if err == nil || failedVerification(err).Status != test.status {
			t.Fatalf("%d %q: err=%v", test.algorithm, test.name, err)
		}
	}
}
