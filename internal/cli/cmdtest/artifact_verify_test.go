package cmdtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rudrankriyam/App-Store-Connect-CLI/cmd"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/artifacts/artifactstest"
)

type verificationReceipt struct {
	SignatureVerification       string `json:"signatureVerification"`
	SignatureVerificationDetail string `json:"signatureVerificationDetail"`
	Status                      string `json:"status"`
}

func runVerification(t *testing.T, args ...string) (int, verificationReceipt, string) {
	t.Helper()
	var exit int
	stdout, stderr := captureOutput(t, func() { exit = cmd.Run(args, "test") })
	var receipt verificationReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatalf("stdout=%q stderr=%q: %v", stdout, stderr, err)
	}
	return exit, receipt, stderr
}

func TestRunArtifactInfoVerifySignatureFailsClosed(t *testing.T) {
	isolateArtifactCommandEnv(t)
	dir := t.TempDir()
	// Throwaway keys never chain to Apple's roots.
	chain := artifactstest.NewTrustChain(t, time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0))
	infoPlist := `<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.demo</string><key>CFBundleExecutable</key><string>Demo</string></dict></plist>`
	options := artifactstest.CodeSignatureOptions{Chain: &chain, InfoPlist: []byte(infoPlist)}
	signedIPA := filepath.Join(dir, "signed.ipa")
	writeArtifactZip(t, signedIPA, map[string]string{
		"Payload/Demo.app/Info.plist":               infoPlist,
		"Payload/Demo.app/Demo":                     string(artifactstest.SignedMachO(t, options)),
		"Payload/Demo.app/embedded.mobileprovision": `<plist version="1.0"><dict><key>Entitlements</key><dict/></dict></plist>`,
	})
	tamperedIPA := filepath.Join(dir, "tampered.ipa")
	tampered := artifactstest.SignedMachO(t, options)
	tampered[5000] ^= 0x01
	writeArtifactZip(t, tamperedIPA, map[string]string{
		"Payload/Demo.app/Info.plist":               infoPlist,
		"Payload/Demo.app/Demo":                     string(tampered),
		"Payload/Demo.app/embedded.mobileprovision": `<plist version="1.0"><dict><key>Entitlements</key><dict/></dict></plist>`,
	})
	info := map[string][]byte{"PackageInfo": []byte(`<pkg-info version="1.0" identifier="com.example.pkg"/>`)}
	signedPKG := filepath.Join(dir, "signed.pkg")
	unsignedPKG := filepath.Join(dir, "unsigned.pkg")
	for path, data := range map[string][]byte{
		signedPKG:   artifactstest.SignedXar(t, info, chain, time.Now()),
		unsignedPKG: artifactstest.Xar(t, info, ""),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name   string
		args   []string
		status string
		detail string
	}{
		{"untrusted IPA", []string{"ipa-info", "--path", signedIPA, "--verify-signature", "--output", "json"}, "untrusted-chain", "does not chain to an embedded Apple root"},
		{"tampered IPA", []string{"ipa-info", "--path", tamperedIPA, "--verify-signature", "--output", "json"}, "invalid", "code page 1 does not match"},
		{"missing IPA", []string{"ipa-info", "--path", filepath.Join(dir, "missing.ipa"), "--verify-signature", "--output", "json"}, "unsupported", "artifact could not be read"},
		{"untrusted pkg", []string{"pkg-info", "--path", signedPKG, "--verify-signature", "--output", "json"}, "untrusted-chain", "RSA signature verified"},
		{"unsigned pkg", []string{"pkg-info", "--path", unsignedPKG, "--verify-signature", "--output", "json"}, "invalid", "package is unsigned"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exit, receipt, stderr := runVerification(t, test.args...)
			if exit != cmd.ExitError {
				t.Fatalf("exit=%d stderr=%q", exit, stderr)
			}
			if receipt.SignatureVerification != test.status || !strings.Contains(receipt.SignatureVerificationDetail, test.detail) {
				t.Fatalf("receipt=%+v", receipt)
			}
			if test.status != "unsupported" && !strings.Contains(stderr, "signature verification "+test.status) {
				t.Fatalf("stderr=%q", stderr)
			}
		})
	}

	// Without the flag the same artifacts keep the unverified receipt and exit 0.
	for _, args := range [][]string{
		{"ipa-info", "--path", tamperedIPA, "--output", "json"},
		{"pkg-info", "--path", unsignedPKG, "--output", "json"},
	} {
		exit, receipt, stderr := runVerification(t, args...)
		if exit != cmd.ExitSuccess || stderr != "" || receipt.SignatureVerification != "not-verified" || receipt.SignatureVerificationDetail != "" {
			t.Fatalf("%v: exit=%d receipt=%+v stderr=%q", args, exit, receipt, stderr)
		}
	}
}

func TestRunPKGInfoVerifiesAppleSignedPackage(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Apple-signed packages ship with Xcode on macOS")
	}
	matches, _ := filepath.Glob("/Applications/Xcode*.app/Contents/Resources/Packages/MobileDeviceDevelopment.pkg")
	if len(matches) == 0 {
		t.Skip("no Apple-signed flat package is installed")
	}
	isolateArtifactCommandEnv(t)
	exit, receipt, stderr := runVerification(t, "pkg-info", "--path", matches[0], "--verify-signature", "--output", "json")
	if exit != cmd.ExitSuccess || receipt.SignatureVerification != "valid" || !strings.Contains(receipt.SignatureVerificationDetail, "Apple Root CA") {
		t.Fatalf("exit=%d receipt=%+v stderr=%q", exit, receipt, stderr)
	}
}
