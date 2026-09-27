package artifacts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Apple's platform binaries carry a real BER-encoded code-signing CMS and a
// universal (fat) layout, which the synthetic fixtures only approximate.
func TestReadMachOSignatureParsesAppleSignedSystemBinary(t *testing.T) {
	data, err := os.ReadFile("/bin/ls")
	if err != nil {
		t.Skipf("system binary unavailable: %v", err)
	}
	status, signer, err := readMachOSignature(bytes.NewReader(data), int64(len(data)))
	if err != nil || status != "signed" || signer == nil {
		t.Fatalf("status=%s signer=%+v err=%v", status, signer, err)
	}
	if !strings.Contains(signer.CommonName, "Software Signing") || !strings.Contains(signer.IssuerCommonName, "Apple") {
		t.Fatalf("signer=%+v", signer)
	}
}

func TestReadMachOSignatureClassifiesCodesignOutput(t *testing.T) {
	codesign, err := exec.LookPath("codesign")
	if err != nil {
		t.Skip("codesign is not installed")
	}
	binary := filepath.Join(t.TempDir(), "tool")
	data, err := os.ReadFile("/bin/ls")
	if err != nil {
		t.Skipf("system binary unavailable: %v", err)
	}
	if err := os.WriteFile(binary, data, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		args []string
		want string
	}{
		{[]string{"--remove-signature", binary}, "unsigned"},
		{[]string{"--force", "--sign", "-", binary}, "ad-hoc"},
	} {
		if output, err := exec.Command(codesign, step.args...).CombinedOutput(); err != nil {
			t.Skipf("codesign %v: %v: %s", step.args, err, output)
		}
		signed, err := os.ReadFile(binary)
		if err != nil {
			t.Fatal(err)
		}
		status, signer, err := readMachOSignature(bytes.NewReader(signed), int64(len(signed)))
		if err != nil || status != step.want || signer != nil {
			t.Fatalf("after %v: status=%s signer=%+v err=%v", step.args, status, signer, err)
		}
	}
}
