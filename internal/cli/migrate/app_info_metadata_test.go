package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadFastlaneAppInfoMetadata_IncludesPrivacyURL(t *testing.T) {
	dir := t.TempDir()
	localeDir := filepath.Join(dir, "en-US")
	if err := os.MkdirAll(localeDir, 0o755); err != nil {
		t.Fatalf("mkdir locale dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localeDir, "privacy_url.txt"), []byte("https://example.com/privacy"), 0o644); err != nil {
		t.Fatalf("write privacy_url: %v", err)
	}

	locs, err := readFastlaneAppInfoMetadata(dir)
	if err != nil {
		t.Fatalf("readFastlaneAppInfoMetadata() error: %v", err)
	}
	if len(locs) != 1 {
		t.Fatalf("expected 1 localization, got %d", len(locs))
	}
	if locs[0].PrivacyURL != "https://example.com/privacy" {
		t.Fatalf("expected privacy url, got %q", locs[0].PrivacyURL)
	}
}

func TestReadFastlaneMetadata_StripsUTF8BOM(t *testing.T) {
	dir := t.TempDir()
	localeDir := filepath.Join(dir, "en-US")
	if err := os.MkdirAll(localeDir, 0o755); err != nil {
		t.Fatalf("mkdir locale dir: %v", err)
	}
	writeFile := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(localeDir, name), []byte("\ufeff"+value+"\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	writeFile("name.txt", "My App")
	writeFile("description.txt", "A description")

	appInfo, err := readFastlaneAppInfoMetadata(dir)
	if err != nil {
		t.Fatalf("readFastlaneAppInfoMetadata() error: %v", err)
	}
	if len(appInfo) != 1 || appInfo[0].Name != "My App" {
		t.Fatalf("expected name %q without BOM, got %#v", "My App", appInfo)
	}

	locs, err := readFastlaneMetadata(dir)
	if err != nil {
		t.Fatalf("readFastlaneMetadata() error: %v", err)
	}
	if len(locs) != 1 || locs[0].Description != "A description" {
		t.Fatalf("expected description %q without BOM, got %#v", "A description", locs)
	}
}
