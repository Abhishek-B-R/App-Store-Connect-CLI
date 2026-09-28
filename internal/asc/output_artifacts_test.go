package asc

import (
	"reflect"
	"testing"
)

func TestArtifactInfoRowsAddVerificationDetailOnlyWhenPresent(t *testing.T) {
	headers, rows := artifactIPAInfoRows(&ArtifactIPAInfo{SignatureVerification: "not-verified"})
	if len(headers) != 7 || len(rows[0]) != 7 {
		t.Fatalf("default table changed: %v %v", headers, rows)
	}
	headers, rows = artifactPKGInfoRows(&ArtifactPKGInfo{SignatureVerification: "invalid", SignatureVerificationDetail: "package is unsigned"})
	if headers[len(headers)-1] != "Signature Detail" || !reflect.DeepEqual(rows[0][len(rows[0])-2:], []string{"invalid", "package is unsigned"}) {
		t.Fatalf("headers=%v rows=%v", headers, rows)
	}
}
