package mtlspki

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateRootFinalize(t *testing.T) {
	root := t.TempDir()
	pki := "test"
	state := rootMetadata{ActiveGeneration: 2, Rotation: &rootRotation{From: 1, To: 2, Phase: "migrating"}}
	if err := validateRootFinalize(root, pki, state); err != nil {
		t.Fatal(err)
	}

	issuerDir := filepath.Join(root, pki, "issuers", "old")
	if err := os.MkdirAll(issuerDir, 0700); err != nil {
		t.Fatal(err)
	}

	data, _ := json.Marshal(metadata{Name: "old", Type: "server", Status: "active", Generation: 1, RootGeneration: 1})
	if err := os.WriteFile(filepath.Join(issuerDir, "metadata.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateRootFinalize(root, pki, state); err == nil {
		t.Fatal("active issuer on old Root did not block finalize")
	}

	data, _ = json.Marshal(metadata{Name: "old", Type: "server", Status: "active", Generation: 2, RootGeneration: 2})
	if err := os.WriteFile(filepath.Join(issuerDir, "metadata.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	records := []record{{Serial: "1", Type: "server", Name: "api", Status: "valid", RootGeneration: 1, NotAfter: time.Now().Add(time.Hour)}}
	if err := writeRecords(filepath.Join(root, pki, "index", "certificates.jsonl"), records); err != nil {
		t.Fatal(err)
	}
	if err := validateRootFinalize(root, pki, state); err == nil {
		t.Fatal("valid leaf on old Root did not block finalize")
	}

	records[0].Status = "revoked"
	if err := writeRecords(filepath.Join(root, pki, "index", "certificates.jsonl"), records); err != nil {
		t.Fatal(err)
	}
	if err := validateRootFinalize(root, pki, state); err != nil {
		t.Fatal(err)
	}
}
