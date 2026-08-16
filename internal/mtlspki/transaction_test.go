package mtlspki

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverCommand(t *testing.T) {
	root := t.TempDir()
	pki := "test"
	pkiDir := filepath.Join(root, pki)
	index := filepath.Join(pkiDir, "index", "certificates.jsonl")
	tx := leafTransaction{Version: 1, Phase: "object-committed", Operation: "issue", Target: filepath.Join(pkiDir, "certificates", "client", "worker"), IndexPath: index, NewRecords: []record{{Serial: "2"}}}
	if err := os.MkdirAll(tx.Target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeTransaction(pkiDir, tx); err != nil {
		t.Fatal(err)
	}

	cmd := makeRecoverCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"--root", root, "--pki", pki, "--output", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"status":"recovered"`)) {
		t.Fatalf("output=%s", output.String())
	}

	records, err := readRecords(index)
	if err != nil || len(records) != 1 || records[0].Serial != "2" {
		t.Fatalf("records=%v err=%v", records, err)
	}
}

func TestRecoverPreparedIssueRollsBack(t *testing.T) {
	pki := t.TempDir()
	index := filepath.Join(pki, "index", "certificates.jsonl")
	old := []record{{Serial: "1", Status: "valid"}}
	if err := writeRecords(index, old); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(pki, "certificates", "server", "api")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}

	tx := leafTransaction{Version: 1, Phase: "prepared", Operation: "issue", Target: target, Stage: filepath.Join(pki, "certificates", "server", ".stage"), IndexPath: index, OldRecords: old, NewRecords: append(old, record{Serial: "2"})}
	if err := writeTransaction(pki, tx); err != nil {
		t.Fatal(err)
	}
	if err := recoverLeafTransaction(pki); err != nil {
		t.Fatal(err)
	}
	if exists(target) {
		t.Fatal("partially committed target survived rollback")
	}

	records, err := readRecords(index)
	if err != nil || len(records) != 1 || records[0].Serial != "1" {
		t.Fatalf("registry=%v err=%v", records, err)
	}
	if hasPendingTransaction(pki) {
		t.Fatal("journal survived recovery")
	}
}

func TestRecoverObjectCommittedRollsForward(t *testing.T) {
	pki := t.TempDir()
	index := filepath.Join(pki, "index", "certificates.jsonl")
	old := []record{{Serial: "1"}}
	next := append(append([]record(nil), old...), record{Serial: "2"})
	if err := writeRecords(index, old); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(pki, "certificates", "client", "worker")
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}

	tx := leafTransaction{Version: 1, Phase: "object-committed", Operation: "issue", Target: target, IndexPath: index, OldRecords: old, NewRecords: next}
	if err := writeTransaction(pki, tx); err != nil {
		t.Fatal(err)
	}
	if err := recoverLeafTransaction(pki); err != nil {
		t.Fatal(err)
	}

	records, err := readRecords(index)
	if err != nil || len(records) != 2 || records[1].Serial != "2" {
		t.Fatalf("registry=%v err=%v", records, err)
	}
	if !exists(target) {
		t.Fatal("committed target was removed")
	}
}

func TestRecoverPreparedRenewRestoresHistory(t *testing.T) {
	pki := t.TempDir()
	index := filepath.Join(pki, "index", "certificates.jsonl")
	old := []record{{Serial: "1", Status: "valid"}}
	if err := writeRecords(index, old); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(pki, "certificates", "server", "api")
	history := filepath.Join(pki, "certificates", "server", "history", "api-1")
	if err := os.MkdirAll(history, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(history, "old"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "new"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}

	tx := leafTransaction{Version: 1, Phase: "prepared", Operation: "renew", Target: target, History: history, Stage: filepath.Join(pki, "certificates", "server", ".stage"), IndexPath: index, OldRecords: old, NewRecords: []record{{Serial: "1", Status: "superseded"}, {Serial: "2", Status: "valid"}}}
	if err := writeTransaction(pki, tx); err != nil {
		t.Fatal(err)
	}
	if err := recoverLeafTransaction(pki); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(target, "old")) || exists(filepath.Join(target, "new")) {
		t.Fatal("old certificate directory was not restored")
	}
}

func TestRecoveryRejectsPathsOutsidePKI(t *testing.T) {
	pki := t.TempDir()
	tx := leafTransaction{Version: 1, Phase: "prepared", Operation: "issue", Target: filepath.Join(filepath.Dir(pki), "outside"), IndexPath: filepath.Join(pki, "index", "certificates.jsonl")}
	if err := writeTransaction(pki, tx); err != nil {
		t.Fatal(err)
	}
	if err := recoverLeafTransaction(pki); err == nil {
		t.Fatal("unsafe journal path was accepted")
	}
}

func TestCommitRenewArchivesByOldSerial(t *testing.T) {
	pki := t.TempDir()
	index := filepath.Join(pki, "index", "certificates.jsonl")
	target := filepath.Join(pki, "certificates", "server", "api")
	stage := filepath.Join(pki, "certificates", "server", ".api.stage-test")
	oldCert := filepath.Join(target, "certs", "server.crt")
	if err := os.MkdirAll(filepath.Dir(oldCert), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldCert, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(stage, "certs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "certs", "server.crt"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}

	old := record{Serial: "OLD", Type: "server", Name: "api", Status: "valid", Certificate: oldCert}
	if err := writeRecords(index, []record{old}); err != nil {
		t.Fatal(err)
	}

	next := record{Serial: "NEW", Type: "server", Name: "api", Status: "valid", Certificate: filepath.Join(target, "certs", "server.crt")}
	if err := commitLeafTransaction(target, stage, "renew", index, next); err != nil {
		t.Fatal(err)
	}

	historyCert := filepath.Join(pki, "certificates", "server", "history", "api-OLD", "certs", "server.crt")
	if !exists(historyCert) {
		t.Fatal("old certificate was not archived by its own serial")
	}

	records, err := readRecords(index)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Status != "superseded" || records[0].Certificate != historyCert {
		t.Fatalf("unexpected registry: %+v", records)
	}
}
