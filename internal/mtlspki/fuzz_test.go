package mtlspki

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParseCSR(f *testing.F) {
	f.Add([]byte("not a CSR"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseCSRBytes(data)
	})
}

func FuzzIssuerMetadata(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":1,"name":"server","type":"server","status":"active","generation":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0600); err != nil {
			t.Fatal(err)
		}

		_, _ = readIssuerMetadata(dir)
	})
}

func FuzzRegistry(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":1,"serial":"1","type":"server","status":"valid"}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "certificates.jsonl")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}

		_, _ = readRecords(path)
	})
}

func FuzzTransactionJournal(f *testing.F) {
	f.Add([]byte(`{"version":1,"phase":"prepared","operation":"issue"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := transactionPath(dir)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}

		_ = recoverLeafTransaction(dir)
	})
}
