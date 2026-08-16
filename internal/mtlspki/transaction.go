package mtlspki

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	storagecore "github.com/uchaloop/mtls-pki/internal/storage"
)

const leafTransactionVersion = 1

type leafTransaction struct {
	Version                           int    `json:"version"`
	Phase                             string `json:"phase"`
	Operation                         string `json:"operation"`
	Target, Stage, History, IndexPath string
	OldRecords, NewRecords            []record
}

func transactionPath(pkiDir string) string { return filepath.Join(pkiDir, "index", "transaction.json") }

func writeTransaction(pkiDir string, tx leafTransaction) error {
	data, err := json.MarshalIndent(tx, "", "  ")
	if err != nil {
		return err
	}

	return storagecore.WriteAtomic(transactionPath(pkiDir), append(data, '\n'), 0600, true)
}

func clearTransaction(pkiDir string) error {
	err := os.Remove(transactionPath(pkiDir))
	if os.IsNotExist(err) {
		return nil
	}

	return err
}

func hasPendingTransaction(pkiDir string) bool {
	_, err := os.Stat(transactionPath(pkiDir))
	return err == nil
}

func recoverLeafTransaction(pkiDir string) error {
	path := transactionPath(pkiDir)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	var tx leafTransaction
	if err = json.Unmarshal(data, &tx); err != nil {
		return fmt.Errorf("cannot parse transaction journal: %w", err)
	}
	if tx.Version != leafTransactionVersion {
		return fmt.Errorf("unsupported transaction journal version %d", tx.Version)
	}
	if err = validateTransactionPaths(pkiDir, tx); err != nil {
		return err
	}

	switch tx.Phase {
	case "prepared":
		if err = rollbackLeafTransaction(pkiDir, tx); err != nil {
			return err
		}
	case "object-committed":
		if err = writeRecords(tx.IndexPath, tx.NewRecords); err != nil {
			return err
		}
		if len(tx.Stage) > 0 {
			_ = os.RemoveAll(tx.Stage)
		}
		if err = clearTransaction(pkiDir); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid transaction phase %q", tx.Phase)
	}

	return nil
}

func validateTransactionPaths(pkiDir string, tx leafTransaction) error {
	for _, path := range []string{tx.Target, tx.Stage, tx.History, tx.IndexPath} {
		if len(path) == 0 {
			continue
		}

		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}

		base, err := filepath.Abs(pkiDir)
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(base, absolute)
		if err != nil {
			return err
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("transaction journal contains a path outside the PKI directory")
		}
	}

	return nil
}

func rollbackLeafTransaction(pkiDir string, tx leafTransaction) error {
	if tx.Operation == "renew" && len(tx.History) > 0 && exists(tx.History) {
		if exists(tx.Target) {
			if err := os.RemoveAll(tx.Target); err != nil {
				return err
			}
		}
		if err := os.Rename(tx.History, tx.Target); err != nil {
			return err
		}
	} else if tx.Operation == "issue" && exists(tx.Target) {
		if err := os.RemoveAll(tx.Target); err != nil {
			return err
		}
	}
	if len(tx.Stage) > 0 && exists(tx.Stage) {
		if err := os.RemoveAll(tx.Stage); err != nil {
			return err
		}
	}
	if err := writeRecords(tx.IndexPath, tx.OldRecords); err != nil {
		return err
	}

	return clearTransaction(pkiDir)
}

func commitLeafTransaction(target, stage, operation, indexPath string, newRecord record) error {
	pkiDir := filepath.Dir(filepath.Dir(indexPath))
	oldRecords, err := readRecords(indexPath)
	if err != nil {
		return err
	}

	newRecords := append([]record(nil), oldRecords...)
	oldSerial := ""
	if operation == "renew" {
		for i := range newRecords {
			if newRecords[i].Type == newRecord.Type && newRecords[i].Name == newRecord.Name && newRecords[i].Status == "valid" {
				oldSerial = newRecords[i].Serial
				newRecords[i].Status = "superseded"
				newRecords[i].Reason = "superseded"
			}
		}
		if len(oldSerial) == 0 {
			return fmt.Errorf("active registry record for %s certificate %s not found", newRecord.Type, newRecord.Name)
		}
	}

	newRecords = append(newRecords, newRecord)
	history := ""
	if operation == "renew" {
		history = filepath.Join(filepath.Dir(target), "history", filepath.Base(target)+"-"+oldSerial)
		for i := range newRecords {
			if newRecords[i].Serial == oldSerial {
				newRecords[i].Certificate = filepath.Join(history, "certs", newRecord.Type+".crt")
			}
		}
	}

	tx := leafTransaction{Version: leafTransactionVersion, Phase: "prepared", Operation: operation, Target: target, Stage: stage, History: history, IndexPath: indexPath, OldRecords: oldRecords, NewRecords: newRecords}
	if err = validateTransactionPaths(pkiDir, tx); err != nil {
		return err
	}
	if err = writeTransaction(pkiDir, tx); err != nil {
		return err
	}
	if operation == "renew" {
		if err = os.MkdirAll(filepath.Dir(history), 0700); err != nil {
			_ = rollbackLeafTransaction(pkiDir, tx)
			return err
		}
		if err = os.Rename(target, history); err != nil {
			_ = rollbackLeafTransaction(pkiDir, tx)
			return err
		}
	}
	if err = os.Rename(stage, target); err != nil {
		_ = rollbackLeafTransaction(pkiDir, tx)
		return err
	}

	tx.Phase = "object-committed"
	if err = writeTransaction(pkiDir, tx); err != nil {
		return err
	}
	if err = writeRecords(indexPath, newRecords); err != nil {
		return err
	}

	return clearTransaction(pkiDir)
}
