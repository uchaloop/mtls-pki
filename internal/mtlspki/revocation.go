package mtlspki

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	storagecore "github.com/uchaloop/mtls-pki/internal/storage"
)

func exclusiveLock(root, pki string) (*storagecore.Lock, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lock, err := storagecore.Acquire(ctx, filepath.Join(root, pki), false)
	if err != nil {
		return nil, operational(err)
	}
	if err = recoverLeafTransaction(filepath.Join(root, pki)); err != nil {
		_ = lock.Close()
		return nil, operational(err)
	}

	return lock, nil
}

func makeIssuerStatusCommand(status string) *cobra.Command {
	var root, pki, name, format string
	short := "Retire an issuing CA"
	if status == "activate" {
		short = "Activate a retired issuing CA"
	}

	cmd := &cobra.Command{Use: status, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateCLIName(pki, "pki"); err != nil {
			return err
		}
		if err := validateCLIName(name, "name"); err != nil {
			return err
		}
		if err := validateFormat(format); err != nil {
			return err
		}

		lock, err := exclusiveLock(root, pki)
		if err != nil {
			return err
		}
		defer lock.Close()

		path := filepath.Join(root, pki, "issuers", name, "metadata.json")
		data, err := osReadFile(path)
		if err != nil {
			return operational(err)
		}

		var meta metadata
		if err = json.Unmarshal(data, &meta); err != nil {
			return operational(err)
		}
		if status == "activate" {
			meta.Status = "active"
		} else {
			meta.Status = "retired"
		}

		encoded, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			return operational(err)
		}
		if err = write(path, append(encoded, '\n'), 0644, true); err != nil {
			return operational(err)
		}
		if format == "json" {
			fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "issuer %s: %s\n", meta.Name, meta.Status)
		}

		return nil
	}}

	f := cmd.Flags()
	f.StringVarP(&root, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&pki, "pki", "p", "", "PKI name")
	f.StringVarP(&name, "name", "n", "", "issuer name")
	f.StringVarP(&format, "output", "o", "text", "output format: text or json")
	return cmd
}

func makeRevokeCommand() *cobra.Command {
	var root, pki, serialValue, certPath, reason, format string
	cmd := &cobra.Command{Use: "revoke", Short: "Revoke an issued certificate", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateCLIName(pki, "pki"); err != nil {
			return err
		}
		if err := validateFormat(format); err != nil {
			return err
		}
		if !validReason(reason) {
			return usageError("invalid --reason")
		}

		serialValue = strings.ToUpper(strings.TrimPrefix(serialValue, "0x"))
		if len(certPath) > 0 {
			cert, err := parseCert(certPath)
			if err != nil {
				return operational(err)
			}

			serialValue = strings.ToUpper(cert.SerialNumber.Text(16))
		}
		if len(serialValue) == 0 {
			return usageError("--serial or --certificate is required")
		}

		lock, err := exclusiveLock(root, pki)
		if err != nil {
			return err
		}
		defer lock.Close()

		path := filepath.Join(root, pki, "index", "certificates.jsonl")
		records, err := readRecords(path)
		if err != nil {
			return operational(err)
		}

		found := false
		now := time.Now().UTC()
		for i := range records {
			if records[i].Serial != serialValue {
				continue
			}
			if records[i].Status == "revoked" {
				return operational(fmt.Errorf("certificate is already revoked"))
			}

			records[i].Status = "revoked"
			records[i].Reason = reason
			records[i].RevokedAt = new(now)
			found = true
		}
		if !found {
			return operational(fmt.Errorf("serial not found in registry"))
		}
		if err = writeRecords(path, records); err != nil {
			return operational(err)
		}
		if format == "json" {
			out, _ := json.Marshal(map[string]string{"operation": "revoke", "serial": serialValue, "status": "revoked", "reason": reason})
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "revoked:", serialValue)
		}

		return nil
	}}

	f := cmd.Flags()
	f.StringVarP(&root, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&pki, "pki", "p", "", "PKI name")
	f.StringVarP(&serialValue, "serial", "s", "", "certificate serial")
	f.StringVar(&certPath, "certificate", "", "certificate path")
	f.StringVarP(&reason, "reason", "R", "unspecified", "revocation reason")
	f.StringVarP(&format, "output", "o", "text", "output format: text or json")
	return cmd
}

func makeRecoverCommand() *cobra.Command {
	var root, pki, format string
	cmd := &cobra.Command{Use: "recover", Short: "Recover an interrupted PKI transaction", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateCLIName(pki, "pki"); err != nil {
			return err
		}
		if err := validateFormat(format); err != nil {
			return err
		}

		pending := hasPendingTransaction(filepath.Join(root, pki))
		lock, err := exclusiveLock(root, pki)
		if err != nil {
			return err
		}
		defer lock.Close()

		status := "clean"
		if pending {
			status = "recovered"
		}
		if format == "json" {
			data, _ := json.Marshal(map[string]any{"operation": "recover", "status": status})
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "PKI transaction status:", status)
		}

		return nil
	}}

	f := cmd.Flags()
	f.StringVarP(&root, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&pki, "pki", "p", "", "PKI name")
	f.StringVarP(&format, "output", "o", "text", "output format: text or json")
	return cmd
}

var osReadFile = func(path string) ([]byte, error) { return os.ReadFile(path) }
