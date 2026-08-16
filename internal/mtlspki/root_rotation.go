package mtlspki

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

type rootRotationOptions struct{ root, pki, format string }

func addRootRotationFlags(cmd *cobra.Command, o *rootRotationOptions) {
	f := cmd.Flags()
	f.StringVarP(&o.root, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&o.pki, "pki", "p", "", "PKI name")
	f.StringVarP(&o.format, "output", "o", "text", "output format: text or json")
}

func makeRootRotationStatusCommand() *cobra.Command {
	o := &rootRotationOptions{}
	cmd := &cobra.Command{Use: "status", Short: "Show Root rotation state", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateCLIName(o.pki, "pki"); err != nil {
			return err
		}
		if err := validateFormat(o.format); err != nil {
			return err
		}

		lock, err := sharedLock(o.root, o.pki)
		if err != nil {
			return err
		}
		defer lock.Close()

		state, err := readRootState(o.root, o.pki)
		if err != nil {
			return err
		}
		if o.format == "json" {
			data, _ := json.MarshalIndent(state, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
			return nil
		}
		if state.Rotation == nil {
			fmt.Fprintf(cmd.OutOrStdout(), "active generation: %d\nrotation: none\n", state.ActiveGeneration)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "active generation: %d\nrotation: %d -> %d\nphase: %s\nstarted: %s\n", state.ActiveGeneration, state.Rotation.From, state.Rotation.To, state.Rotation.Phase, state.Rotation.StartedAt.Format(time.RFC3339))
		}

		return nil
	}}

	addRootRotationFlags(cmd, o)
	return cmd
}

func makeRootRotationFinalizeCommand() *cobra.Command {
	o := &rootRotationOptions{}
	cmd := &cobra.Command{Use: "finalize", Short: "Remove old Root generations after migration", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := validateCLIName(o.pki, "pki"); err != nil {
			return err
		}
		if err := validateFormat(o.format); err != nil {
			return err
		}

		lock, err := exclusiveLock(o.root, o.pki)
		if err != nil {
			return err
		}
		defer lock.Close()

		state, err := readRootState(o.root, o.pki)
		if err != nil {
			return err
		}
		if state.Rotation == nil {
			return operational(fmt.Errorf("no Root rotation is in progress"))
		}
		if err = validateRootFinalize(o.root, o.pki, state); err != nil {
			return operational(err)
		}

		state.Rotation.Phase = "finalizing"
		if err = writeRootState(o.root, o.pki, state); err != nil {
			return err
		}

		activeCert, err := os.ReadFile(filepath.Join(o.root, o.pki, "root", "certs", "root.crt"))
		if err != nil {
			return operational(err)
		}
		if err = write(filepath.Join(o.root, o.pki, "root", "certs", "trust-bundle.crt"), activeCert, 0644, true); err != nil {
			return operational(err)
		}

		state.TrustGenerations = []uint64{state.ActiveGeneration}
		state.Rotation = nil
		if err = writeRootState(o.root, o.pki, state); err != nil {
			return err
		}
		if o.format == "json" {
			data, _ := json.Marshal(map[string]any{"operation": "root-rotation-finalize", "activeGeneration": state.ActiveGeneration, "status": "complete"})
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Root rotation finalized at generation %d\n", state.ActiveGeneration)
		}

		return nil
	}}

	addRootRotationFlags(cmd, o)
	return cmd
}

func readRootState(root, pki string) (rootMetadata, error) {
	data, err := os.ReadFile(filepath.Join(root, pki, "root", "metadata.json"))
	if err != nil {
		return rootMetadata{}, operational(err)
	}

	var state rootMetadata
	if err = json.Unmarshal(data, &state); err != nil {
		return state, operational(err)
	}
	if err = validateSchemaVersion(state.SchemaVersion); err != nil {
		return state, operational(err)
	}
	if state.SchemaVersion == 0 {
		state.SchemaVersion = storageSchemaVersion
	}

	return state, nil
}

func writeRootState(root, pki string, state rootMetadata) error {
	state.SchemaVersion = storageSchemaVersion
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return operational(err)
	}
	if err = write(filepath.Join(root, pki, "root", "metadata.json"), append(data, '\n'), 0644, true); err != nil {
		return operational(err)
	}

	return nil
}

func validateRootFinalize(root, pki string, state rootMetadata) error {
	entries, err := os.ReadDir(filepath.Join(root, pki, "issuers"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(root, pki, "issuers", entry.Name(), "metadata.json"))
		if err != nil {
			return err
		}

		var meta metadata
		if err = json.Unmarshal(data, &meta); err != nil {
			return err
		}
		if meta.Status == "active" && meta.RootGeneration != state.ActiveGeneration {
			return fmt.Errorf("active issuer %s still uses Root generation %d", meta.Name, meta.RootGeneration)
		}
	}

	records, err := readRecords(filepath.Join(root, pki, "index", "certificates.jsonl"))
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	for _, record := range records {
		generation := record.RootGeneration
		if generation == 0 {
			generation = 1
		}
		if record.Status == "valid" && record.NotAfter.After(now) && generation != state.ActiveGeneration {
			return fmt.Errorf("valid certificate %s/%s still uses Root generation %d", record.Type, record.Name, generation)
		}
	}

	return nil
}
