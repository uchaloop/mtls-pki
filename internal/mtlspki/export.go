package mtlspki

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

type exportOptions struct {
	root, pki, typ, name, format, resultFormat, out, secret, namespace string
	includeKey, force                                                  bool
}

func makeExportCommand() *cobra.Command {
	o := &exportOptions{}
	cmd := &cobra.Command{Use: "export", Short: "Export certificate material", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runExport(cmd, o) }}
	f := cmd.Flags()
	f.StringVarP(&o.root, "root", "r", "pki", "PKI storage root")
	f.StringVarP(&o.pki, "pki", "p", "", "PKI name")
	f.StringVarP(&o.typ, "type", "t", "", "server or client")
	f.StringVarP(&o.name, "name", "n", "", "certificate name")
	f.StringVar(&o.format, "format", "pem", "export format: pem, json or kubernetes")
	f.StringVarP(&o.resultFormat, "output", "o", "text", "result format: text or json")
	f.StringVarP(&o.out, "out", "O", "", "output file (stdout if empty)")
	f.BoolVar(&o.includeKey, "include-private-key", false, "include private key in PEM/JSON")
	f.BoolVarP(&o.force, "force", "f", false, "replace output file")
	f.StringVar(&o.secret, "secret-name", "mtls-certificate", "Kubernetes Secret name")
	f.StringVar(&o.namespace, "namespace", "default", "Kubernetes namespace")
	return cmd
}

func runExport(cmd *cobra.Command, o *exportOptions) error {
	if err := validateCLIName(o.pki, "pki"); err != nil {
		return err
	}
	if err := validateCLIName(o.name, "name"); err != nil {
		return err
	}
	if o.typ != "server" && o.typ != "client" {
		return usageError("--type must be server or client")
	}
	if err := validateFormat(o.resultFormat); err != nil {
		return err
	}
	if o.resultFormat == "json" && len(o.out) == 0 {
		return usageError("--output json requires --out")
	}
	if (o.includeKey || o.format == "kubernetes") && len(o.out) == 0 {
		return usageError("private key export requires --out")
	}
	if o.format == "kubernetes" {
		if err := validateKubernetesDNSSubdomain(o.secret, "secret-name"); err != nil {
			return err
		}
		if err := validateKubernetesDNSLabel(o.namespace, "namespace"); err != nil {
			return err
		}
	}

	lock, err := sharedLock(o.root, o.pki)
	if err != nil {
		return err
	}
	defer lock.Close()

	dir := filepath.Join(o.root, o.pki, "certificates", o.typ, o.name)
	crt, err := os.ReadFile(filepath.Join(dir, "certs", o.typ+".crt"))
	if err != nil {
		return operational(err)
	}

	chain, err := os.ReadFile(filepath.Join(dir, "certs", "chain.crt"))
	if err != nil {
		return operational(err)
	}

	fullchain, err := os.ReadFile(filepath.Join(dir, "certs", "fullchain.crt"))
	if err != nil {
		return operational(err)
	}

	var key []byte
	if o.includeKey || o.format == "kubernetes" {
		key, err = os.ReadFile(filepath.Join(dir, "private", o.typ+".key"))
		if err != nil {
			return operational(fmt.Errorf("private key is required for %s export: %w", o.format, err))
		}
	}

	var data []byte
	switch o.format {
	case "pem":
		data = append(append([]byte{}, crt...), chain...)
		if o.includeKey {
			data = append(data, key...)
		}
	case "json":
		value := map[string]string{"certificate": string(crt), "chain": string(chain), "fullchain": string(fullchain)}
		if o.includeKey {
			value["privateKey"] = string(key)
		}

		data, _ = json.MarshalIndent(value, "", "  ")
		data = append(data, '\n')
	case "kubernetes":
		data = fmt.Appendf(nil, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ntype: kubernetes.io/tls\ndata:\n  tls.crt: %s\n  tls.key: %s\n  ca.crt: %s\n", o.secret, o.namespace, base64.StdEncoding.EncodeToString(fullchain), base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(chain))
	default:
		return usageError("--format must be pem, json or kubernetes")
	}
	if len(o.out) == 0 {
		_, err = cmd.OutOrStdout().Write(data)
		return operational(err)
	}
	if err = write(o.out, data, 0600, o.force); err != nil {
		return operational(err)
	}
	if o.resultFormat == "json" {
		result, _ := json.Marshal(map[string]string{"operation": "export", "format": o.format, "path": o.out})
		fmt.Fprintln(cmd.OutOrStdout(), string(result))
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "export:", o.out)
	}

	return nil
}

func validateKubernetesDNSSubdomain(value, flag string) error {
	if len(value) == 0 || len(value) > 253 {
		return usageError("--%s must be a Kubernetes DNS-1123 subdomain of at most 253 characters", flag)
	}

	for label := range strings.SplitSeq(value, ".") {
		if err := validateKubernetesDNSLabelValue(label); err != nil {
			return usageError("--%s must be a Kubernetes DNS-1123 subdomain: %v", flag, err)
		}
	}

	return nil
}

func validateKubernetesDNSLabel(value, flag string) error {
	if err := validateKubernetesDNSLabelValue(value); err != nil {
		return usageError("--%s must be a Kubernetes DNS-1123 label: %v", flag, err)
	}

	return nil
}

func validateKubernetesDNSLabelValue(value string) error {
	if len(value) == 0 || len(value) > 63 {
		return fmt.Errorf("each label must contain between 1 and 63 characters")
	}
	if value[0] == '-' || value[len(value)-1] == '-' {
		return fmt.Errorf("a label must start and end with a lowercase letter or digit")
	}

	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
			return fmt.Errorf("a label may contain only lowercase letters, digits and hyphens")
		}
	}

	return nil
}
