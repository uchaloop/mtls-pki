package mtlspki

import (
	"errors"
	"fmt"
	"os"

	"github.com/uchaloop/mtls-pki/internal/apperr"

	"github.com/spf13/cobra"
)

// Execute builds and runs the mtls-pki command tree and returns its process exit code.

func MakeCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "mtls-pki",
		Short:         "Operate a small private mTLS PKI",
		Version:       buildVersion(),
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	root.CompletionOptions.DisableDefaultCmd = false

	root.AddCommand(group("root", "Manage Root CA",
		makeRootCommand("create"),
		makeRootCommand("rotate"),
		group("rotation", "Inspect or finalize Root rotation",
			makeRootRotationStatusCommand(),
			makeRootRotationFinalizeCommand(),
		),
	))
	root.AddCommand(group("issuer", "Manage issuing CAs",
		makeIssuerCommand("create"),
		makeIssuerCommand("rotate"),
		makeIssuerListCommand(),
		makeIssuerInspectCommand(),
		makeIssuerStatusCommand("retire"),
		makeIssuerStatusCommand("activate"),
	))
	root.AddCommand(group("server", "Manage server certificates",
		makeLeafCommand("server", "issue"),
		makeLeafCommand("server", "renew"),
	))
	root.AddCommand(group("client", "Manage client certificates",
		makeLeafCommand("client", "issue"),
		makeLeafCommand("client", "renew"),
	))
	root.AddCommand(makeInspectCommand())
	root.AddCommand(makeVerifyCommand())
	root.AddCommand(makeListCommand())
	root.AddCommand(makeRevokeCommand())
	root.AddCommand(makeRecoverCommand())
	root.AddCommand(makeDoctorCommand())
	root.AddCommand(group("crl", "Manage certificate revocation lists",
		makeCRLGenerateCommand(),
	))
	root.AddCommand(group("csr", "Create, inspect, and sign certificate requests",
		makeCSRCreateCommand(),
		makeCSRInspectCommand(),
		makeCSRSignCommand(),
	))
	root.AddCommand(makeExportCommand())
	return root
}

func Execute() int {
	root := MakeCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		var appErr *apperr.Error
		if errors.As(err, &appErr) {
			return appErr.Code
		}

		return apperr.Usage
	}

	return 0
}

func group(use, short string, children ...*cobra.Command) *cobra.Command {
	c := &cobra.Command{Use: use, Short: short}
	c.AddCommand(children...)
	return c
}
