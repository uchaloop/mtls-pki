package mtlspki

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestCLIContract(t *testing.T) {
	root := MakeCommand()
	required := [][]string{
		{"root", "create"}, {"root", "rotate"}, {"root", "rotation", "status"}, {"root", "rotation", "finalize"},
		{"issuer", "create"}, {"issuer", "rotate"}, {"issuer", "list"}, {"issuer", "inspect"}, {"issuer", "activate"}, {"issuer", "retire"},
		{"server", "issue"}, {"server", "renew"}, {"client", "issue"}, {"client", "renew"},
		{"csr", "create"}, {"csr", "inspect"}, {"csr", "sign"}, {"crl", "generate"},
		{"inspect"}, {"verify"}, {"list"}, {"revoke"}, {"recover"}, {"export"}, {"doctor"},
	}

	for _, path := range required {
		if commandAt(root, path...) == nil {
			t.Fatalf("missing command %v", path)
		}
	}

	for _, path := range [][]string{{"server", "issue"}, {"client", "issue"}, {"doctor"}, {"list"}} {
		command := commandAt(root, path...)
		for _, flag := range []string{"root", "pki", "output"} {
			if command.Flags().Lookup(flag) == nil {
				t.Errorf("command %v is missing --%s", path, flag)
			}
		}
	}
}

func commandAt(root *cobra.Command, path ...string) *cobra.Command {
	current := root
	for _, name := range path {
		var next *cobra.Command
		for _, child := range current.Commands() {
			if child.Name() == name {
				next = child
				break
			}
		}
		if next == nil {
			return nil
		}

		current = next
	}

	return current
}
