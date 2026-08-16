package main

import (
	"os"

	"github.com/uchaloop/mtls-pki/internal/mtlspki"
)

func main() {
	os.Exit(mtlspki.Execute())
}
