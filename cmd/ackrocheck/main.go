// Command ackrocheck is a static security scanner for AWS ACK and KRO
// Kubernetes manifests.
package main

import (
	"os"

	"github.com/edgarsilva948/ackrocheck/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}
