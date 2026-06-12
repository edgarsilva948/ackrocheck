// Package controls embeds the built-in AckroCheck security controls so the
// released binary is fully self-contained.
package controls

import (
	"embed"

	"github.com/edgarsilva948/ackrocheck/internal/policy"
)

//go:embed aws
var builtinFS embed.FS

// Builtin loads and validates all embedded built-in controls.
func Builtin() ([]policy.Policy, error) {
	return policy.LoadFS(builtinFS, "aws")
}
