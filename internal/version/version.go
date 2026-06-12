// Package version holds build-time version information for AckroCheck.
// All values are overridable via -ldflags at build time.
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the AckroCheck release version.
	Version = "dev"
	// ControlsVersion identifies the embedded controls bundle.
	ControlsVersion = "embedded-dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// Date is the build date.
	Date = "unknown"
)

// Info holds resolved version information.
type Info struct {
	Version         string `json:"version"`
	ControlsVersion string `json:"controls_version"`
	Commit          string `json:"commit"`
	Date            string `json:"date"`
	GoVersion       string `json:"go_version"`
}

// Get returns the current build information.
func Get() Info {
	return Info{
		Version:         Version,
		ControlsVersion: ControlsVersion,
		Commit:          Commit,
		Date:            Date,
		GoVersion:       runtime.Version(),
	}
}

// String renders the version information in the canonical human-readable form.
func (i Info) String() string {
	return fmt.Sprintf(
		"AckroCheck version: %s\nControls version: %s\nCommit: %s\nBuild date: %s\nGo version: %s\n",
		i.Version, i.ControlsVersion, i.Commit, i.Date, i.GoVersion,
	)
}
