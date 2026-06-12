package version

import (
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	info := Get()
	if info.Version != Version || info.ControlsVersion != ControlsVersion {
		t.Errorf("info = %+v", info)
	}
	if !strings.HasPrefix(info.GoVersion, "go") {
		t.Errorf("GoVersion = %q", info.GoVersion)
	}
}

func TestString(t *testing.T) {
	out := Info{
		Version:         "1.0.0",
		ControlsVersion: "controls-1",
		Commit:          "abc123",
		Date:            "2026-01-01",
		GoVersion:       "go1.21.0",
	}.String()
	for _, want := range []string{
		"AckroCheck version: 1.0.0",
		"Controls version: controls-1",
		"Commit: abc123",
		"Build date: 2026-01-01",
		"Go version: go1.21.0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}
