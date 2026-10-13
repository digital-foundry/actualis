package main

import (
	"strings"
	"testing"
)

// R3G2: with commands that have no recorded mode (every Gemini CLI one), the
// tray's supervision line says what the share covers and names the rest.
func TestUnsupervisedLineNamesCommandsWithNoMode(t *testing.T) {
	r := parseReport([]byte(`{"unsupervised_pct": 100.0, "moded_commands": 1,
		"unmoded_commands": 3, "permission_modes": {"yolo": 1}}`), 7)
	got := unsupLabel(r)
	if got == "100% ran unsupervised" || !strings.Contains(got, "recorded mode") ||
		!strings.Contains(got, "3 commands had none") {
		t.Fatalf("label %q overstates the share", got)
	}
	r = parseReport([]byte(`{"unsupervised_pct": 37.5, "unmoded_commands": 0}`), 7)
	if got := unsupLabel(r); got != "38% ran unsupervised" {
		t.Fatalf("fully moded fleet: label %q", got)
	}
	r = parseReport([]byte(`{"unsupervised_pct": null, "unmoded_commands": 2}`), 7)
	if got := unsupLabel(r); !strings.Contains(got, "2 shell commands had no recorded") {
		t.Fatalf("no moded turns: label %q", got)
	}
}
