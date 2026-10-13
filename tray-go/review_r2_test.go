package main

import "testing"

// P2E1: the tray reads the CLI's unsupervised_pct instead of re-deriving it.
func TestUnsupervisedPctComesFromTheCLI(t *testing.T) {
	r := parseReport([]byte(`{"unsupervised_pct": 37.5,
		"permission_modes": {"codex:never": 4, "sandbox:workspace-write": 4}}`), 7)
	if !r.hasUnsup || r.unsupPct != 37.5 {
		t.Fatalf("unsupPct=%v hasUnsup=%v, want the CLI's 37.5", r.unsupPct, r.hasUnsup)
	}
	r = parseReport([]byte(`{"unsupervised_pct": null, "permission_modes": {}}`), 7)
	if r.hasUnsup {
		t.Fatal("a null unsupervised_pct (no recorded mode) showed a share")
	}
}

// P2E1 fallback for an older CLI: a Codex sandbox: key is not a turn.
func TestOlderCLISandboxKeyIsNotATurn(t *testing.T) {
	r := parseReport([]byte(`{"permission_modes": {"codex:never": 4, "sandbox:workspace-write": 4}}`), 7)
	if !r.hasUnsup || r.unsupPct < 99.9 || r.unsupPct > 100.1 {
		t.Fatalf("unsupPct=%v hasUnsup=%v, want 100 (as actualis --share says)", r.unsupPct, r.hasUnsup)
	}
}

// P2E4: "N flagged" is the CLI's per-command, unsuppressed high count.
func TestFlaggedHighComesFromTheCLI(t *testing.T) {
	r := parseReport([]byte(`{"bash": {"total": 1,
		"flag_counts": {"high:remote-exec": 1, "high:destructive": 1, "high:privilege": 1},
		"flagged": {"high": 0, "medium": 0},
		"flags": [{"severity": "high", "suppressed": true}]}}`), 7)
	if r.flaggedHigh != 0 || r.shell != 1 {
		t.Fatalf("flaggedHigh=%d shell=%d, want 0 and 1", r.flaggedHigh, r.shell)
	}
}

// P2E4 fallback for an older CLI: count bash.flags[], skipping suppressed ones,
// never the per-category flag_counts.
func TestOlderCLIFlaggedHighCountsCommands(t *testing.T) {
	r := parseReport([]byte(`{"bash": {"total": 3,
		"flag_counts": {"high:remote-exec": 2, "high:destructive": 2, "med:network": 1},
		"flags": [
			{"severity": "high", "suppressed": true, "categories": ["remote-exec", "destructive"]},
			{"severity": "high", "suppressed": false, "categories": ["remote-exec", "destructive"]},
			{"severity": "med"}
		]}}`), 7)
	if r.flaggedHigh != 1 {
		t.Fatalf("flaggedHigh=%d, want 1", r.flaggedHigh)
	}
}
