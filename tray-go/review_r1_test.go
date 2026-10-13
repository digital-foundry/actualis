package main

import (
	"strings"
	"testing"
)

// G4: a suppressed credential must not light the badge or count as new.
func TestSuppressedSecretsAreNotCounted(t *testing.T) {
	out := []byte(`{"secrets": [
		{"id": "fp1", "priority": "critical", "suppressed": true},
		{"id": "fp2", "priority": "high", "suppressed": true},
		{"id": "fp3", "priority": "critical"},
		{"id": "fp4", "priority": "high", "suppressed": false}
	]}`)
	r := parseReport(out, 7)
	if r.critical != 1 || r.rotatable != 2 {
		t.Fatalf("critical=%d rotatable=%d, want 1 and 2", r.critical, r.rotatable)
	}
	if r.fingerprints["fp1"] || !r.fingerprints["fp3"] {
		t.Fatalf("fingerprints=%v, want only fp3", r.fingerprints)
	}
}

// G5: the tray's "ran unsupervised" uses the CLI's definition, codex:never included.
func TestCodexNeverCountsAsUnsupervised(t *testing.T) {
	r := parseReport([]byte(`{"permission_modes": {"codex:never": 90, "default": 10}}`), 7)
	if !r.hasUnsup || r.unsupPct < 89.9 || r.unsupPct > 90.1 {
		t.Fatalf("unsupPct=%v hasUnsup=%v, want 90", r.unsupPct, r.hasUnsup)
	}
	for k, want := range map[string]bool{
		"auto": true, "bypassPermissions": true, "codex:never": true,
		"default": false, "codex:on-request": false, "plan": false,
	} {
		if got := isUngatedMode(k); got != want {
			t.Errorf("isUngatedMode(%q) = %v, want %v", k, got, want)
		}
	}
}

// G9: a report carries its own window, and a scan over a new window
// re-baselines instead of announcing old exposures as new.
func TestWindowChangeRebaselines(t *testing.T) {
	u := newUI()
	r7 := report{days: 7, fingerprints: map[string]bool{"a": true}}
	if fresh := u.absorb(r7); len(fresh) != 0 {
		t.Fatalf("first scan announced %v", fresh)
	}
	r7b := report{days: 7, fingerprints: map[string]bool{"a": true, "b": true}}
	if fresh := u.absorb(r7b); len(fresh) != 1 || fresh[0] != "b" {
		t.Fatalf("same window, new fingerprint: got %v, want [b]", fresh)
	}
	r90 := report{days: 90, fingerprints: map[string]bool{"a": true, "b": true, "old": true}}
	if fresh := u.absorb(r90); len(fresh) != 0 {
		t.Fatalf("widening the window announced old exposures: %v", fresh)
	}
	r90b := report{days: 90, fingerprints: map[string]bool{"a": true, "b": true, "old": true, "new": true}}
	if fresh := u.absorb(r90b); len(fresh) != 1 || fresh[0] != "new" {
		t.Fatalf("after re-baselining: got %v, want [new]", fresh)
	}
	if parseReport([]byte(`{}`), 30).days != 30 {
		t.Fatal("parseReport does not record the window")
	}
}

// An error report must not become the baseline.
func TestErrorReportDoesNotPrime(t *testing.T) {
	u := newUI()
	u.absorb(report{days: 7, err: "boom"})
	if u.primed {
		t.Fatal("an error primed the baseline")
	}
}

// G11: the Windows notification is a real toast, and the text never enters
// the script (it would be evaluated by PowerShell).
func TestWindowsNotifyCmd(t *testing.T) {
	title, body := "t$(calc)", "b`whoami`"
	cmd := windowsNotifyCmd(title, body)
	script := cmd.Args[len(cmd.Args)-1]
	if strings.Contains(script, title) || strings.Contains(script, body) {
		t.Fatal("notification text reached the PowerShell script")
	}
	if !strings.Contains(script, "ToastNotificationManager") || strings.Contains(script, "Write-Output") {
		t.Fatal("not a toast")
	}
	env := strings.Join(cmd.Env, "\n")
	if !strings.Contains(env, "ACTUALIS_TRAY_NOTIFY_TITLE="+title) ||
		!strings.Contains(env, "ACTUALIS_TRAY_NOTIFY_BODY="+body) {
		t.Fatal("text not passed through the environment")
	}
}
