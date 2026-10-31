package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeInFlight(t *testing.T, dir string, pid int, at time.Time) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"pid": pid, "provider": "gsb", "started_at": at.UTC().Format(time.RFC3339)})
	if err := os.WriteFile(filepath.Join(dir, "in-flight.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNetInFlight(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if netInFlight(dir, now) {
		t.Fatal("no marker should mean no network use")
	}
	writeInFlight(t, dir, os.Getpid(), now.Add(-time.Minute))
	if !netInFlight(dir, now) {
		t.Fatal("a live process with a fresh marker is network use")
	}
	writeInFlight(t, dir, os.Getpid(), now.Add(-2*time.Hour))
	if netInFlight(dir, now) {
		t.Fatal("a marker older than an hour is stale")
	}
	os.WriteFile(filepath.Join(dir, "in-flight.json"), []byte("{bad"), 0o600)
	if netInFlight(dir, now) {
		t.Fatal("a malformed marker is ignored")
	}
}

func TestReputationDirFollowsActualis(t *testing.T) {
	t.Setenv("ACTUALIS_REPUTATION_DIR", "/x/rep")
	if got := reputationDir(); got != "/x/rep" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("ACTUALIS_REPUTATION_DIR", "")
	t.Setenv("XDG_CACHE_HOME", "/x/cache")
	if got := reputationDir(); got != filepath.Join("/x/cache", "actualis", "reputation") && os.Getenv("LOCALAPPDATA") == "" {
		t.Fatalf("got %q", got)
	}
}

func TestIconForNetwork(t *testing.T) {
	if len(iconFor("network", true)) == 0 || len(iconFor("network", false)) == 0 {
		t.Fatal("network icons must be embedded")
	}
	if string(iconFor("network", true)) == string(iconFor("idle", true)) {
		t.Fatal("network icon must differ from idle")
	}
}
