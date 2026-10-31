package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeState(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "gsb"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gsb", "state.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestListsAgeIsTheOldestList(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	dir := writeState(t, `{"schema":1,"lists":[
		{"name":"mw-4b","fetched_at":"2026-10-30T12:00:00+00:00"},
		{"name":"se-4b","fetched_at":"2026-10-28T12:00:00+00:00"}]}`)
	age, ok := listsAge(dir, now)
	if !ok || age != 72*time.Hour {
		t.Fatalf("age %v ok %v, want 72h true", age, ok)
	}
}

func TestListsAgeHidesWhatItCannotTrust(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"corrupt":     `{"lists": [`,
		"empty":       `{"schema":1,"lists":[]}`,
		"bad time":    `{"lists":[{"fetched_at":"yesterday"}]}`,
		"future":      `{"lists":[{"fetched_at":"2026-11-02T00:00:00+00:00"}]}`,
		"wrong shape": `{"lists":"mw-4b"}`,
	}
	for name, body := range cases {
		if _, ok := listsAge(writeState(t, body), now); ok {
			t.Errorf("%s: want ok=false", name)
		}
	}
	if _, ok := listsAge(t.TempDir(), now); ok {
		t.Error("never downloaded: want ok=false (reputation is opt-in)")
	}
	big := writeState(t, `{"lists":[]}`+strings.Repeat(" ", 1<<20))
	if _, ok := listsAge(big, now); ok {
		t.Error("oversized state: want ok=false")
	}
}

func TestListsLabel(t *testing.T) {
	cases := []struct {
		age  time.Duration
		want string
	}{
		{26 * time.Hour, "Update Safe Browsing Lists (26 hours old)…"},
		{3*24*time.Hour + 5*time.Hour, "Update Safe Browsing Lists (3 days old)…"},
		{9 * 24 * time.Hour, "Update Safe Browsing Lists (9 days old, stale)…"},
	}
	for _, c := range cases {
		if got := listsLabel(c.age); got != c.want {
			t.Errorf("listsLabel(%v) = %q, want %q", c.age, got, c.want)
		}
	}
	if got := listsTooltip("Actualis — ok", 9*24*time.Hour); got != "Actualis — ok · Safe Browsing lists 9 days old, stale" {
		t.Errorf("tooltip %q", got)
	}
}

func TestListsDueThreshold(t *testing.T) {
	now := time.Now().UTC()
	for _, c := range []struct {
		ago  time.Duration
		want bool
	}{{23 * time.Hour, false}, {25 * time.Hour, true}} {
		dir := writeState(t, `{"lists":[{"fetched_at":"`+now.Add(-c.ago).Format(time.RFC3339)+`"}]}`)
		t.Setenv("ACTUALIS_REPUTATION_DIR", dir)
		if _, due := listsDue(); due != c.want {
			t.Errorf("fetched %v ago: due=%v, want %v", c.ago, due, c.want)
		}
	}
}

func TestUpdateStateRanksBelowCredentialStates(t *testing.T) {
	u := newUI()
	u.listsDue = true
	if s := u.state(); s != "update" {
		t.Fatalf("idle with due lists: %q, want update", s)
	}
	u.rep.rotatable = 1
	if s := u.state(); s != "monitoring" {
		t.Fatalf("rotatable credentials must outrank lists: %q", s)
	}
	u.rep.critical = 1
	if s := u.state(); s != "exposed" {
		t.Fatalf("an exposure must outrank lists: %q", s)
	}
	if len(iconFor("update", true)) == 0 || len(iconFor("update", false)) == 0 {
		t.Fatal("update icon is not embedded")
	}
}

func TestFindToolLooksForTheCompanionByName(t *testing.T) {
	dir := t.TempDir()
	name := "actualis-reputation"
	if os.PathSeparator == '\\' {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if got := findTool("actualis-reputation"); got == "" || filepath.Base(got) != name {
		t.Fatalf("findTool = %q", got)
	}
}
