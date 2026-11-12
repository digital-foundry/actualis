package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// #95: the tray's reading of `actualis --watch --json`. Synthetic data only.

const chrome = "mcp__claude-in-chrome__get_page_text"

func ev(t *testing.T, line string) watchEvent {
	t.Helper()
	e, ok := parseEvent([]byte(line))
	if !ok {
		t.Fatalf("parseEvent(%s) not ok", line)
	}
	return e
}

func TestParseEvent(t *testing.T) {
	e := ev(t, `{"event": "finding", "at": "2026-11-12T10:00:00+00:00", "source": "screen",
		"kind": "personal", "detector": "email", "id": "8377d007", "priority": null,
		"suppressed": false, "agent": "claude-code", "tool": "`+chrome+`",
		"family": "claude-in-chrome", "session": "s1", "project": "shop", "future_field": [1]}`)
	if e.Event != "finding" || e.Kind != "personal" || e.Detector != "email" || e.Priority != "" ||
		e.Tool != chrome || e.Source != "screen" {
		t.Fatalf("got %+v", e)
	}
	h := ev(t, `{"event": "hello", "schema_version": 1, "screen": true}`)
	if !h.Screen {
		t.Fatal("hello.screen not read")
	}
	for _, bad := range []string{"", "not json", `[1,2]`, `{"phase": "start"}`, `{"event": 7}`,
		`{"event": "x", "tool": ` + strings.Repeat(" ", maxEventLine) + `"t"}`} {
		if _, ok := parseEvent([]byte(bad)); ok {
			t.Errorf("parseEvent(%.30q) ok, want not ok", bad)
		}
	}
}

func TestLookingTimesOut(t *testing.T) {
	l := newLiveState()
	t0 := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	if l.looking(t0) {
		t.Fatal("looking before any event")
	}
	start := watchEvent{Event: "activity", Phase: "start", Tool: chrome, Family: "claude-in-chrome",
		Agent: "claude-code", Session: "s1"}
	end := start
	end.Phase = "end"

	// A short call: looking for lookWindow after its end.
	l.apply(start, t0)
	l.apply(end, t0.Add(2*time.Second))
	if !l.looking(t0.Add(2*time.Second + lookWindow - time.Second)) {
		t.Error("not looking within the window")
	}
	if l.looking(t0.Add(2*time.Second + lookWindow)) {
		t.Error("still looking after the window")
	}

	// A call still open keeps it on past lookWindow, but not past openCallMax.
	t1 := t0.Add(time.Hour)
	l.apply(start, t1)
	if !l.looking(t1.Add(3 * time.Minute)) {
		t.Error("open call: not looking at 3 minutes")
	}
	if l.looking(t1.Add(openCallMax)) {
		t.Error("open call: still looking after openCallMax")
	}
	if len(l.open) != 0 {
		t.Error("stale open call not dropped")
	}
}

func TestLiveCountsAndRescans(t *testing.T) {
	l := newLiveState()
	t0 := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		line string
		want rescan
	}{
		{`{"event": "activity", "phase": "start", "tool": "` + chrome + `", "session": "s"}`, rescanNone},
		{`{"event": "activity", "phase": "end", "tool": "` + chrome + `", "session": "s"}`, rescanNone},
		{`{"event": "finding", "source": "screen", "kind": "personal", "detector": "email", "id": "aaaaaaaa"}`, rescanQuiet},
		{`{"event": "finding", "source": "screen", "kind": "credential", "detector": "Stripe key", "id": "bbbbbbbb", "priority": "critical"}`, rescanSoon},
		{`{"event": "finding", "source": "screen", "kind": "credential", "id": "cccccccc", "suppressed": true}`, rescanNone},
		{`{"event": "finding", "source": "command", "kind": "credential", "id": "dddddddd"}`, rescanSoon},
		{`{"event": "screenshot", "tool": "` + chrome + `", "count": 2}`, rescanQuiet},
		{`{"event": "flag", "categories": ["remote-exec"]}`, rescanNone},
		{`{"event": "heartbeat"}`, rescanNone},
		{`{"event": "something-new"}`, rescanNone},
	}
	for i, c := range cases {
		if got := l.apply(ev(t, c.line), t0.Add(time.Duration(i)*time.Second)); got != c.want {
			t.Errorf("%s: rescan %v, want %v", c.line, got, c.want)
		}
	}
	got := l.since(t0)
	want := liveCount{results: 1, personal: 1, credentials: 2, shots: 2}
	got.at = time.Time{}
	if got != want {
		t.Fatalf("since(t0) = %+v, want %+v", got, want)
	}
	// A scan that started after the personal finding has it; only later ones count.
	later := l.since(t0.Add(3 * time.Second))
	if later.personal != 0 || later.credentials != 2 || later.shots != 2 || later.results != 0 {
		t.Fatalf("since(t0+3s) = %+v", later)
	}
	if len(l.counts) != 3 {
		t.Fatalf("older counts not pruned: %d left", len(l.counts))
	}
}

func TestWithLiveNeedsTheScreenKey(t *testing.T) {
	c := liveCount{results: 2, personal: 3, shots: 4}
	if got := withLive(screenSeen{}, c); got != (screenSeen{}) {
		t.Fatalf("older CLI: %+v, want nothing", got)
	}
	got := withLive(screenSeen{present: true, personal: 15, screenshots: 842}, c)
	if screenLabel(got) != "Seen on screen: 18 personal data  ·  846 screenshots" {
		t.Fatalf("label %q", screenLabel(got))
	}
}

func TestTrayStatePriority(t *testing.T) {
	cases := []struct {
		r            report
		due, looking bool
		want         string
	}{
		{report{critical: 1, rotatable: 1}, true, true, "exposed"},
		{report{rotatable: 2}, true, true, "monitoring"},
		{report{}, true, true, "looking"},
		{report{}, true, false, "update"},
		{report{}, false, true, "looking"},
		{report{}, false, false, "idle"},
	}
	for _, c := range cases {
		if got := trayState(c.r, c.due, c.looking); got != c.want {
			t.Errorf("trayState(%+v, due=%v, looking=%v) = %q, want %q", c.r, c.due, c.looking, got, c.want)
		}
	}
}

func TestTooltipNamesToolAndAgent(t *testing.T) {
	look := lookingLabel(chrome, "claude-in-chrome", "claude-code")
	if look != "Claude Code is using Claude in Chrome (get_page_text)" {
		t.Fatalf("lookingLabel = %q", look)
	}
	if got := lookingLabel("computer", "computer-use", "x"); got != "An agent is using computer use (computer)" {
		t.Errorf("unknown agent: %q", got)
	}
	if got := tooltipFor(report{}, "looking", true, look, 0); got != "Actualis — "+look {
		t.Errorf("looking tooltip %q", got)
	}
	got := tooltipFor(report{critical: 2, rotatable: 3}, "exposed", true, look, 0)
	if got != "Actualis — 2 critical credential(s) exposed  ·  "+look {
		t.Errorf("exposed+looking tooltip %q", got)
	}
	if got := tooltipFor(report{}, "idle", false, look, 0); got != "Actualis — no critical credentials exposed" {
		t.Errorf("idle tooltip %q", got)
	}
}

// fakeCLI writes a shell script standing in for actualis. POSIX only.
func fakeCLI(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script stand-in for the CLI")
	}
	p := filepath.Join(t.TempDir(), "actualis")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStreamDeliversEventsAfterHello(t *testing.T) {
	bin := fakeCLI(t, `[ "$1 $2" = "--watch --json" ] || exit 9
echo '{"event": "hello", "schema_version": 1, "screen": true}'
echo 'garbage'
echo '{"event": "activity", "phase": "start", "tool": "`+chrome+`", "agent": "claude-code"}'
echo '{"event": "finding", "source": "screen", "kind": "personal", "detector": "email", "id": "aaaaaaaa"}'
`)
	var got []string
	ok := streamOnce(bin, []string{"--watch", "--json"}, make(chan struct{}),
		func(e watchEvent) { got = append(got, e.Event) })
	if !ok || strings.Join(got, ",") != "activity,finding" {
		t.Fatalf("ok=%v events=%v", ok, got)
	}
}

func TestStreamFallsBackForAnOlderCLI(t *testing.T) {
	for name, body := range map[string]string{
		"refuses the flag": `echo "actualis: error: --json cannot be combined with --watch" >&2; exit 2`,
		"no screen events": `echo '{"event": "hello", "screen": false}'; echo '{"event": "activity"}'`,
		"text, not json":   `echo "actualis watch · 3 files"; sleep 0`,
	} {
		bin := fakeCLI(t, body)
		called := false
		if streamOnce(bin, []string{"--watch", "--json"}, make(chan struct{}),
			func(watchEvent) { called = true }) {
			t.Errorf("%s: ok, want fallback", name)
		}
		if called {
			t.Errorf("%s: events delivered from an unsupported stream", name)
		}
	}
}

func TestStreamStopsTheChild(t *testing.T) {
	bin := fakeCLI(t, `echo '{"event": "hello", "screen": true}'
exec sleep 60
`)
	stop := make(chan struct{})
	done := make(chan bool)
	go func() { done <- streamOnce(bin, nil, stop, func(watchEvent) {}) }()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	select {
	case ok := <-done:
		if !ok {
			t.Error("hello was sent: want ok")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child not stopped")
	}
}
