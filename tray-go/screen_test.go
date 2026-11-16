package main

import (
	"strings"
	"testing"
)

// #94: the tray reads `screen` from --json. Synthetic data only.
func TestParseReportScreen(t *testing.T) {
	cases := []struct {
		name  string
		json  string
		want  screenSeen
		label string
	}{
		{"absent key (older CLI)", `{"secrets": []}`, screenSeen{}, ""},
		{"empty", `{"screen": {}}`, screenSeen{present: true}, ""},
		{"no browser results", `{"screen": {"results_scanned": 0, "credentials": 0,
			"personal_data": 0, "screenshots_total": 0}}`, screenSeen{present: true}, ""},
		{"scanned, nothing found", `{"screen": {"results_scanned": 3}}`,
			screenSeen{present: true, results: 3},
			"Seen on screen: 0 personal data  ·  0 screenshots"},
		{"personal data only", `{"screen": {"results_scanned": 42, "personal_data": 15,
			"by_detector": {"email": 15}, "findings": [{"kind": "personal", "id": "aaaaaaaa"}]}}`,
			screenSeen{present: true, results: 42, personal: 15},
			"Seen on screen: 15 personal data  ·  0 screenshots"},
		{"credentials only", `{"screen": {"results_scanned": 5, "credentials": 2}}`,
			screenSeen{present: true, results: 5, credentials: 2},
			"Seen on screen: 2 credential(s)  ·  0 personal data  ·  0 screenshots"},
		{"screenshots only", `{"screen": {"screenshots_total": 1842}}`,
			screenSeen{present: true, screenshots: 1842},
			"Seen on screen: 0 personal data  ·  1,842 screenshots"},
		{"wrong shape", `{"screen": "yes"}`, screenSeen{}, ""},
	}
	for _, c := range cases {
		r := parseReport([]byte(c.json), 7)
		if r.err != "" {
			t.Errorf("%s: err %q", c.name, r.err)
		}
		if r.screen != c.want {
			t.Errorf("%s: screen %+v, want %+v", c.name, r.screen, c.want)
		}
		if got := screenLabel(r.screen); got != c.label {
			t.Errorf("%s: label %q, want %q", c.name, got, c.label)
		}
	}
}

// Personal data never changes the icon state: exposed and monitoring stay
// about credentials.
func TestScreenPersonalDataLeavesIconAlone(t *testing.T) {
	r := parseReport([]byte(`{"secrets": [], "screen": {"results_scanned": 9, "personal_data": 40,
		"screenshots_total": 12}}`), 7)
	u := newUI()
	u.rep = r
	if s := u.state(); s != "idle" {
		t.Fatalf("state %q, want idle", s)
	}
}

func TestParseReportSecretSource(t *testing.T) {
	r := parseReport([]byte(`{"secrets": [
		{"id": "fp-cmd", "priority": "critical", "source": "command"},
		{"id": "fp-scr", "priority": "critical", "source": "screen"},
		{"id": "fp-both", "priority": "critical", "source": "both"},
		{"id": "fp-old", "priority": "critical"},
		{"id": "fp-high", "priority": "high", "source": "screen"}
	]}`), 7)
	if r.critical != 4 || r.rotatable != 5 {
		t.Fatalf("critical=%d rotatable=%d, want 4 and 5", r.critical, r.rotatable)
	}
	want := map[string]string{"fp-cmd": "command", "fp-scr": "screen", "fp-both": "both"}
	if len(r.sources) != len(want) {
		t.Fatalf("sources %v, want %v", r.sources, want)
	}
	for k, v := range want {
		if r.sources[k] != v {
			t.Errorf("sources[%s] = %q, want %q", k, r.sources[k], v)
		}
	}
}

func TestNewCredentialNotice(t *testing.T) {
	src := map[string]string{"c": "command", "s": "screen", "b": "both"}
	const plain = "actualis: new credential exposed"
	cases := []struct {
		name        string
		fresh       []string
		title, body string
	}{
		{"command", []string{"c"}, plain, "1 new critical credential(s) in your agent history"},
		{"no source (older CLI)", []string{"x"}, plain, "1 new critical credential(s) in your agent history"},
		{"screen", []string{"s"}, plain + " (seen on screen)", "1 new critical credential(s) in your agent history"},
		{"both", []string{"b"}, plain + " (seen on screen)", "1 new critical credential(s) in your agent history"},
		{"screen and both", []string{"s", "b"}, plain + " (seen on screen)", "2 new critical credential(s) in your agent history"},
		{"mixed", []string{"c", "s", "x"}, plain, "3 new critical credential(s) in your agent history, 1 seen on screen"},
	}
	for _, c := range cases {
		title, body := newCredentialNotice(c.fresh, src)
		if title != c.title || body != c.body {
			t.Errorf("%s: got %q / %q, want %q / %q", c.name, title, body, c.title, c.body)
		}
	}
}

// Fingerprints are long hex ids in practice; the label and notice carry none.
func TestScreenTextCarriesNoFingerprint(t *testing.T) {
	fp := "deadbeef"
	r := parseReport([]byte(`{"secrets": [{"id": "deadbeef", "priority": "critical", "source": "screen"}],
		"screen": {"results_scanned": 1, "credentials": 1, "findings": [{"id": "deadbeef", "kind": "credential"}]}}`), 7)
	title, body := newCredentialNotice([]string{fp}, r.sources)
	for _, s := range []string{screenLabel(r.screen), title, body} {
		if strings.Contains(s, fp) {
			t.Errorf("fingerprint in %q", s)
		}
	}
}
