package main

import "testing"

// Regression: the CLI path was interpolated into shell command strings
// unquoted, so a home directory containing a space broke "Open full report"
// outright, and the Windows notification used %q — which escapes quotes and
// backslashes but leaves $ and backtick for PowerShell to evaluate.
func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"/usr/local/bin/actualis":        `'/usr/local/bin/actualis'`,
		"/Users/first last/bin/actualis": `'/Users/first last/bin/actualis'`,
		"/tmp/$(id)/actualis":            `'/tmp/$(id)/actualis'`,
		"/tmp/`id`/actualis":             "'/tmp/`id`/actualis'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
	if got := shellQuote("/tmp/it's/actualis"); got != `'/tmp/it'\''s/actualis'` {
		t.Errorf("embedded quote not escaped: %q", got)
	}
}

func TestAppleScriptString(t *testing.T) {
	if got := appleScriptString(`say "hi"`); got != `"say \"hi\""` {
		t.Errorf("quote not escaped: %q", got)
	}
	if got := appleScriptString(`a\b`); got != `"a\\b"` {
		t.Errorf("backslash not escaped: %q", got)
	}
}
