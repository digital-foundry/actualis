package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// #97: the Resolve submenu. Synthetic data only.

const resolveJSON = `{
  "secrets": [
    {"id": "aaaa0001", "priority": "critical", "types": ["stripe-live-key"], "suppressed": false,
     "source": "screen", "disposition": null},
    {"id": "aaaa0002", "priority": "high", "types": ["API_TOKEN"], "suppressed": false,
     "source": "command", "disposition": null},
    {"id": "aaaa0003", "priority": "critical", "types": ["github-pat"], "suppressed": true,
     "source": "command", "disposition": "rotated"},
    {"id": "aaaa0004", "priority": "low", "types": ["dev"], "suppressed": false,
     "source": "command", "disposition": null},
    {"id": "NOT-HEX!", "priority": "critical", "types": ["x"], "suppressed": false,
     "disposition": null}
  ],
  "screen": {"findings": [
    {"kind": "personal", "detector": "email", "id": "bbbb0001", "disposition": null},
    {"kind": "personal", "detector": "email", "id": "bbbb0001", "disposition": null},
    {"kind": "personal", "detector": "phone", "id": "bbbb0002", "disposition": "expected"},
    {"kind": "credential", "detector": "stripe-live-key", "id": "aaaa0001", "disposition": null}
  ]}
}`

func TestResolvablesFromJSON(t *testing.T) {
	r := parseReport([]byte(resolveJSON), 7)
	if !r.canResolve {
		t.Fatal("canResolve false for a CLI that emits disposition")
	}
	got := []string{}
	for _, x := range r.resolvables {
		got = append(got, x.ID)
	}
	want := "aaaa0001 aaaa0002 bbbb0001"
	if strings.Join(got, " ") != want {
		t.Fatalf("resolvables %v, want %s", got, want)
	}
	if !r.resolvables[0].Screen || r.resolvables[1].Screen || !r.resolvables[2].Personal {
		t.Errorf("flags wrong: %+v", r.resolvables)
	}
}

func TestOlderCLIOffersNothing(t *testing.T) {
	r := parseReport([]byte(`{"secrets": [{"id": "aaaa0001", "priority": "critical",
		"types": ["x"], "suppressed": false}]}`), 7)
	if r.canResolve || len(r.resolvables) != 0 {
		t.Fatalf("an older CLI must not get a Resolve menu: %+v", r)
	}
}

func TestDispositionsOffered(t *testing.T) {
	cred := dispositionsFor(resolvable{ID: "aaaa0001", Priority: "critical"})
	if len(cred) != 3 || cred[0].Value != "rotated" || cred[2].Value != "false-positive" {
		t.Errorf("credential choices %v", cred)
	}
	pd := dispositionsFor(resolvable{ID: "bbbb0001", Personal: true})
	if len(pd) != 2 || pd[0].Value != "expected" {
		t.Errorf("personal data has no Rotated: %v", pd)
	}
}

func TestResolvableLabel(t *testing.T) {
	cases := map[string]resolvable{
		"aaaa0001  ·  stripe-live-key (critical, screen)": {ID: "aaaa0001", What: "stripe-live-key", Priority: "critical", Screen: true},
		"aaaa0002  ·  API_TOKEN (high)":                   {ID: "aaaa0002", What: "API_TOKEN", Priority: "high"},
		"bbbb0001  ·  email seen on screen":               {ID: "bbbb0001", What: "email", Personal: true},
	}
	for want, r := range cases {
		if got := resolvableLabel(r); got != want {
			t.Errorf("label %q, want %q", got, want)
		}
	}
}

func TestCleanReason(t *testing.T) {
	if s, ok := cleanReason("  replaced in the vault\n"); !ok || s != "replaced in the vault" {
		t.Errorf("trim: %q %v", s, ok)
	}
	for _, bad := range []string{"", "   \n", "ok\n620e24b6 x", "bell\a"} {
		if _, ok := cleanReason(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if s, _ := cleanReason(strings.Repeat("é", 300)); len([]rune(s)) != 200 {
		t.Errorf("not capped at 200 runes: %d", len([]rune(s)))
	}
}

// The reason is one argv entry: shell syntax in it is text, not code.
func TestResolveArgsKeepTheReasonWhole(t *testing.T) {
	reason := `$(touch /tmp/pwned); "quoted" 'single' ` + "`tick`"
	args := resolveArgs("aaaa0001", "rotated", reason)
	want := []string{"--resolve", "aaaa0001", "--as", "rotated", "--reason", reason}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args %q", args)
	}
}

func TestReasonDialogPerPlatform(t *testing.T) {
	none := func(string) (string, error) { return "", errors.New("absent") }
	only := func(name string) func(string) (string, error) {
		return func(n string) (string, error) {
			if n == name {
				return "/usr/bin/" + n, nil
			}
			return "", errors.New("absent")
		}
	}
	prompt := reasonPrompt(resolvable{ID: "aaaa0001"}, dispRotated)

	mac := reasonDialogCmd("darwin", prompt, none)
	if mac == nil || filepath.Base(mac.Path) != "osascript" || !strings.Contains(mac.Args[2], "display dialog") {
		t.Fatalf("darwin: %v", mac)
	}
	if !strings.Contains(mac.Args[2], `cancel button "Cancel"`) {
		t.Error("darwin dialog has no cancel button")
	}

	win := reasonDialogCmd("windows", prompt, none)
	if win == nil || win.Args[len(win.Args)-1] != windowsReasonScript {
		t.Fatalf("windows: script must be the constant, got %v", win)
	}
	envOK := false
	for _, e := range win.Env {
		if e == "ACTUALIS_TRAY_PROMPT="+prompt {
			envOK = true
		}
	}
	if !envOK {
		t.Error("windows: prompt not passed through the environment")
	}

	if z := reasonDialogCmd("linux", prompt, only("zenity")); z == nil || z.Args[1] != "--entry" {
		t.Errorf("linux zenity: %v", z)
	}
	if k := reasonDialogCmd("linux", prompt, only("kdialog")); k == nil || k.Args[3] != "--inputbox" {
		t.Errorf("linux kdialog: %v", k)
	}
	if reasonDialogCmd("linux", prompt, none) != nil {
		t.Error("linux without a dialog tool must hide Resolve")
	}
}

// The CLI is the only writer: runResolve hands it the arguments unchanged,
// and refuses an id that is not one.
func TestRunResolveCallsTheCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script as the fake CLI")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "args")
	bin := filepath.Join(dir, "actualis")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + shellQuote(out) + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	reason := `own address; $(echo no)`
	if err := runResolve(bin, "bbbb0001", "expected", reason); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	want := "--resolve\nbbbb0001\n--as\nexpected\n--reason\n" + reason + "\n"
	if string(got) != want {
		t.Fatalf("CLI got %q, want %q", got, want)
	}
	if err := runResolve(bin, "../../etc", "expected", "x"); err == nil {
		t.Error("a non-id was passed to the CLI")
	}

	fail := filepath.Join(dir, "failing")
	_ = os.WriteFile(fail, []byte("#!/bin/sh\necho 'usage: actualis' >&2\necho 'actualis: error: --until has already passed.' >&2\nexit 2\n"), 0o755)
	err := runResolve(fail, "bbbb0001", "expected", "x")
	if err == nil || err.Error() != "actualis: error: --until has already passed." {
		t.Errorf("error %v", err)
	}
}
