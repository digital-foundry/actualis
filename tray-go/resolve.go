package main

// Resolve… (#97): record what a finding turned out to be, from the menu.
//
// The tray never writes the suppressions file. It asks for a reason in a
// native dialog and runs `actualis --resolve ID --as DISPOSITION --reason
// TEXT`, with every argument passed as its own argv entry: no shell sees the
// reason, so nothing typed into the dialog can run. The CLI validates the id,
// refuses control characters and the audit-config id, and is the only writer.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"fyne.io/systray"
)

// resolvable is one actionable finding the menu offers to resolve. Never a
// value: an id (sha256[:8] of the value), what kind it is, and its priority.
type resolvable struct {
	ID       string
	Personal bool   // personal data seen on screen, not a credential
	What     string // credential types, or the personal-data detector
	Priority string // critical or high for a credential, "" for personal data
	Screen   bool   // a credential seen on screen (or on screen and in a command)
}

// disposition is one choice in a finding's Resolve submenu.
type disposition struct{ Value, Label string }

var (
	dispRotated  = disposition{"rotated", "Rotated…"}
	dispExpected = disposition{"expected", "Expected…"}
	dispFalse    = disposition{"false-positive", "False positive…"}
	// allDispositions is the submenu, in order. Personal data has no Rotated.
	allDispositions = []disposition{dispRotated, dispExpected, dispFalse}
)

// fingerprint is the only id shape the CLI emits or accepts.
var fingerprint = regexp.MustCompile(`^[0-9a-f]{8}$`)

// maxResolvable is how many findings the Resolve submenu lists; the rest are
// counted on one line that opens the full report.
const maxResolvable = 8

// resolveTimeout bounds one `actualis --resolve`, which only appends a line.
const resolveTimeout = 30 * time.Second

func dispositionsFor(r resolvable) []disposition {
	if r.Personal {
		return []disposition{dispExpected, dispFalse}
	}
	return allDispositions
}

// resolvablesFrom lists the findings worth resolving from `actualis --json`:
// critical and high credentials not already resolved, then personal data seen
// on screen with no disposition. ok is false for a CLI that predates
// --resolve (no `disposition` key anywhere), and the tray then offers nothing.
func resolvablesFrom(root map[string]any) (out []resolvable, ok bool) {
	seen := map[string]bool{}
	if secrets, _ := root["secrets"].([]any); secrets != nil {
		for _, s := range secrets {
			m, _ := s.(map[string]any)
			if m == nil {
				continue
			}
			if _, has := m["disposition"]; has {
				ok = true
			}
			id, _ := m["id"].(string)
			pri, _ := m["priority"].(string)
			if sup, _ := m["suppressed"].(bool); sup || !fingerprint.MatchString(id) || seen[id] {
				continue
			}
			if pri != "critical" && pri != "high" {
				continue
			}
			types := []string{}
			if ts, _ := m["types"].([]any); ts != nil {
				for _, t := range ts {
					if s, _ := t.(string); s != "" {
						types = append(types, s)
					}
				}
			}
			src, _ := m["source"].(string)
			seen[id] = true
			out = append(out, resolvable{ID: id, What: strings.Join(types, ", "), Priority: pri,
				Screen: src == "screen" || src == "both"})
		}
	}
	if sc, _ := root["screen"].(map[string]any); sc != nil {
		rows, _ := sc["findings"].([]any)
		for _, row := range rows {
			m, _ := row.(map[string]any)
			if m == nil {
				continue
			}
			d, has := m["disposition"]
			if has {
				ok = true
			}
			kind, _ := m["kind"].(string)
			id, _ := m["id"].(string)
			if kind != "personal" || d != nil || !fingerprint.MatchString(id) || seen[id] {
				continue
			}
			det, _ := m["detector"].(string)
			seen[id] = true
			out = append(out, resolvable{ID: id, Personal: true, What: det})
		}
	}
	rank := func(r resolvable) int {
		switch {
		case r.Personal:
			return 2
		case r.Priority == "critical":
			return 0
		}
		return 1
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	if !ok {
		return nil, false
	}
	return out, true
}

// resolvableLabel is the finding's line in the Resolve submenu.
func resolvableLabel(r resolvable) string {
	what := r.What
	if len(what) > 32 {
		what = what[:31] + "…"
	}
	switch {
	case r.Personal:
		return fmt.Sprintf("%s  ·  %s seen on screen", r.ID, what)
	case r.Screen:
		return fmt.Sprintf("%s  ·  %s (%s, screen)", r.ID, what, r.Priority)
	}
	return fmt.Sprintf("%s  ·  %s (%s)", r.ID, what, r.Priority)
}

// reasonPrompt is the dialog text. Built only from the validated id and fixed
// words, never from anything a transcript supplied.
func reasonPrompt(r resolvable, d disposition) string {
	what := map[string]string{
		"rotated":        "rotated",
		"expected":       "expected",
		"false-positive": "a false positive",
	}[d.Value]
	return fmt.Sprintf("Resolve %s as %s.\n\nWhy? Recorded beside the id in your "+
		"suppressions file, so it can be reviewed later.", r.ID, what)
}

// resolveArgs is the CLI invocation. The reason is one argv entry, whatever
// it holds.
func resolveArgs(id, disp, reason string) []string {
	return []string{"--resolve", id, "--as", disp, "--reason", reason}
}

// cleanReason trims what a dialog returns. A reason with a control
// character (the CLI refuses those) or nothing in it is not a reason.
func cleanReason(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == ' ' || r == ' ' {
			return "", false
		}
	}
	if len([]rune(s)) > 200 {
		s = string([]rune(s)[:200])
	}
	return s, true
}

// windowsReasonScript asks for the reason through the VisualBasic InputBox,
// on every Windows install. A constant, like windowsToastScript: the prompt
// arrives through the environment, so no text is ever parsed as PowerShell.
const windowsReasonScript = `$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName Microsoft.VisualBasic
[Console]::OutputEncoding = [Text.Encoding]::UTF8
[Microsoft.VisualBasic.Interaction]::InputBox($Env:ACTUALIS_TRAY_PROMPT, 'Actualis', '')`

// reasonDialogCmd builds the native dialog for goos, nil where there is none
// (a Linux desktop without zenity or kdialog). lookPath is exec.LookPath,
// injected for tests.
func reasonDialogCmd(goos, prompt string, lookPath func(string) (string, error)) *exec.Cmd {
	switch goos {
	case "darwin":
		// AppleScript performs no substitution inside a literal, and the
		// prompt holds only the id and fixed words. Cancel exits non-zero.
		script := "text returned of (display dialog " + appleScriptString(prompt) +
			` default answer "" with title "Actualis" buttons {"Cancel", "Resolve"}` +
			` default button "Resolve" cancel button "Cancel" with icon note)`
		return exec.Command("osascript", "-e", script)
	case "windows":
		cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", windowsReasonScript)
		cmd.Env = append(os.Environ(), "ACTUALIS_TRAY_PROMPT="+prompt)
		return cmd
	default:
		if p, err := lookPath("zenity"); err == nil {
			return exec.Command(p, "--entry", "--title=Actualis", "--text="+prompt)
		}
		if p, err := lookPath("kdialog"); err == nil {
			return exec.Command(p, "--title", "Actualis", "--inputbox", prompt)
		}
	}
	return nil
}

// canAskReason says whether this desktop has a dialog to ask with. Where it
// has none the Resolve submenu is hidden: a resolution without a reason is
// not one the tray records.
func canAskReason() bool {
	return reasonDialogCmd(runtime.GOOS, "", exec.LookPath) != nil
}

// askReason shows the dialog. ok is false when it was cancelled, could not
// be shown, or returned no usable reason.
func askReason(prompt string) (string, bool) {
	cmd := reasonDialogCmd(runtime.GOOS, prompt, exec.LookPath)
	if cmd == nil {
		return "", false
	}
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return cleanReason(string(out))
}

// runResolve runs the CLI, the only writer. It returns the CLI's last line
// of error output on failure: argparse's message, never a value.
func runResolve(bin, id, disp, reason string) error {
	if !fingerprint.MatchString(id) {
		return fmt.Errorf("not an id from actualis: %q", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, resolveArgs(id, disp, reason)...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
		msg := strings.TrimSpace(lines[len(lines)-1])
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// resolveFinding is a click on Rotated…, Expected… or False positive…: ask,
// run the CLI, say what happened, rescan.
func (u *ui) resolveFinding(r resolvable, d disposition) {
	bin := findBinary()
	if bin == "" {
		notify("actualis: not resolved", "actualis not found on PATH")
		return
	}
	reason, ok := askReason(reasonPrompt(r, d))
	if !ok {
		return // cancelled, or nothing typed: nothing is written
	}
	if err := runResolve(bin, r.ID, d.Value, reason); err != nil {
		notify("actualis: not resolved", err.Error())
		return
	}
	notify("actualis: resolved", fmt.Sprintf("%s recorded as %s. It stays counted.",
		r.ID, strings.TrimSuffix(strings.ToLower(d.Label), "…")))
	u.refresh()
}

// resolveRow is one finding's slot in the Resolve submenu, with one item per
// disposition in allDispositions order.
type resolveRow struct {
	item    *systray.MenuItem
	choices []*systray.MenuItem
}

// addResolveMenu adds "Resolve…" with a fixed pool of rows, shown and bound
// to findings at each render (systray menus are built once).
func (u *ui) addResolveMenu() {
	u.canAsk = canAskReason()
	u.mResolve = systray.AddMenuItem("Resolve…",
		"Record what a finding turned out to be. Runs actualis --resolve; it stays counted")
	for i := 0; i < maxResolvable; i++ {
		row := resolveRow{item: u.mResolve.AddSubMenuItem("", "")}
		for _, d := range allDispositions {
			row.choices = append(row.choices, row.item.AddSubMenuItem(d.Label, "Asks why, then records it"))
		}
		row.item.Hide()
		u.mResolveRows = append(u.mResolveRows, row)
		for j := range allDispositions {
			go u.watchResolveChoice(i, j)
		}
	}
	u.mResolveMore = u.mResolve.AddSubMenuItem("", "")
	u.mResolveMore.Disable()
	u.mResolveMore.Hide()
	u.mResolve.Hide()
}

// watchResolveChoice handles clicks on row i's disposition j, resolving
// whatever finding the row is bound to at the moment of the click.
func (u *ui) watchResolveChoice(i, j int) {
	ch := u.mResolveRows[i].choices[j].ClickedCh
	for {
		select {
		case <-ch:
			u.mu.Lock()
			bound := i < len(u.resolveBound) && !u.resolving
			var r resolvable
			if bound {
				r = u.resolveBound[i]
				u.resolving = true
			}
			u.mu.Unlock()
			if bound {
				go func() {
					u.resolveFinding(r, allDispositions[j])
					u.mu.Lock()
					u.resolving = false
					u.mu.Unlock()
				}()
			}
		case <-u.stop:
			return
		}
	}
}

// renderResolve shows the Resolve submenu for the report's actionable
// findings; hidden for an older CLI, a desktop with no dialog, or nothing to
// resolve.
func (u *ui) renderResolve(r report) {
	list := r.resolvables
	if !r.canResolve || !u.canAsk || len(list) == 0 {
		u.mResolve.Hide()
		u.mu.Lock()
		u.resolveBound = nil
		u.mu.Unlock()
		return
	}
	shown := list
	if len(shown) > maxResolvable {
		shown = shown[:maxResolvable]
	}
	u.mu.Lock()
	u.resolveBound = append([]resolvable(nil), shown...)
	u.mu.Unlock()
	for i, row := range u.mResolveRows {
		if i >= len(shown) {
			row.item.Hide()
			continue
		}
		show(row.item, resolvableLabel(shown[i]))
		offered := map[string]bool{}
		for _, d := range dispositionsFor(shown[i]) {
			offered[d.Value] = true
		}
		for j, d := range allDispositions {
			if offered[d.Value] {
				row.choices[j].Show()
			} else {
				row.choices[j].Hide()
			}
		}
	}
	if more := len(list) - len(shown); more > 0 {
		show(u.mResolveMore, fmt.Sprintf("%d more: actualis --resolve ID --as …", more))
	} else {
		u.mResolveMore.Hide()
	}
	show(u.mResolve, "Resolve…")
}
