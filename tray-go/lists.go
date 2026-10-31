package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Safe Browsing list age. The tray only reads gsb/state.json, a local file the
// companion writes; it never downloads anything itself. Lists that were never
// downloaded show nothing, because reputation checks are opt-in.
const (
	listsDueAfter   = 24 * time.Hour
	listsStaleAfter = 7 * 24 * time.Hour // matches the CLI's reputation-stale finding
)

// listsAge is the age of the oldest list in the cache. ok is false when there
// are no lists, or the state file is missing, oversized or unreadable: the CLI
// reports a corrupt cache itself, and the tray must not guess.
func listsAge(dir string, now time.Time) (age time.Duration, ok bool) {
	b, err := os.ReadFile(filepath.Join(dir, "gsb", "state.json"))
	if err != nil || len(b) > 1<<20 {
		return 0, false
	}
	var st struct {
		Lists []struct {
			FetchedAt string `json:"fetched_at"`
		} `json:"lists"`
	}
	if json.Unmarshal(b, &st) != nil || len(st.Lists) == 0 {
		return 0, false
	}
	var oldest time.Time
	for i, l := range st.Lists {
		at, err := time.Parse(time.RFC3339, l.FetchedAt)
		if err != nil || at.After(now.Add(time.Minute)) {
			return 0, false
		}
		if i == 0 || at.Before(oldest) {
			oldest = at
		}
	}
	return now.Sub(oldest), true
}

// listsLabel is the menu item for lists at least listsDueAfter old.
func listsLabel(age time.Duration) string {
	var when string
	if age < 48*time.Hour {
		when = fmt.Sprintf("%d hours old", int(age.Hours()))
	} else {
		when = fmt.Sprintf("%d days old", int(age.Hours()/24))
	}
	if age >= listsStaleAfter {
		when += ", stale"
	}
	return "Update Safe Browsing Lists (" + when + ")…"
}

// listsDue reports whether the lists exist and want refreshing now.
func listsDue() (time.Duration, bool) {
	age, ok := listsAge(reputationDir(), time.Now())
	return age, ok && age >= listsDueAfter
}

// openListsUpdate runs `actualis-reputation update` in a terminal. The user
// sees the network disclosure there and answers its consent prompt; the key
// comes from their shell (ACTUALIS_GSB_KEY or a key command). The tray holds
// no key and sends nothing.
func openListsUpdate() {
	bin := findTool("actualis-reputation")
	if bin == "" {
		return
	}
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(`tell application "Terminal"
activate
do script %s
end tell`, appleScriptString(shellQuote(bin)+" update"))
		_ = exec.Command("osascript", "-e", script).Run()
	case "windows":
		_ = exec.Command("cmd", "/c", "start", "cmd", "/k", `"`+bin+`" update`).Start()
	default:
		for _, term := range []string{"x-terminal-emulator", "gnome-terminal", "konsole", "xterm"} {
			if _, err := exec.LookPath(term); err == nil {
				_ = exec.Command(term, "-e", "sh", "-c", shellQuote(bin)+" update; exec sh").Start()
				return
			}
		}
	}
}

// listsTooltip appends the list age to the idle tooltip.
func listsTooltip(base string, age time.Duration) string {
	return base + " · Safe Browsing lists " + strings.TrimSuffix(
		strings.TrimPrefix(listsLabel(age), "Update Safe Browsing Lists ("), ")…")
}
