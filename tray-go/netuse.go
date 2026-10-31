package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"fyne.io/systray"
)

// reputationDir is where actualis-reputation keeps its cache; the same
// resolution as actualis.py's reputation_dir().
func reputationDir() string {
	if d := os.Getenv("ACTUALIS_REPUTATION_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" && os.Getenv("LOCALAPPDATA") != "" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "actualis", "reputation")
	}
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "actualis", "reputation")
}

// netInFlight reports whether actualis-reputation is using the network now:
// its in-flight marker exists, is under an hour old, and names a live process.
func netInFlight(dir string, now time.Time) bool {
	b, err := os.ReadFile(filepath.Join(dir, "in-flight.json"))
	if err != nil || len(b) > 4096 {
		return false
	}
	var m struct {
		PID       int    `json:"pid"`
		StartedAt string `json:"started_at"`
	}
	if json.Unmarshal(b, &m) != nil || m.PID <= 0 {
		return false
	}
	at, err := time.Parse(time.RFC3339, m.StartedAt)
	if err != nil || now.Sub(at) > time.Hour || at.After(now.Add(time.Minute)) {
		return false
	}
	return processAlive(m.PID)
}

const netTooltip = "actualis-reputation is using the network"

// netUse holds the badge: while active, setIcon shows "network" and
// remembers the state underneath, which comes back when the run ends.
// tip is the tooltip underneath, so a report refresh during a run does not
// replace the network tooltip and the end of the run restores the latest one.
var netUse struct {
	sync.Mutex
	active bool
	under  string
	tip    string
}

// setTooltip is systray.SetTooltip that yields to the network badge: during a
// run it only remembers the text for later.
func setTooltip(text string) {
	netUse.Lock()
	netUse.tip = text
	active := netUse.active
	netUse.Unlock()
	if !active {
		systray.SetTooltip(text)
	}
}

// watchNetworkUse polls the in-flight marker. ended runs when a companion run
// finishes, so the tray re-reads what it changed (a list update clears the
// "update" badge straight away rather than at the next ten-minute scan).
func watchNetworkUse(ended func()) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		on := netInFlight(reputationDir(), time.Now())
		netUse.Lock()
		changed := on != netUse.active
		if changed && on {
			iconState.Lock()
			netUse.under = iconState.name
			iconState.Unlock()
		}
		netUse.active = on
		under, tip := netUse.under, netUse.tip
		netUse.Unlock()
		if !changed {
			continue
		}
		if on {
			setIcon("network")
			systray.SetTooltip(netTooltip)
		} else {
			setIcon(under)
			systray.SetTooltip(tip)
			if ended != nil {
				ended()
			}
		}
	}
}
