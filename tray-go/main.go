// actualis tray — macOS, Linux and Windows.
//
// Copyright (C) 2026 Digital Foundry Solutions, LLC
// Licensed under the GNU Affero General Public License v3 or later.
//
// A thin shell over the CLI: it runs `actualis --json --days N` on a ticker
// and renders the result. All measurement lives in the CLI, which stays the
// single auditable artifact with no dependencies. This binary has one
// dependency, for drawing a tray icon, and holds no logic worth auditing.
//
// The badge counts UNROTATED CRITICAL CREDENTIALS, not spend. A tray number
// earns its place by being actionable at a glance: "3" is a to-do you can
// clear, "$980" is trivia, and on a flat subscription it is not even a bill.
//
// Platform honesty: only macOS and some Linux desktops render text beside a
// tray icon. Windows does not. So the count is always in the tooltip and the
// first menu item, and SetTitle is a bonus where it works rather than the
// mechanism it relies on.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
)

// ACTUALIS icon system 1.0.0.
//
// macOS gets TEMPLATE icons: alpha only, inked by the OS for whatever the menu
// bar is actually doing. This replaced an AppleInterfaceStyle probe that was
// simply wrong — it reported Dark on a machine whose menu bar was visibly
// light, which is exactly how you ship an invisible icon. The OS knows; asking
// it a proxy question does not work.
//
// Everywhere else there is no template concept, so the fallback is drawn in
// amber throughout: a mid-tone that reads on a light taskbar and a dark one
// alike, so no appearance guess is needed there either.
//
// State is carried by FORM — a ring, a dot, a spinner, a crosshair — never by
// colour alone, per the brand accessibility rule. That is also what lets the
// monochrome template convey every state.

//go:embed icons/idle-template.png
var tplIdle []byte

//go:embed icons/idle.png
var regIdle []byte

//go:embed icons/monitoring-template.png
var tplMon []byte

//go:embed icons/monitoring.png
var regMon []byte

//go:embed icons/exposed-template.png
var tplExp []byte

//go:embed icons/exposed.png
var regExp []byte

//go:embed icons/syncing-template.png
var tplSync []byte

//go:embed icons/syncing.png
var regSync []byte

//go:embed icons/error-template.png
var tplErr []byte

//go:embed icons/error.png
var regErr []byte

// setIcon installs the state's mark. SetTemplateIcon uses the template on
// macOS and falls back to the regular icon elsewhere, which is precisely the
// behaviour wanted on all three platforms.
func setIcon(state string) {
	var tpl, reg []byte
	switch state {
	case "exposed":
		tpl, reg = tplExp, regExp
	case "monitoring":
		tpl, reg = tplMon, regMon
	case "syncing":
		tpl, reg = tplSync, regSync
	case "error":
		tpl, reg = tplErr, regErr
	default:
		tpl, reg = tplIdle, regIdle
	}
	systray.SetTemplateIcon(tpl, reg)
}

// ---------------------------------------------------------------- report

type report struct {
	fingerprints map[string]bool
	critical     int
	rotatable    int
	cost         float64
	shell        int
	flaggedHigh  int
	unsupPct     float64
	hasUnsup     bool
	invisPct     float64
	findings     []finding
	err          string
	at           time.Time
}

type finding struct{ ID, Title, Severity string }

// findBinary resolves the CLI without a login shell's PATH, which a
// desktop-launched process does not inherit.
func findBinary() string {
	if p, err := exec.LookPath("actualis"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".local", "bin", "actualis"),
		"/opt/homebrew/bin/actualis",
		"/usr/local/bin/actualis",
		filepath.Join(home, "AppData", "Local", "Programs", "actualis", "actualis.exe"),
	}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, "actualis.exe")
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

func fetch(days int) report {
	r := report{at: time.Now()}
	bin := findBinary()
	if bin == "" {
		r.err = "actualis not found on PATH"
		return r
	}
	out, err := exec.Command(bin, "--json", "--days", strconv.Itoa(days)).Output()
	if err != nil {
		r.err = "could not run actualis: " + err.Error()
		return r
	}
	var root map[string]any
	if err := json.Unmarshal(out, &root); err != nil {
		r.err = "actualis returned no usable JSON"
		return r
	}

	if v, ok := root["cost_usd"].(float64); ok {
		r.cost = v
	}
	r.fingerprints = map[string]bool{}
	if secrets, ok := root["secrets"].([]any); ok {
		for _, s := range secrets {
			m, _ := s.(map[string]any)
			switch m["priority"] {
			case "critical":
				r.critical++
				r.rotatable++
				if fp, ok := m["id"].(string); ok {
					r.fingerprints[fp] = true
				}
			case "high":
				r.rotatable++
			}
		}
	}
	if bash, ok := root["bash"].(map[string]any); ok {
		if v, ok := bash["total"].(float64); ok {
			r.shell = int(v)
		}
		if fc, ok := bash["flag_counts"].(map[string]any); ok {
			for k, v := range fc {
				if strings.HasPrefix(k, "high:") {
					if n, ok := v.(float64); ok {
						r.flaggedHigh += int(n)
					}
				}
			}
		}
	}
	if modes, ok := root["permission_modes"].(map[string]any); ok && len(modes) > 0 {
		var total, auto float64
		for k, v := range modes {
			n, _ := v.(float64)
			total += n
			lk := strings.ToLower(k)
			if strings.Contains(lk, "auto") || strings.Contains(lk, "bypass") {
				auto += n
			}
		}
		if total > 0 {
			r.unsupPct, r.hasUnsup = auto/total*100, true
		}
	}
	if subs, ok := root["subagents"].(map[string]any); ok {
		if tools, ok := subs["tools"].(map[string]any); ok {
			hidden, _ := tools["bashCount"].(float64)
			if all := hidden + float64(r.shell); all > 0 {
				r.invisPct = hidden / all * 100
			}
		}
	}
	if coach, ok := root["coach"].([]any); ok {
		for _, c := range coach {
			m, _ := c.(map[string]any)
			id, _ := m["id"].(string)
			t, _ := m["title"].(string)
			sev, _ := m["severity"].(string)
			if id != "" {
				r.findings = append(r.findings, finding{id, t, sev})
			}
		}
	}
	return r
}

func shareText() string {
	bin := findBinary()
	if bin == "" {
		return "actualis not found"
	}
	cmd := exec.Command(bin, "--share")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, err := cmd.Output()
	if err != nil {
		return "could not run actualis"
	}
	return string(out)
}

// ---------------------------------------------------------------- ui

type ui struct {
	mu      sync.Mutex
	rep     report
	days    int
	loading bool
	seen    map[string]bool // critical fingerprints already announced
	primed  bool            // first scan must not fire a flood of alerts

	mHeader, mSub, mCost, mShell, mUnsup, mInvis *systray.MenuItem
	mFindings                                    []*systray.MenuItem
	mReport, mCopy, mRefresh, mQuit              *systray.MenuItem
	mDays                                        map[int]*systray.MenuItem
}

func main() { systray.Run(newUI().onReady, func() {}) }

func newUI() *ui {
	return &ui{days: 7, mDays: map[int]*systray.MenuItem{}, seen: map[string]bool{}}
}

// notify raises a native desktop notification. Best effort: a missing notifier
// must never take the tray down.
func notify(title, body string) {
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf("display notification %q with title %q sound name \"Ping\"",
			body, title)
		_ = exec.Command("osascript", "-e", script).Run()
	case "linux":
		_ = exec.Command("notify-send", "-u", "critical", title, body).Run()
	case "windows":
		_ = exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("[void][Windows.UI.Notifications.ToastNotificationManager];"+
				"Write-Output %q", title+": "+body)).Run()
	}
}

// flash draws attention when something new appears. Three beats is noticeable
// without becoming an animation nobody can turn off.
func (u *ui) flash(state string) {
	go func() {
		for i := 0; i < 3; i++ {
			setIcon("exposed")
			time.Sleep(320 * time.Millisecond)
			setIcon("syncing")
			time.Sleep(220 * time.Millisecond)
		}
		setIcon(state)
	}()
}

func (u *ui) onReady() {
	setIcon("idle")
	systray.SetTooltip("Actualis — what actually ran")

	u.mHeader = systray.AddMenuItem("Loading…", "")
	u.mHeader.Disable()
	u.mSub = systray.AddMenuItem("", "")
	u.mSub.Disable()
	systray.AddSeparator()

	u.mCost = addDisabled("")
	u.mShell = addDisabled("")
	u.mUnsup = addDisabled("")
	u.mInvis = addDisabled("")
	systray.AddSeparator()

	for i := 0; i < 4; i++ {
		u.mFindings = append(u.mFindings, addDisabled(""))
	}
	systray.AddSeparator()

	u.mReport = systray.AddMenuItem("Open Full Report", "Run the CLI in a terminal")
	u.mCopy = systray.AddMenuItem("Copy Shareable Summary", "Safe to post: nothing identifying")
	u.mRefresh = systray.AddMenuItem("Refresh Now", "")

	window := systray.AddMenuItem("Window", "How far back to look")
	for _, d := range []int{1, 7, 30, 90} {
		u.mDays[d] = window.AddSubMenuItemCheckbox(fmt.Sprintf("Last %d days", d), "", d == u.days)
	}
	systray.AddSeparator()
	u.mQuit = systray.AddMenuItem("Quit Actualis", "")

	go u.loop()
	go u.refresh()
}

func addDisabled(s string) *systray.MenuItem {
	m := systray.AddMenuItem(s, "")
	m.Disable()
	if s == "" {
		m.Hide()
	}
	return m
}

func (u *ui) loop() {
	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			u.refresh()
		case <-u.mRefresh.ClickedCh:
			u.refresh()
		case <-u.mCopy.ClickedCh:
			go copyToClipboard(shareText())
		case <-u.mReport.ClickedCh:
			go openReport()
		case <-u.mQuit.ClickedCh:
			systray.Quit()
			return
		case <-u.mDays[1].ClickedCh:
			u.setDays(1)
		case <-u.mDays[7].ClickedCh:
			u.setDays(7)
		case <-u.mDays[30].ClickedCh:
			u.setDays(30)
		case <-u.mDays[90].ClickedCh:
			u.setDays(90)
		}
	}
}

func (u *ui) setDays(d int) {
	u.mu.Lock()
	u.days = d
	for k, m := range u.mDays {
		if k == d {
			m.Check()
		} else {
			m.Uncheck()
		}
	}
	u.mu.Unlock()
	u.refresh()
}

func (u *ui) refresh() {
	u.mu.Lock()
	if u.loading {
		u.mu.Unlock()
		return
	}
	u.loading = true
	days := u.days
	u.mu.Unlock()

	r := fetch(days)

	u.mu.Lock()
	u.rep, u.loading = r, false
	fresh := []string{}
	for fp := range r.fingerprints {
		if !u.seen[fp] {
			u.seen[fp] = true
			if u.primed {
				fresh = append(fresh, fp)
			}
		}
	}
	// The first scan establishes a baseline. Announcing a month of history on
	// launch would train the user to ignore the notification permanently.
	u.primed = true
	u.mu.Unlock()

	u.render()
	if len(fresh) > 0 {
		notify("actualis: new credential exposed",
			fmt.Sprintf("%d new critical credential(s) in your agent history", len(fresh)))
		u.flash(u.state())
	}
}

func (u *ui) render() {
	u.mu.Lock()
	r, days := u.rep, u.days
	u.mu.Unlock()

	if r.err != "" {
		setIcon("error")
		systray.SetTooltip("actualis: " + r.err)
		u.mHeader.SetTitle(r.err)
		return
	}

	if r.critical > 0 {
		setIcon("exposed")
		// Only macOS and some Linux desktops show this; Windows ignores it.
		systray.SetTitle(strconv.Itoa(r.critical))
		systray.SetTooltip(fmt.Sprintf("Actualis — %d critical credential(s) exposed", r.critical))
		u.mHeader.SetTitle(fmt.Sprintf("%d critical credential(s) exposed", r.critical))
		show(u.mSub, fmt.Sprintf("%d worth rotating in total", r.rotatable))
	} else if r.rotatable > 0 {
		setIcon("monitoring")
		systray.SetTitle("")
		systray.SetTooltip(fmt.Sprintf("Actualis — %d credential(s) worth rotating", r.rotatable))
		u.mHeader.SetTitle(fmt.Sprintf("%d credential(s) worth rotating", r.rotatable))
		u.mSub.Hide()
	} else {
		setIcon("idle")
		systray.SetTitle("")
		systray.SetTooltip("Actualis — no critical credentials exposed")
		u.mHeader.SetTitle("No critical credentials exposed")
		u.mSub.Hide()
	}

	show(u.mCost, fmt.Sprintf("$%.2f  ·  last %d days, at list price", r.cost, days))
	show(u.mShell, fmt.Sprintf("%s shell commands  ·  %d flagged",
		comma(r.shell), r.flaggedHigh))
	if r.hasUnsup {
		show(u.mUnsup, fmt.Sprintf("%.0f%% ran unsupervised", r.unsupPct))
	} else {
		u.mUnsup.Hide()
	}
	if r.invisPct > 0 {
		show(u.mInvis, fmt.Sprintf("%.0f%% of shell activity is unauditable", r.invisPct))
	} else {
		u.mInvis.Hide()
	}

	sort.SliceStable(r.findings, func(i, j int) bool {
		rank := map[string]int{"critical": 0, "high": 1, "info": 2}
		return rank[r.findings[i].Severity] < rank[r.findings[j].Severity]
	})
	for i, m := range u.mFindings {
		if i < len(r.findings) {
			show(m, r.findings[i].ID+"  "+r.findings[i].Title)
		} else {
			m.Hide()
		}
	}
}

func (u *ui) state() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.rep.critical > 0 {
		return "exposed"
	}
	if u.rep.rotatable > 0 {
		return "monitoring"
	}
	return "idle"
}

func show(m *systray.MenuItem, s string) { m.SetTitle(s); m.Show() }

func comma(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// ---------------------------------------------------------------- platform

func copyToClipboard(text string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "windows":
		cmd = exec.Command("clip")
	default:
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd = exec.Command("wl-copy")
		} else {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		}
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	_, _ = in.Write([]byte(text))
	_ = in.Close()
	_ = cmd.Wait()
}

// openReport hands the user to the CLI. The tray is a glance; the CLI is the tool.
func openReport() {
	bin := findBinary()
	if bin == "" {
		return
	}
	switch runtime.GOOS {
	case "darwin":
		script := fmt.Sprintf(`tell application "Terminal"
activate
do script "%s --coach; echo; %s | less -R"
end tell`, bin, bin)
		_ = exec.Command("osascript", "-e", script).Run()
	case "windows":
		_ = exec.Command("cmd", "/c", "start", "cmd", "/k",
			bin+" --coach && "+bin).Start()
	default:
		for _, term := range []string{"x-terminal-emulator", "gnome-terminal", "konsole", "xterm"} {
			if _, err := exec.LookPath(term); err == nil {
				_ = exec.Command(term, "-e", "sh", "-c",
					bin+" --coach; echo; "+bin+" | less -R; exec sh").Start()
				return
			}
		}
	}
}
