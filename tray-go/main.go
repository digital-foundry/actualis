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
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
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
// Geometry comes from the ACTUALIS macOS icon sheet, measured rather than eyeballed;
// icons/gen_icons.py records every ratio and where on the sheet it was taken
// from. The sheet says "do not alter proportions or stroke weights", so the
// generator is the spec and the PNGs are build output.
//
// These are NOT template icons. A macOS template image is alpha-only — the OS
// inks it as a flat monochrome mask — which strips the amber the sheet puts on
// every state, in both its light-mode and dark-mode context examples. Amber is
// load-bearing here: it is what makes an exposure read as a warning. So the
// icons ship in full colour, in two colourways, and the app picks the one that
// matches the menu bar.
//
// Picking a colourway means asking the OS what appearance it is drawing. The
// earlier `defaults read -g AppleInterfaceStyle` probe answered a proxy
// question and got it wrong — Dark on a visibly light menu bar, hence an
// invisible icon. menuBarIsDark asks AppKit directly via
// NSApp.effectiveAppearance. Where the answer is unknown (Linux, Windows) the
// dark colourway is used, overridable with ACTUALIS_TRAY_THEME.
//
// State is carried by FORM as well as colour — a ring, dots, a spinner, a
// slash — so the icon still reads if the colour does not.

//go:embed icons/idle-dark.png
var iconIdleDark []byte

//go:embed icons/idle-light.png
var iconIdleLight []byte

//go:embed icons/monitoring-dark.png
var iconMonDark []byte

//go:embed icons/monitoring-light.png
var iconMonLight []byte

//go:embed icons/exposed-dark.png
var iconExpDark []byte

//go:embed icons/exposed-light.png
var iconExpLight []byte

//go:embed icons/syncing-dark.png
var iconSyncDark []byte

//go:embed icons/syncing-light.png
var iconSyncLight []byte

//go:embed icons/error-dark.png
var iconErrDark []byte

//go:embed icons/error-light.png
var iconErrLight []byte

// iconState remembers what is currently installed so the appearance watcher
// can reinstall the same state in the other colourway.
var iconState struct {
	sync.Mutex
	name string
	dark bool
	set  bool
}

// barIsDark reports whether the tray sits on a dark bar, which selects the
// bone-ink colourway. ACTUALIS_TRAY_THEME names the BAR, not the ink, and
// exists for Linux and Windows where there is no appearance signal to read.
func barIsDark() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ACTUALIS_TRAY_THEME"))) {
	case "light":
		return false
	case "dark":
		return true
	}
	dark, known := menuBarIsDark()
	if !known {
		return true // a dark taskbar is the safer default
	}
	return dark
}

// setIcon installs the state's mark in the colourway matching the menu bar.
// dark reports whether the menu bar is dark, i.e. whether the light-ink
// artwork is wanted.
func setIcon(state string) {
	dark := barIsDark()
	iconState.Lock()
	iconState.name, iconState.dark, iconState.set = state, dark, true
	iconState.Unlock()
	systray.SetIcon(iconFor(state, dark))
}

func iconFor(state string, dark bool) []byte {
	var onDark, onLight []byte
	switch state {
	case "exposed":
		onDark, onLight = iconExpDark, iconExpLight
	case "monitoring":
		onDark, onLight = iconMonDark, iconMonLight
	case "syncing":
		onDark, onLight = iconSyncDark, iconSyncLight
	case "error":
		onDark, onLight = iconErrDark, iconErrLight
	default:
		onDark, onLight = iconIdleDark, iconIdleLight
	}
	if dark {
		return onDark
	}
	return onLight
}

// watchAppearance reinstalls the current icon when the menu bar flips between
// light and dark. Without this the ink stays inverted until the next state
// change, which for a healthy fleet may be never.
func watchAppearance() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		dark := barIsDark()
		iconState.Lock()
		stale := iconState.set && iconState.dark != dark
		name := iconState.name
		if stale {
			iconState.dark = dark
		}
		iconState.Unlock()
		if stale {
			systray.SetIcon(iconFor(name, dark))
		}
	}
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
	unmoded      int // shell commands with no recorded mode: approval unknown
	invisPct     float64
	netItems     int
	netUnasked   int
	findings     []finding
	err          string
	at           time.Time
	days         int // the window this report covers, which render labels it with
}

type finding struct{ ID, Title, Severity string }

// unsupLabel is the tray's supervision line, "" when there is nothing to say.
// When some commands have no recorded mode the share says what it covers and
// names them, as actualis --share does, instead of reading as the whole fleet.
func unsupLabel(r report) string {
	switch {
	case r.hasUnsup && r.unmoded > 0:
		return fmt.Sprintf("%.0f%% of turns with a recorded mode ran unsupervised  ·  %s commands had none",
			r.unsupPct, comma(r.unmoded))
	case r.hasUnsup:
		return fmt.Sprintf("%.0f%% ran unsupervised", r.unsupPct)
	case r.unmoded > 0:
		return fmt.Sprintf("%s shell commands had no recorded permission mode", comma(r.unmoded))
	}
	return ""
}

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
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// scanTimeout bounds one CLI run. A hung actualis (a stuck network home, a
// huge transcript) must not leave the tray "loading" for good.
const scanTimeout = 5 * time.Minute

// isUngatedMode mirrors the CLI's is_ungated_mode, its single definition of a
// permission mode that does not stop for approval. Keep the two in step.
func isUngatedMode(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "auto") || strings.Contains(k, "bypass") || strings.Contains(k, "yolo") ||
		key == "codex:never"
}

// flaggedHigh is the CLI's "flagged N high": one per command, suppressed
// flags left out. bash.flagged.high carries it from the CLI; an older CLI
// lacks it, so count bash.flags[] the same way. Never sum flag_counts: it
// counts per category and includes suppressed flags.
func flaggedHigh(bash map[string]any) int {
	if fl, ok := bash["flagged"].(map[string]any); ok {
		if n, ok := fl["high"].(float64); ok {
			return int(n)
		}
	}
	n := 0
	if flags, ok := bash["flags"].([]any); ok {
		for _, f := range flags {
			m, _ := f.(map[string]any)
			if sup, _ := m["suppressed"].(bool); sup {
				continue
			}
			if m["severity"] == "high" {
				n++
			}
		}
	}
	return n
}

func fetch(days int) report {
	r := report{at: time.Now(), days: days}
	bin := findBinary()
	if bin == "" {
		r.err = "actualis not found on PATH"
		return r
	}
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--json", "--days", strconv.Itoa(days)).Output()
	if ctx.Err() == context.DeadlineExceeded {
		r.err = fmt.Sprintf("actualis did not finish within %s", scanTimeout)
		return r
	}
	if err != nil {
		r.err = "could not run actualis: " + err.Error()
		return r
	}
	return parseReport(out, days)
}

// parseReport reads `actualis --json` output. Split from fetch so it can be
// tested without a CLI on PATH.
func parseReport(out []byte, days int) report {
	r := report{at: time.Now(), days: days}
	var root map[string]any
	if err := json.Unmarshal(out, &root); err != nil {
		r.err = "actualis returned no usable JSON"
		return r
	}

	if v, ok := root["cost_usd"].(float64); ok {
		r.cost = v
	}
	// network.totals exists from 0.3.0; an older CLI simply leaves these at zero.
	if net, ok := root["network"].(map[string]any); ok {
		if t, ok := net["totals"].(map[string]any); ok {
			if v, ok := t["items"].(float64); ok {
				r.netItems = int(v)
			}
			if v, ok := t["unasked"].(float64); ok {
				r.netUnasked = int(v)
			}
		}
	}
	r.fingerprints = map[string]bool{}
	if secrets, ok := root["secrets"].([]any); ok {
		for _, s := range secrets {
			m, _ := s.(map[string]any)
			// secrets[] lists suppressed entries too. The CLI's gate and the
			// action leave them out; a reasoned suppression must clear the badge.
			if sup, _ := m["suppressed"].(bool); sup {
				continue
			}
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
		r.flaggedHigh = flaggedHigh(bash)
	}
	// The CLI computes the unsupervised share once (unsupervised_pct, added
	// after 0.3.0). Read it rather than re-derive it: a second copy of the
	// maths already drifted once. null means no permission mode was recorded.
	// unsupervised_pct covers only turns with a recorded mode; the CLI names
	// the commands that have none (every Gemini CLI one), and so must we.
	if v, ok := root["unmoded_commands"].(float64); ok && v > 0 {
		r.unmoded = int(v)
	}
	if v, present := root["unsupervised_pct"]; present {
		if pct, ok := v.(float64); ok {
			r.unsupPct, r.hasUnsup = pct, true
		}
	} else if modes, ok := root["permission_modes"].(map[string]any); ok && len(modes) > 0 {
		// Fallback for an older CLI: the same maths as its recorded_turns and
		// ungated_modes. A Codex `sandbox:` key sits beside every approval
		// policy and is not a turn of its own.
		var total, auto float64
		for k, v := range modes {
			if strings.HasPrefix(k, "sandbox:") {
				continue
			}
			n, _ := v.(float64)
			total += n
			if isUngatedMode(k) {
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
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--share")
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	out, err := cmd.Output()
	if err != nil {
		return "could not run actualis"
	}
	return string(out)
}

// ---------------------------------------------------------------- ui

type ui struct {
	mu         sync.Mutex
	rep        report
	days       int
	loading    bool
	pending    bool            // the window changed while a scan ran: scan again after it
	seen       map[string]bool // critical fingerprints already announced
	primed     bool            // first scan must not fire a flood of alerts
	primedDays int             // the window the baseline in seen was taken over

	mHeader, mSub, mCost, mShell, mUnsup, mInvis *systray.MenuItem
	mNet, mNetReport                             *systray.MenuItem
	mFindings                                    []*systray.MenuItem
	mReport, mCopy, mRefresh, mQuit              *systray.MenuItem
	mBug, mFeat, mSupport                        *systray.MenuItem
	mDays                                        map[int]*systray.MenuItem
}

func main() { systray.Run(newUI().onReady, func() {}) }

func newUI() *ui {
	return &ui{days: 7, mDays: map[int]*systray.MenuItem{}, seen: map[string]bool{}}
}

// shellQuote wraps a path for POSIX sh. Single quotes suppress every
// expansion; an embedded quote is closed, escaped and reopened.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// appleScriptString renders a Go string as an AppleScript literal. AppleScript
// performs no substitution inside a literal, so escaping the quote and the
// backslash is sufficient.
func appleScriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
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
		_ = windowsNotifyCmd(title, body).Run()
	}
}

// windowsToastScript shows a toast through the WinRT notification API, which
// ships with Windows 10 and later (no module to install). It is a constant:
// the text goes through the environment and is referenced by name. Go's %q
// escapes quotes and backslashes but not $ or backtick, and PowerShell
// evaluates $(...) inside a double-quoted string, so formatting the text into
// the command would hand it execution. CreateTextNode takes the text as data.
// The app id is PowerShell's own, registered on every install, because a toast
// from an unregistered id is silently dropped. Not run on Windows in CI.
const windowsToastScript = `$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($t)
$n = $x.GetElementsByTagName('text')
$n.Item(0).AppendChild($x.CreateTextNode($Env:ACTUALIS_TRAY_NOTIFY_TITLE)) > $null
$n.Item(1).AppendChild($x.CreateTextNode($Env:ACTUALIS_TRAY_NOTIFY_BODY)) > $null
$id = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($id).Show([Windows.UI.Notifications.ToastNotification]::new($x))`

func windowsNotifyCmd(title, body string) *exec.Cmd {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-Command", windowsToastScript)
	cmd.Env = append(os.Environ(),
		"ACTUALIS_TRAY_NOTIFY_TITLE="+title, "ACTUALIS_TRAY_NOTIFY_BODY="+body)
	return cmd
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

// trayVersion is stamped at build time with -X main.trayVersion=... ; the
// fallback keeps a hand-built binary honest rather than claiming a version it
// does not have.
var trayVersion = "dev"

const (
	repoURL    = "https://github.com/digital-foundry/actualis"
	supportURL = "https://actualis.app/support/"
)

// issueURL builds a prefilled GitHub issue.
//
// It carries the tray version, OS and architecture and NOTHING ELSE. That is a
// deliberate limit, not an oversight: this tool reads credential exposures, and
// a convenient "attach diagnostics" button would post them to a public issue
// tracker. Anything from a scan is for the user to paste knowingly.
func issueURL(kind, label string) string {
	body := fmt.Sprintf(
		"\n\n---\nActualis tray %s · %s/%s\n\n"+
			"Please do not paste scan output, transcripts or credentials into this issue.\n",
		trayVersion, runtime.GOOS, runtime.GOARCH)
	return fmt.Sprintf("%s/issues/new?labels=%s&title=%s&body=%s",
		repoURL, url.QueryEscape(label),
		url.QueryEscape(kind+": "), url.QueryEscape(body))
}

// openBrowser hands a URL to the desktop's default handler.
func openBrowser(target string) {
	// Only ever called with the constants above, but parse anyway so a future
	// caller cannot hand the shell something unexpected.
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return
	}
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", u.String()).Run()
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String()).Run()
	default:
		_ = exec.Command("xdg-open", u.String()).Run()
	}
}

func (u *ui) onReady() {
	setIcon("idle")
	go watchAppearance()
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
	u.mNet = addDisabled("")
	systray.AddSeparator()

	for i := 0; i < 4; i++ {
		u.mFindings = append(u.mFindings, addDisabled(""))
	}
	systray.AddSeparator()

	u.mReport = systray.AddMenuItem("Open Full Report", "Run the CLI in a terminal")
	u.mNetReport = systray.AddMenuItem("Open Network Report", "What the agents downloaded, and whether anyone asked")
	u.mCopy = systray.AddMenuItem("Copy Shareable Summary", "Safe to post: nothing identifying")
	u.mRefresh = systray.AddMenuItem("Refresh Now", "")

	window := systray.AddMenuItem("Window", "How far back to look")
	for _, d := range []int{1, 7, 30, 90} {
		u.mDays[d] = window.AddSubMenuItemCheckbox(fmt.Sprintf("Last %d days", d), "", d == u.days)
	}
	systray.AddSeparator()

	help := systray.AddMenuItem("Help", "")
	u.mBug = help.AddSubMenuItem("Report a Bug…", "Opens GitHub. Sends version and platform only")
	u.mFeat = help.AddSubMenuItem("Request a Feature…", "Opens GitHub")
	u.mSupport = systray.AddMenuItem("Support Development…", "Actualis is free. Opens actualis.app")

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
	// Scans run off this loop: a scan takes as long as the history is big, and
	// Quit, Copy and the rest must answer while it runs.
	for {
		select {
		case <-tick.C:
			go u.refresh()
		case <-u.mRefresh.ClickedCh:
			go u.refresh()
		case <-u.mCopy.ClickedCh:
			go copyToClipboard(shareText())
		case <-u.mReport.ClickedCh:
			go openReport()
		case <-u.mNetReport.ClickedCh:
			go openNetworkReport()
		case <-u.mBug.ClickedCh:
			go openBrowser(issueURL("Bug", "bug"))
		case <-u.mFeat.ClickedCh:
			go openBrowser(issueURL("Feature", "enhancement"))
		case <-u.mSupport.ClickedCh:
			go openBrowser(supportURL)
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
	go u.refresh()
}

func (u *ui) refresh() {
	u.mu.Lock()
	if u.loading {
		// A scan is in flight. If it is for an older window, scan again when it
		// lands, rather than wait for the next tick.
		u.pending = true
		u.mu.Unlock()
		return
	}
	u.loading = true
	days := u.days
	u.mu.Unlock()

	r := fetch(days)

	u.mu.Lock()
	u.rep, u.loading = r, false
	fresh := u.absorb(r)
	again := u.pending || r.days != u.days
	u.pending = false
	u.mu.Unlock()

	u.render()
	if again {
		go u.refresh()
	}
	if len(fresh) > 0 {
		notify("actualis: new credential exposed",
			fmt.Sprintf("%d new critical credential(s) in your agent history", len(fresh)))
		u.flash(u.state())
	}
}

// absorb records a report's critical fingerprints and returns the ones worth
// announcing. Called with u.mu held.
//
// The first scan establishes a baseline. Announcing a month of history on
// launch would train the user to ignore the notification permanently. A scan
// over a different window re-baselines the same way: widening 7 days to 90
// brings older exposures into view, and they are not new.
func (u *ui) absorb(r report) []string {
	if r.err != "" {
		return nil
	}
	announce := u.primed && r.days == u.primedDays
	fresh := []string{}
	for fp := range r.fingerprints {
		if !u.seen[fp] {
			u.seen[fp] = true
			if announce {
				fresh = append(fresh, fp)
			}
		}
	}
	u.primed, u.primedDays = true, r.days
	return fresh
}

func (u *ui) render() {
	u.mu.Lock()
	// The report's own window, not the one selected now: a scan that started
	// before the window changed covers the old one.
	r := u.rep
	days := r.days
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
	if label := unsupLabel(r); label != "" {
		show(u.mUnsup, label)
	} else {
		u.mUnsup.Hide()
	}
	if r.invisPct > 0 {
		show(u.mInvis, fmt.Sprintf("%.0f%% of shell activity is unauditable", r.invisPct))
	} else {
		u.mInvis.Hide()
	}
	if r.netItems > 0 {
		show(u.mNet, fmt.Sprintf("%s downloads  ·  %s unasked", comma(r.netItems), comma(r.netUnasked)))
	} else {
		u.mNet.Hide()
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
func openReport() { openInTerminal("--coach", "") }

// openNetworkReport shows only the NETWORK section, paged.
func openNetworkReport() { openInTerminal("", "--network") }

// openInTerminal runs `actualis <first>` (if any), then `actualis <args> | less -R`.
func openInTerminal(first, args string) {
	bin := findBinary()
	if bin == "" {
		return
	}
	switch runtime.GOOS {
	case "darwin":
		// `do script` hands its argument to a shell, so the path must be
		// single-quoted there: an unquoted /Users/first last/.local/bin/actualis
		// simply breaks. The AppleScript literal then needs its own escaping.
		sh := shellQuote(bin)
		script := fmt.Sprintf(`tell application "Terminal"
activate
do script %s
end tell`, appleScriptString(termLine(sh, first, args)))
		_ = exec.Command("osascript", "-e", script).Run()
	case "windows":
		q := `"` + bin + `"`
		line := q + " " + args
		if first != "" {
			line = q + " " + first + " && " + line
		}
		_ = exec.Command("cmd", "/c", "start", "cmd", "/k", strings.TrimSpace(line)).Start()
	default:
		for _, term := range []string{"x-terminal-emulator", "gnome-terminal", "konsole", "xterm"} {
			if _, err := exec.LookPath(term); err == nil {
				sh := shellQuote(bin)
				_ = exec.Command(term, "-e", "sh", "-c",
					termLine(sh, first, args)+"; exec sh").Start()
				return
			}
		}
	}
}

// termLine is the POSIX shell line for a terminal: the optional first command,
// then the paged report. sh is already shell-quoted; args are fixed flags.
func termLine(sh, first, args string) string {
	line := strings.TrimSpace(sh + " " + args)
	paged := line + " | less -R"
	if first == "" {
		return paged
	}
	return sh + " " + first + "; echo; " + paged
}
