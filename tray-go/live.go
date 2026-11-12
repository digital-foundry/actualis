package main

// Live state from `actualis --watch --json` (#95).
//
// The tray's scan runs every ten minutes; a browser agent can read a page,
// and the tray learn of it, well after. So the tray also runs the CLI's watch
// stream as a long-lived child and reads one JSON event per line. It uses the
// stream for three things only: the "agent looking" icon while a browser or
// computer-use tool is in use, live seen-on-screen counts, and an early
// rescan when a credential appears (the notification still comes from the
// scan, so there is one path to it). The stream carries no values, and
// nothing from it is shown beyond a tool name, a family and an agent.
//
// An older CLI refuses --watch --json (exit 2). The tray then keeps to the
// periodic scan and asks again an hour later, in case the CLI was upgraded.

import (
	"bufio"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// lookWindow is how long after the last browser or computer-use event the
	// icon keeps showing "agent looking". A page read is one call; a session
	// of them is several, seconds apart, and should read as one stretch.
	lookWindow = 45 * time.Second
	// openCallMax bounds how long a call whose result never came keeps the
	// state on. A call can outlive lookWindow (a slow page) but not this.
	openCallMax = 5 * time.Minute
	// rescanAfterScreen is how long the stream must be quiet after a screen
	// finding or screenshot before the tray rescans to reconcile its counts.
	rescanAfterScreen = 60 * time.Second
	// rescanAfterCredential is the delay before the rescan a credential
	// triggers: soon, but after the agent's next records have landed.
	rescanAfterCredential = 3 * time.Second
	// streamRetryOld is how long to wait before asking an older CLI again.
	streamRetryOld = time.Hour
	// maxEventLine bounds one stream line. Events are a few hundred bytes.
	maxEventLine = 64 << 10
)

// watchEvent is one line of `actualis --watch --json`. Fields not listed
// here are ignored, and so are event types the tray does not know.
type watchEvent struct {
	Event      string `json:"event"`
	Phase      string `json:"phase"`
	Agent      string `json:"agent"`
	Tool       string `json:"tool"`
	Family     string `json:"family"`
	Session    string `json:"session"`
	Source     string `json:"source"`
	Kind       string `json:"kind"`
	Detector   string `json:"detector"`
	ID         string `json:"id"`
	Priority   string `json:"priority"`
	Suppressed bool   `json:"suppressed"`
	Screen     bool   `json:"screen"`
	Count      int    `json:"count"`
}

// parseEvent reads one stream line; ok is false for anything that is not a
// JSON object naming an event.
func parseEvent(line []byte) (watchEvent, bool) {
	var ev watchEvent
	if len(line) == 0 || len(line) > maxEventLine || json.Unmarshal(line, &ev) != nil || ev.Event == "" {
		return watchEvent{}, false
	}
	return ev, true
}

// liveCount is what one stream event adds to the seen-on-screen counts.
type liveCount struct {
	at                                    time.Time
	results, personal, credentials, shots int
}

// liveState is what the stream has said. Not safe for concurrent use: the ui
// holds its lock around every call.
type liveState struct {
	open                map[string]time.Time // session+tool of a call started and not ended
	last                time.Time            // the last browser or computer-use event
	tool, family, agent string               // the call it was about
	counts              []liveCount
}

func newLiveState() *liveState { return &liveState{open: map[string]time.Time{}} }

// rescan says what an event asks of the scan: nothing, a rescan soon (a
// credential), or one once the stream has been quiet a while (screen counts).
type rescan int

const (
	rescanNone rescan = iota
	rescanSoon
	rescanQuiet
)

// apply records one event and says whether it calls for a rescan.
func (l *liveState) apply(ev watchEvent, now time.Time) rescan {
	switch ev.Event {
	case "activity":
		key := ev.Session + "\x00" + ev.Tool
		l.last, l.tool, l.family, l.agent = now, ev.Tool, ev.Family, ev.Agent
		switch ev.Phase {
		case "start":
			l.open[key] = now
		case "end":
			delete(l.open, key)
			l.counts = append(l.counts, liveCount{at: now, results: 1})
		}
	case "finding":
		if ev.Kind == "credential" {
			if ev.Source == "screen" {
				l.counts = append(l.counts, liveCount{at: now, credentials: 1})
			}
			if ev.Suppressed {
				return rescanNone
			}
			return rescanSoon
		}
		if ev.Source == "screen" && ev.Kind == "personal" {
			l.counts = append(l.counts, liveCount{at: now, personal: 1})
			return rescanQuiet
		}
	case "screenshot":
		if ev.Count > 0 {
			l.counts = append(l.counts, liveCount{at: now, shots: ev.Count})
			return rescanQuiet
		}
	}
	return rescanNone
}

// looking reports whether a browser or computer-use tool was in use within
// lookWindow, or has a call open that started within openCallMax.
func (l *liveState) looking(now time.Time) bool {
	if !l.last.IsZero() && now.Sub(l.last) < lookWindow {
		return true
	}
	for key, at := range l.open {
		if now.Sub(at) < openCallMax {
			return true
		}
		delete(l.open, key)
	}
	return false
}

// since sums the counts the stream added at or after t: what the scan that
// started at t has not seen yet. Older entries are dropped.
func (l *liveState) since(t time.Time) liveCount {
	var sum liveCount
	kept := l.counts[:0]
	for _, c := range l.counts {
		if c.at.Before(t) {
			continue
		}
		kept = append(kept, c)
		sum.results += c.results
		sum.personal += c.personal
		sum.credentials += c.credentials
		sum.shots += c.shots
	}
	l.counts = kept
	return sum
}

// withLive adds the stream's counts since the scan to the scan's own. Only
// when the scan read `screen` at all: a CLI without it shows nothing.
func withLive(s screenSeen, c liveCount) screenSeen {
	if !s.present {
		return s
	}
	s.results += c.results
	s.personal += c.personal
	s.credentials += c.credentials
	s.screenshots += c.shots
	return s
}

// trayState is the icon for a report. Credential states come first: "agent
// looking" never hides an exposure. A stale list ranks below looking, which
// is about now.
func trayState(r report, listsDue, looking bool) string {
	switch {
	case r.critical > 0:
		return "exposed"
	case r.rotatable > 0:
		return "monitoring"
	case looking:
		return "looking"
	case listsDue:
		return "update"
	}
	return "idle"
}

var familyNames = map[string]string{
	"claude-in-chrome": "Claude in Chrome",
	"playwright":       "Playwright",
	"chrome-devtools":  "Chrome DevTools",
	"computer-use":     "computer use",
}

var agentNames = map[string]string{
	"claude-code": "Claude Code", "codex": "Codex", "copilot": "Copilot",
	"gemini": "Gemini CLI", "qwen": "Qwen Code",
}

// lookingLabel names the agent and tool for the tooltip, e.g. "Claude Code
// is using Claude in Chrome (get_page_text)". The tool's short name is the
// part after the last "__" of an MCP name.
func lookingLabel(tool, family, agent string) string {
	who := agentNames[agent]
	if who == "" {
		who = "An agent"
	}
	what := familyNames[family]
	if what == "" {
		what = "a browser tool"
	}
	short := tool
	if i := strings.LastIndex(tool, "__"); i >= 0 {
		short = tool[i+2:]
	}
	if len(short) > 48 {
		short = short[:48]
	}
	if short == "" || short == what {
		return who + " is using " + what
	}
	return who + " is using " + what + " (" + short + ")"
}

// ---------------------------------------------------------------- the child

// streamOnce runs `bin --watch --json` until it exits or stop is closed,
// handing each event to onEvent. It returns whether the CLI said hello with
// screen events: false means an older CLI, which refuses the flag or does
// not stream what the tray reads.
func streamOnce(bin string, args []string, stop <-chan struct{}, onEvent func(watchEvent)) bool {
	cmd := exec.Command(bin, args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return false
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return false
	}
	done := make(chan struct{})
	var once sync.Once
	kill := func() { once.Do(func() { _ = cmd.Process.Kill() }) }
	go func() {
		select {
		case <-stop:
			kill()
		case <-done:
		}
	}()
	defer close(done)

	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 4096), maxEventLine)
	hello := false
	for sc.Scan() {
		ev, ok := parseEvent(sc.Bytes())
		if !ok {
			continue
		}
		if !hello {
			if ev.Event != "hello" || !ev.Screen {
				kill()
				break
			}
			hello = true
			continue
		}
		onEvent(ev)
	}
	kill() // a line too long or a read error: start over rather than half-read
	_, _ = io.Copy(io.Discard, out)
	_ = cmd.Wait()
	return hello
}

// runStream keeps the watch stream running for the tray's lifetime: restart
// with backoff when it ends, and an hour's wait when the CLI is too old.
func (u *ui) runStream() {
	backoff := 2 * time.Second
	for {
		select {
		case <-u.stop:
			return
		default:
		}
		bin := findBinary()
		wait := time.Minute
		if bin != "" {
			started := time.Now()
			ok := streamOnce(bin, []string{"--watch", "--json"}, u.stop, u.onEvent)
			u.mu.Lock()
			u.liveOK = ok
			u.mu.Unlock()
			switch {
			case !ok:
				wait = streamRetryOld
			case time.Since(started) > 5*time.Minute:
				backoff = 2 * time.Second
				wait = backoff
			default:
				wait = backoff
				if backoff *= 2; backoff > 5*time.Minute {
					backoff = 5 * time.Minute
				}
			}
		}
		select {
		case <-u.stop:
			return
		case <-time.After(wait):
		}
	}
}

// onEvent applies one stream event and re-renders when it changed what the
// tray shows.
func (u *ui) onEvent(ev watchEvent) {
	u.mu.Lock()
	need := u.live.apply(ev, time.Now())
	u.mu.Unlock()
	switch need {
	case rescanSoon:
		time.AfterFunc(rescanAfterCredential, func() { u.refresh() })
	case rescanQuiet:
		u.mu.Lock()
		if u.quietTimer == nil {
			u.quietTimer = time.AfterFunc(rescanAfterScreen, func() { u.refresh() })
		} else {
			u.quietTimer.Reset(rescanAfterScreen)
		}
		u.mu.Unlock()
	}
	if ev.Event == "activity" || need != rescanNone {
		u.render()
	}
}

// watchLooking re-renders when "agent looking" lapses: nothing arrives on the
// stream to say so.
func (u *ui) watchLooking() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	was := false
	for {
		select {
		case <-u.stop:
			return
		case <-t.C:
		}
		u.mu.Lock()
		now := u.live.looking(time.Now())
		u.mu.Unlock()
		if now != was {
			was = now
			u.render()
		}
	}
}
