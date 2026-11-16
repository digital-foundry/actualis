# Tray — macOS, Linux, Windows

One Go binary per platform, about 2.6 MB, no runtime dependency.

```sh
go build -ldflags "-s -w" -o actualis-tray .
./actualis-tray
```

Prebuilt binaries for all three platforms are produced by the `tray` workflow on
every push and attached as artifacts.

## Brand

Palette from the brand guide (master; the macOS icon sheet lists different
values for slate, smoke and amber and is treated as the outlier):

| | hex |
|---|---|
| CARBON | `#0B0C0E` |
| SLATE | `#1F2430` |
| SMOKE | `#3A414E` |
| BONE | `#F2EFE9` |
| AMBER | `#E08A24` |

Type: **Inter** primary, **IBM Plex Mono** for data.

## The icon

The **A-mark** from the Actualis icon system: two splayed legs with an amber
baseline. Identity stays constant; state is carried by an added *form*.

| state | form | when |
|---|---|---|
| idle | A-mark | nothing exposed |
| monitoring | A-mark + two amber dots | credentials worth rotating |
| exposed | A-mark inside a thin amber ring | critical credentials exposed |
| syncing | segmented spinner, no A-mark | scanning |
| error | A-mark with a slash (the sheet's MUTED glyph) | data could not be read |
| looking | A-mark + a small amber eye, upper right | a browser or computer-use tool was in use in the last 45 seconds, or a call is still open (up to 5 minutes). Below exposed and monitoring |

The looking eye is not on the sheet: it sits in the corner and at the weight of
the sheet's badges, and its form (an outline with a pupil) differs from the
monitoring dots and the solid update badge.

**The geometry is measured, not eyeballed.** Every ratio in
`icons/gen_icons.py` was taken off the ACTUALIS macOS icon sheet — the 32px cells
of the SIZES table for layout, the 98px overview tiles for stroke weight, with
the source measurement recorded beside each constant. The sheet says *"do not
alter proportions or stroke weights"*, so the generator is the spec and the
PNGs are build output. Regenerate with `python3 icons/gen_icons.py`.

**These are not template icons.** A macOS template image is alpha-only — the OS
inks it as a flat monochrome mask — so it cannot carry the amber that the sheet
puts on every state, in both its light-mode and dark-mode context examples.
Amber is load-bearing: it is what makes an exposure read as a warning rather
than as a letter A. So the icons ship in full colour, in two colourways, and
the app installs the one matching the menu bar.

Choosing a colourway means asking the OS what appearance it is drawing.
`defaults read -g AppleInterfaceStyle` answers a proxy question and gets it
wrong — it reported *Dark* on a machine whose menu bar was visibly light, which
is exactly how you ship an invisible icon. `appearance_darwin.go` asks AppKit
directly through `NSApp.effectiveAppearance`, and a 2-second watcher reinstalls
the icon when the appearance flips, since for a healthy fleet the next state
change may never come.

Linux and Windows have no single reliable cross-desktop appearance signal, so
they get the dark-menu-bar colourway by default. `ACTUALIS_TRAY_THEME=light`
overrides it.

Icons render at 44px (22pt @2x) with 4x4 supersampling.

Two brand rules shape the rest. **Amber indicates state, never identity**, so
the mark still reads with amber stripped. And **colour alone never carries
meaning** — every state also changes form.

## Menu

Beyond the read-outs, the menu carries three outward links:

| item | goes to |
|---|---|
| Help → Report a Bug… | a prefilled GitHub issue |
| Help → Request a Feature… | a prefilled GitHub issue |
| Support Development… | `actualis.app/support` |

A prefilled bug report carries the tray version, the OS and the architecture,
and **nothing else**. There is deliberately no "attach diagnostics" button:
this tool reads credential exposures, and a convenience that posted them to a
public issue tracker would be the worst bug it could have. The issue body says
so, so a helpful reporter does not paste them by hand either.

`trayVersion` is stamped at build time (`-X main.trayVersion=...`) and CI sets
it to the commit SHA, so a report names an exact build. A hand-built binary
reports `dev` rather than claiming a version it does not have.

### Seen on screen

When the run read any browser or computer-use results, the menu shows
`Seen on screen: 15 personal data  ·  842 screenshots` (with a credential count
first when there is one), from the CLI's `screen` key. It is counts only: never
a value, a fingerprint or a detector name. Clicking it opens
`actualis --explain screen` in a terminal. Personal data does not change the
icon: the exposed and monitoring states stay about credentials. A CLI without
the `screen` key shows nothing here.

### Live

Beside its scans, the tray runs `actualis --watch --json` as a child process
and reads its event stream (see `docs/json.md`, "`--watch --json`"):

- While a browser or computer-use tool is in use, the icon shows **looking**
  and the tooltip names the agent and tool, e.g. *Claude Code is using Claude in
  Chrome (get_page_text)*. With a credential warning up, the warning keeps the
  icon and the tooltip adds the same words after it.
- The seen-on-screen line adds what the stream reports after the last scan
  started, and the tray rescans once the stream has been quiet for 60 seconds
  to reconcile (a value seen earlier in the window can be counted twice until
  then).
- A credential on the stream triggers a rescan within seconds, so its
  notification comes from the scan as before, not from the stream.

The child is restarted with backoff when it ends and killed when the tray
quits; if the tray dies first, the child's next heartbeat write fails and it
exits. A CLI that refuses `--watch --json` (0.7.0 and older) leaves the tray on
the ten-minute scan, and the tray asks again an hour later.

## Alerting

A **newly** appearing critical credential raises a native notification and
flashes the badge three times. Deduplicated by fingerprint, so the same secret
never announces itself twice, and the first scan only establishes a baseline —
announcing a month of history at launch trains you to ignore the notification
permanently. Changing the window re-baselines the same way: widening it to 90
days brings older exposures into view, and they are not new. A credential you
suppressed (with a reason) does not count toward the badge or the alert, as it
does not count toward `--fail-on`. On Windows the notification is a toast
through the built-in WinRT API (Windows 10 and later).

A credential seen in a browser or computer-use result rather than in a command
says so: `actualis: new credential exposed (seen on screen)` when every new one
was, or `..., N seen on screen` in the body when only some were.

## What the count means

**Unrotated critical credentials.** Not spend. A tray number earns its place by
being actionable at a glance: "3" is a to-do you can clear, "$980" is trivia,
and on a flat subscription it is not even a bill. Spend is one click into the
menu.

## Platform differences, stated rather than papered over

| | macOS | Linux | Windows |
|---|---|---|---|
| Icon | yes | yes | yes |
| **Count beside the icon** | yes | depends on desktop | **no** |
| Tooltip | yes | yes | yes |
| Menu | yes | yes | yes |

Only macOS reliably renders text next to a tray icon. Some Linux desktops do;
Windows does not. So the count always appears in the **tooltip and the first
menu item**, and `SetTitle` is a bonus where it happens to work rather than the
mechanism anything depends on. The icon itself carries the state everywhere:
hollow when clean, filled when there is something to rotate.

Linux needs an AppIndicator-capable tray. GNOME requires the AppIndicator
extension; KDE, XFCE and most others work out of the box.

## Why not Electron or Tauri

An icon, a count and a menu are operating system APIs. There is no document to
render, so there is no reason to ship a browser engine — 2.6 MB against roughly
100 MB for Electron, and no webview attack surface on a machine where this sits
next to your credentials.

## Relationship to the CLI

This is a thin shell. It runs `actualis --json --days N` every ten minutes and
renders the result, and reads `actualis --watch --json` for the live state. **All measurement lives in the CLI**, which stays
dependency-free and auditable in one sitting. The tray has one dependency, for
drawing a tray icon, and contains no logic worth reviewing.

That boundary is deliberate: you can read and trust the thing that touches your
transcripts without reading the thing that draws a menu.

## Build dependencies

- **macOS** — Xcode command line tools
- **Linux** — `libgtk-3-dev libayatana-appindicator3-dev`
- **Windows** — none beyond Go. Build with
  `-ldflags "-H windowsgui"` or a console window sits behind the tray icon for
  the life of the process. CI asserts this rather than trusting it.
