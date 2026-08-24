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

**The geometry is measured, not eyeballed.** Every ratio in
`icons/gen_icons.py` was taken off `branding/trayiconMac.png` — the 32px cells
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

## Alerting

A **newly** appearing critical credential raises a native notification and
flashes the badge three times. Deduplicated by fingerprint, so the same secret
never announces itself twice, and the first scan only establishes a baseline —
announcing a month of history at launch trains you to ignore the notification
permanently.

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
renders the result. **All measurement lives in the CLI**, which stays
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
