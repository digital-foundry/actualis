# Tray — macOS, Linux, Windows

One Go binary per platform, about 2.6 MB, no runtime dependency.

```sh
go build -ldflags "-s -w" -o agentfleet-tray .
./agentfleet-tray
```

Prebuilt binaries for all three platforms are produced by the `tray` workflow on
every push and attached as artifacts.

## What the badge counts

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

This is a thin shell. It runs `agentfleet --json --days N` every ten minutes and
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
