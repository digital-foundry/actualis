# Menu bar app (macOS)

A glance at the one number that should be zero.

```sh
./build.sh && open agentfleet.app
```

Requires the Xcode command line tools. No Xcode project, no package manager, no
dependencies — one Swift file compiled into a bundle, about 150 KB.

## What the badge counts

**Unrotated critical credentials.** Not spend.

A menu bar number earns its place by being actionable at a glance. "3" is a
to-do you can clear. "$980" is trivia you cannot do anything about while looking
at it, and on a flat subscription it is not even a bill. Spend is in the menu,
one click away, where it belongs.

The icon is a sealed checkmark when clean and a key with a count when not.

## What it is

A thin shell over the CLI. It runs `agentfleet --json --days N` on a background
queue every ten minutes and renders the result. **All measurement lives in the
CLI**, which stays the single auditable artifact; this process holds no logic
worth reviewing and no state worth stealing.

Native AppKit, deliberately. An icon, a count and a menu are operating system
APIs. There is no document to render, so there is no reason to ship a browser
engine to draw a number — which is what Electron would mean, and what Tauri
would mean at a smaller size.

The window selector (1 / 7 / 30 / 90 days) exists because the scan is bounded by
file modification time: a one-day window reads 7 files rather than 1,784, so it
returns in about a second.

## Menu

- Critical credentials exposed, and how many are worth rotating
- Spend for the window, at list price
- Shell commands and how many were flagged
- What share ran unsupervised, and what share is unauditable inside subagents
- The top coach findings
- **Open Full Report** — hands you to the CLI in Terminal, because the tray is a
  glance and the CLI is the tool
- **Copy Shareable Summary** — `--share` output to the clipboard, safe to post
- Window selector, refresh, quit

## Distribution

The build is **ad-hoc signed**, which is enough to run on the machine that built
it. Shipping it to anyone else needs a Developer ID certificate ($99/yr) and
notarisation. That cost is worth weighing only if this is ever distributed;
until then, building locally avoids it entirely.

## Run it at login

System Settings → General → Login Items → add `agentfleet.app`.
