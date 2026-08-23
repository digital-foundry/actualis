// agentfleet menu bar app (macOS)
//
// Copyright (C) 2026 Digital Foundry Solutions, LLC
// Licensed under the GNU Affero General Public License v3 or later.
//
// A thin shell over the CLI: it runs `agentfleet --json --days N` on a
// background queue and renders the result. All measurement lives in the CLI,
// which stays the single auditable artifact. This process holds no logic worth
// auditing and no state worth stealing.
//
// The badge counts UNROTATED CRITICAL SECRETS, not spend. A good menu bar
// number is one that should be zero and that you can act on. "3" is a to-do;
// "$980" is trivia you cannot do anything about at a glance.
//
// Native AppKit rather than Electron or Tauri: an icon, a count and a menu are
// OS APIs. There is no document to render, so there is no reason to ship a
// browser engine to draw a number.

import AppKit
import Foundation

// MARK: - Model

struct Report {
    var criticalSecrets = 0
    var rotatableSecrets = 0
    var costUSD = 0.0
    var shellCommands = 0
    var flaggedHigh = 0
    var unsupervisedPct: Double?
    var invisiblePct = 0.0
    var findings: [(id: String, title: String, severity: String)] = []
    var error: String?
    var updated = Date()
}

// MARK: - CLI bridge

enum CLI {
    /// Resolve the binary without relying on a login shell's PATH, which a
    /// GUI-launched app does not inherit.
    static func binary() -> String? {
        let candidates = [
            "\(NSHomeDirectory())/.local/bin/agentfleet",
            "/opt/homebrew/bin/agentfleet",
            "/usr/local/bin/agentfleet",
        ]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    static func fetch(days: Int) -> Report {
        var r = Report()
        guard let bin = CLI.binary() else {
            r.error = "agentfleet not found on PATH"
            return r
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--json", "--days", String(days)]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = Pipe()      // the scan progress line must not pollute stdout

        do { try p.run() } catch {
            r.error = "could not run agentfleet: \(error.localizedDescription)"
            return r
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()

        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            r.error = "agentfleet returned no usable JSON"
            return r
        }

        r.costUSD = root["cost_usd"] as? Double ?? 0
        if let secrets = root["secrets"] as? [[String: Any]] {
            r.criticalSecrets = secrets.filter { ($0["priority"] as? String) == "critical" }.count
            r.rotatableSecrets = secrets.filter { ($0["priority"] as? String) != "low" }.count
        }
        if let bash = root["bash"] as? [String: Any] {
            r.shellCommands = bash["total"] as? Int ?? 0
            if let counts = bash["flag_counts"] as? [String: Int] {
                r.flaggedHigh = counts.filter { $0.key.hasPrefix("high:") }.values.reduce(0, +)
            }
        }
        if let modes = root["permission_modes"] as? [String: Int], !modes.isEmpty {
            let total = modes.values.reduce(0, +)
            let auto = modes.filter { $0.key.lowercased().contains("auto")
                                   || $0.key.lowercased().contains("bypass") }
                            .values.reduce(0, +)
            if total > 0 { r.unsupervisedPct = Double(auto) / Double(total) * 100 }
        }
        if let subs = root["subagents"] as? [String: Any],
           let tools = subs["tools"] as? [String: Int] {
            let hidden = tools["bashCount"] ?? 0
            let all = hidden + r.shellCommands
            if all > 0 { r.invisiblePct = Double(hidden) / Double(all) * 100 }
        }
        if let coach = root["coach"] as? [[String: Any]] {
            r.findings = coach.compactMap {
                guard let id = $0["id"] as? String, let t = $0["title"] as? String,
                      let s = $0["severity"] as? String else { return nil }
                return (id, t, s)
            }
        }
        return r
    }

    static func shareText() -> String {
        guard let bin = CLI.binary() else { return "agentfleet not found" }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--share"]
        p.environment = ["NO_COLOR": "1", "PATH": "/usr/bin:/bin"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = Pipe()
        guard (try? p.run()) != nil else { return "could not run agentfleet" }
        let d = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: d, encoding: .utf8) ?? ""
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var item: NSStatusItem!
    private var timer: Timer?
    private var report = Report()
    private var loading = false
    private var windowDays = 7

    func applicationDidFinishLaunching(_ note: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.menu = NSMenu()
        item.menu?.delegate = self
        render()
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 600, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    private func refresh() {
        guard !loading else { return }
        loading = true
        let days = windowDays
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let r = CLI.fetch(days: days)
            DispatchQueue.main.async {
                self?.report = r
                self?.loading = false
                self?.render()
            }
        }
    }

    /// Badge: the count that should be zero. Nothing else earns menu bar space.
    private func render() {
        guard let button = item.button else { return }
        let n = report.criticalSecrets
        let symbol: String
        let label: String
        if report.error != nil {
            symbol = "exclamationmark.triangle"; label = ""
        } else if n > 0 {
            symbol = "key.fill"; label = " \(n)"
        } else {
            symbol = "checkmark.seal"; label = ""
        }
        let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "agentfleet")
        img?.isTemplate = true
        button.image = img
        button.title = label
        button.toolTip = report.error ?? "agentfleet — \(n) critical credential(s) exposed"
    }
}

// MARK: - Menu

extension AppDelegate: NSMenuDelegate {
    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()

        if let err = report.error {
            menu.addItem(header(err))
            menu.addItem(.separator())
            menu.addItem(action("Retry", #selector(doRefresh)))
            menu.addItem(action("Quit", #selector(doQuit)))
            return
        }

        // The finding first, because it is the only actionable line.
        if report.criticalSecrets > 0 {
            menu.addItem(header("\(report.criticalSecrets) critical credential(s) exposed"))
            menu.addItem(dim("\(report.rotatableSecrets) worth rotating in total"))
        } else {
            menu.addItem(header("No critical credentials exposed"))
        }

        menu.addItem(.separator())
        menu.addItem(dim(String(format: "$%.2f  ·  last %d days, at list price",
                                report.costUSD, windowDays)))
        menu.addItem(dim("\(report.shellCommands.formatted()) shell commands  ·  "
                         + "\(report.flaggedHigh) flagged"))
        if let u = report.unsupervisedPct {
            menu.addItem(dim(String(format: "%.0f%% ran unsupervised", u)))
        }
        if report.invisiblePct > 0 {
            menu.addItem(dim(String(format: "%.0f%% of shell activity is unauditable",
                                    report.invisiblePct)))
        }

        if !report.findings.isEmpty {
            menu.addItem(.separator())
            for f in report.findings.prefix(4) {
                menu.addItem(dim("\(f.id)  \(f.title)"))
            }
        }

        menu.addItem(.separator())
        menu.addItem(action("Open Full Report", #selector(doOpenReport)))
        menu.addItem(action("Copy Shareable Summary", #selector(doCopyShare)))
        menu.addItem(action(loading ? "Refreshing…" : "Refresh Now", #selector(doRefresh)))

        let win = NSMenuItem(title: "Window", action: nil, keyEquivalent: "")
        let sub = NSMenu()
        for d in [1, 7, 30, 90] {
            let i = NSMenuItem(title: "Last \(d) days", action: #selector(doSetWindow(_:)),
                               keyEquivalent: "")
            i.target = self; i.tag = d; i.state = (d == windowDays) ? .on : .off
            sub.addItem(i)
        }
        win.submenu = sub
        menu.addItem(win)

        menu.addItem(.separator())
        menu.addItem(dim("updated " + relative(report.updated)))
        menu.addItem(action("Quit", #selector(doQuit)))
    }

    private func header(_ s: String) -> NSMenuItem {
        let i = NSMenuItem(title: s, action: nil, keyEquivalent: "")
        i.attributedTitle = NSAttributedString(string: s, attributes: [
            .font: NSFont.systemFont(ofSize: 13, weight: .semibold)])
        return i
    }

    private func dim(_ s: String) -> NSMenuItem {
        let i = NSMenuItem(title: s, action: nil, keyEquivalent: "")
        i.attributedTitle = NSAttributedString(string: s, attributes: [
            .font: NSFont.monospacedSystemFont(ofSize: 11, weight: .regular),
            .foregroundColor: NSColor.secondaryLabelColor])
        return i
    }

    private func action(_ title: String, _ sel: Selector) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: sel, keyEquivalent: "")
        i.target = self
        return i
    }

    private func relative(_ d: Date) -> String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: d, relativeTo: Date())
    }

    @objc private func doRefresh() { refresh() }
    @objc private func doQuit() { NSApp.terminate(nil) }

    @objc private func doSetWindow(_ sender: NSMenuItem) {
        windowDays = sender.tag
        refresh()
    }

    @objc private func doCopyShare() {
        DispatchQueue.global(qos: .userInitiated).async {
            let text = CLI.shareText()
            DispatchQueue.main.async {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            }
        }
    }

    /// Open the real report in Terminal. The tray is a glance; the CLI is the tool.
    @objc private func doOpenReport() {
        guard let bin = CLI.binary() else { return }
        let script = "tell application \"Terminal\"\n"
            + "activate\n"
            + "do script \"\(bin) --coach; echo; \(bin) | less -R\"\n"
            + "end tell"
        if let apple = NSAppleScript(source: script) {
            var err: NSDictionary?
            apple.executeAndReturnError(&err)
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)   // menu bar only, no Dock icon
app.run()
