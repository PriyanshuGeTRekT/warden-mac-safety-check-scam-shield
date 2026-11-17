import Foundation
import WardenCore

// MARK: - output helpers

let isTTY = isatty(STDOUT_FILENO) != 0
func c(_ code: String, _ s: String) -> String { isTTY ? "\u{1B}[\(code)m\(s)\u{1B}[0m" : s }
func out(_ s: String = "") { print(s) }
func err(_ s: String) { FileHandle.standardError.write((s + "\n").data(using: .utf8)!) }
func fail(_ s: String, code: Int32 = 1) -> Never { err("warden: " + s); exit(code) }

func wrap(_ text: String, width: Int = 88, indent: String = "") -> String {
    var lines: [String] = [], line = ""
    for w in text.split(separator: " ") {
        if line.count + w.count + 1 > width, !line.isEmpty { lines.append(line); line = "" }
        line += (line.isEmpty ? "" : " ") + w
    }
    if !line.isEmpty { lines.append(line) }
    return lines.map { indent + $0 }.joined(separator: "\n")
}

func symbol(_ s: Severity) -> String {
    switch s {
    case .ok: return c("32", "✓")
    case .info: return c("34", "●")
    case .attention: return c("33", "▲")
    case .alert: return c("1;31", "■")
    }
}

func notify(_ title: String, _ body: String) {
    func esc(_ s: String) -> String { s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    p.arguments = ["-e", "display notification \"\(esc(body))\" with title \"\(esc(title))\" sound name \"Basso\""]
    try? p.run()
}

func machineName() -> String { Host.current().localizedName ?? ProcessInfo.processInfo.hostName }

func printReport(_ r: Report, verbose: Bool) {
    out(c("1", "Warden — Safety Check") + "   " + c("2", DateFormatter.localizedString(from: r.generated, dateStyle: .medium, timeStyle: .short)))
    out(c("1", r.headline))
    out()
    for sev in [Severity.alert, .attention, .info, .ok] {
        let fs = r.findings.filter { $0.severity == sev }
        guard !fs.isEmpty else { continue }
        out(c("1", sev.label.uppercased()))
        for f in fs {
            out(" \(symbol(sev)) \(c("1", f.title))")
            if sev >= .info || verbose {
                out(wrap(f.why, indent: "     "))
                for d in f.detail.prefix(verbose ? 40 : 8) { out("     • \(d)") }
                for fix in f.fixes where fix.kind != .quitProcess {
                    switch fix.kind {
                    case .openSettings: out(c("2", "     → \(fix.label): open \"\(fix.target)\""))
                    case .revealInFinder: out(c("2", "     → \(fix.label): open -R \"\(fix.target)\""))
                    case .quitProcess: break
                    }
                }
                for fix in f.fixes where fix.kind == .quitProcess { out(c("2", "     → \(fix.label): warden close \(f.id.components(separatedBy: "-").last ?? "")")) }
            }
        }
        out()
    }
    out(c("2", "Warden only looks; it changes nothing and sends nothing anywhere."))
}

let usage = """
warden — a Safety Check for your Mac, and a shield against remote-access scams.

  Scammers phone people, claim their computer has a problem, and talk them into installing a "support" program
  (AnyDesk, TeamViewer…) that hands over control. Warden looks for those programs, watches for one opening, and
  checks the usual signs of a break-in. It explains everything in plain words and never changes anything itself.

USAGE
  warden audit [--json] [--verbose]    run the Safety Check (exit code: 0 fine · 1 worth a look · 2 needs attention now)
  warden summary                       the same, as plain text to paste to someone who helps you
  warden watch [--notify]              the live shield: tells you when a remote-control program opens or seems connected
  warden tools                         remote-control programs installed or open right now
  warden close <tool>                  close a remote-control program that is open (asks first)
  warden trust <tool> | untrust <tool> | trusted     "I use this one": no stop sign when it opens
  warden helper set <name> <phone|email>             who to call when something looks wrong (also read from Hearth)
  warden helper show
"""

// MARK: - commands

var argv = Array(CommandLine.arguments.dropFirst())
guard let cmd = argv.first else { out(usage); exit(0) }
argv.removeFirst()
let flags = Set(argv.filter { $0.hasPrefix("--") })
let positional = argv.filter { !$0.hasPrefix("--") }

func toolArg(_ s: String) -> RemoteTool? {
    let l = s.lowercased()
    return KnownTools.all.first { $0.id == l || $0.name.lowercased() == l || $0.names.contains(l) }
}

switch cmd {
case "help", "-h", "--help":
    out(usage)

case "audit", "summary":
    let probe = LiveProbe()
    let trust = TrustStore.standard()
    let report = Audit(probe: probe, trusted: trust.ids).run()
    if cmd == "summary" {
        out(report.summaryText(machine: machineName(), os: ProcessInfo.processInfo.operatingSystemVersionString))
    } else if flags.contains("--json") {
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]; e.dateEncodingStrategy = .iso8601
        out(String(data: try! e.encode(report), encoding: .utf8)!)
    } else {
        printReport(report, verbose: flags.contains("--verbose"))
    }
    exit(report.worst == .alert ? 2 : (report.worst == .attention ? 1 : 0))

case "tools":
    let probe = LiveProbe()
    let trust = TrustStore.standard()
    var any = false
    let procs = probe.runningProcesses().compactMap { p in KnownTools.matchProcess(command: p.command).map { ($0, p) } }
    let f = DateFormatter(); f.dateFormat = "MMM d, yyyy"
    for a in probe.installedApps() {
        guard let t = KnownTools.match(bundleID: a.bundleID, name: a.name, path: a.path), !t.builtIn else { continue }
        any = true
        let open = procs.contains { $0.0.id == t.id }
        out("\(open ? c("1;33", "OPEN     ") : "installed ") \(t.name)  \(c("2", "(id: \(t.id))"))  installed \(a.installed.map { f.string(from: $0) } ?? "?")" +
            (trust.isTrusted(t.id) ? c("32", "   [you use this]") : ""))
    }
    if !any { out("No remote-control programs are installed. 👍") }

case "trust", "untrust":
    guard let name = positional.first, let t = toolArg(name) else { fail("which tool? try: warden tools   (e.g. warden \(cmd) anydesk)") }
    let trust = TrustStore.standard()
    if cmd == "trust" { trust.trust(t.id); out("OK. Warden won't show a stop sign when \(t.name) opens. It will still tell you quietly if a session seems to start.") }
    else { trust.untrust(t.id); out("OK. Warden will warn you whenever \(t.name) opens.") }

case "trusted":
    let ids = TrustStore.standard().ids.sorted()
    out(ids.isEmpty ? "You haven't marked any tool as one you use." : ids.compactMap { KnownTools.tool(id: $0)?.name ?? $0 }.joined(separator: "\n"))

case "helper":
    if positional.first == "set", positional.count >= 3 {
        let name = positional[1], handle = positional[2]
        guard Parse_isUsable(handle) else { fail("that doesn't look like a phone number or an email address") }
        try HelperContact(name: name, handle: handle).save()
        out("OK. If something looks wrong, Warden will offer to call \(name).")
    } else if let h = HelperContact.load() { out("\(h.name) — \(h.handle)") }
    else { out("No helper set. Use: warden helper set \"Anna\" \"+1 555 010 0199\"") }

case "close":
    guard let name = positional.first, let t = toolArg(name) else { fail("which tool? (warden tools)") }
    let probe = LiveProbe()
    let monitor = ShieldMonitor(probe: probe, trust: TrustStore.standard())
    monitor.tick()
    let pids = monitor.pids(of: t.id)
    guard !pids.isEmpty else { out("\(t.name) isn't open."); exit(0) }
    print("Close \(t.name) (\(pids.count) process\(pids.count == 1 ? "" : "es"))? Anything it is doing will stop. [y/N] ", terminator: "")
    guard let a = readLine(), ["y", "yes"].contains(a.lowercased()) else { out("Nothing changed."); exit(0) }
    let closed = monitor.close(toolID: t.id)
    out(closed.count == pids.count ? "Closed." : "Closed \(closed.count) of \(pids.count). Some parts run with administrator rights; quit \(t.name) from its own menu, or from Activity Monitor.")

case "watch":
    let probe = LiveProbe()
    let trust = TrustStore.standard()
    let monitor = ShieldMonitor(probe: probe, trust: trust)
    let doNotify = flags.contains("--notify")
    let helper = HelperContact.load()
    err("warden: shield on — watching for remote-control programs (Ctrl-C to stop)")
    for sig in [SIGINT, SIGTERM] { signal(sig) { _ in LiveProbe.shutdown(); exit(0) } }
    while true {
        for e in monitor.tick() {
            let stamp = DateFormatter.localizedString(from: e.at, dateStyle: .none, timeStyle: .medium)
            switch e.kind {
            case .launched:
                out("[\(stamp)] \(e.trusted ? "●" : "▲") \(e.detail)" + (e.trusted ? "" : " If someone asked you to open it, stop and hang up."))
                if doNotify && !e.trusted { notify("\(e.tool.name) is open", "If someone told you to open this, stop. It can give them control of your Mac." + (helper.map { " Call \($0.name)." } ?? "")) }
            case .sessionLikely:
                out("[\(stamp)] ■ \(e.detail)  Close it now with: warden close \(e.tool.id)")
                if doNotify { notify("Someone may be controlling your Mac", e.detail) }
            case .sessionEnded: out("[\(stamp)] ✓ \(e.detail)")
            case .quit: out("[\(stamp)] ✓ \(e.detail)")
            }
            fflush(stdout)
        }
        Thread.sleep(forTimeInterval: 3)
    }

default:
    err("warden: unknown command “\(cmd)”\n")
    err(usage)
    exit(64)
}

func Parse_isUsable(_ s: String) -> Bool {
    let t = s.trimmingCharacters(in: .whitespaces)
    if t.contains("@") && t.contains(".") && !t.contains(" ") { return true }
    let digits = t.filter { $0.isNumber }
    return digits.count >= 7 && digits.count <= 15 && t.allSatisfy { $0.isNumber || " +-().".contains($0) }
}
