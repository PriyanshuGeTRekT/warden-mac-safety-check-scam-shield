import Foundation

/// The "Safety Check": looks at who can see or control this Mac, and at the usual traces of a scam or a break-in,
/// and explains each result in plain words. It reads; it never changes anything.
public struct Audit {
    public let probe: SystemProbe
    public var trusted: Set<String>
    /// Bytes per second leaving a remote-control program that suggest someone is watching the screen.
    public static let heavyOutBytesPerSecond: Double = 60_000
    public var sampleSeconds: TimeInterval = 2
    public var sleep: (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) }

    public init(probe: SystemProbe, trusted: Set<String> = []) {
        self.probe = probe
        self.trusted = trusted
    }

    public func run() -> Report {
        var f: [Finding] = []
        f += remoteControl()
        f += sharing()
        f += device()
        f += basics()
        f += network()
        f += startup()
        f += permissions()
        f += accounts()
        return Report(generated: probe.now(), findings: f)
    }

    // MARK: remote control

    static let scamAdvice = "If someone phoned, messaged or emailed you and asked you to open or install this, stop: it is a very common scam. Hang up, and do not give out passwords, codes or card numbers."

    func remoteControl() -> [Finding] {
        var out: [Finding] = []
        let now = probe.now()
        let installed: [(tool: RemoteTool, app: InstalledApp)] = probe.installedApps().compactMap { a in
            guard let t = KnownTools.match(bundleID: a.bundleID, name: a.name, path: a.path), !t.builtIn else { return nil }
            return (t, a)
        }
        var running: [String: (tool: RemoteTool, procs: [RunningProcess])] = [:]
        for p in probe.runningProcesses() {
            guard let t = KnownTools.matchProcess(command: p.command) else { continue }
            running[t.id, default: (t, [])].procs.append(p)
        }

        // watch the running tools for a couple of seconds: an idle tool whispers, a session streams the screen
        let watched = running.values.filter { !$0.tool.builtIn }.flatMap { $0.procs.map { $0.pid } }
        var rate: [Int32: Double] = [:]
        if !watched.isEmpty {
            probe.startTrafficStream()
            var a = probe.trafficSnapshot()
            var waited = 0.0
            while a == nil && waited < 8 { sleep(0.25); waited += 0.25; a = probe.trafficSnapshot() } // the first sample takes a moment
            sleep(sampleSeconds)
            var b = probe.trafficSnapshot()
            var extra = 0.0
            while let x = a, (b == nil || b!.at <= x.at), extra < 3 { sleep(0.25); extra += 0.25; b = probe.trafficSnapshot() } // wait for a newer sample
            if let x = a, let y = b, y.at > x.at {
                let dt = y.at.timeIntervalSince(x.at)
                for pid in watched { if let p = x.byPid[pid], let q = y.byPid[pid], q.outBytes >= p.outBytes { rate[pid] = Double(q.outBytes - p.outBytes) / dt } }
            }
        }
        let conns = watched.isEmpty ? [] : probe.establishedConnections().filter { watched.contains($0.pid) && !$0.isLocal }

        for (id, entry) in running.sorted(by: { $0.key < $1.key }) {
            let tool = entry.tool
            let pids = entry.procs.map { $0.pid }
            if tool.builtIn {
                out.append(Finding(id: "remote-running-\(id)", category: .remoteAccess, severity: .attention,
                                   title: "Apple Remote Management is running",
                                   why: "This lets an administrator see and control this Mac over the network. That is normal for a work or school Mac, or if you turned it on yourself. If you didn't, switch it off.",
                                   fixes: [.settings("Open Sharing settings", SettingsPane.sharing)]))
                continue
            }
            let peak = pids.compactMap { rate[$0] }.reduce(0, +)
            let remotes = Array(Set(conns.filter { pids.contains($0.pid) }.map { "\($0.remoteHost):\($0.remotePort)" })).sorted().prefix(4)
            let quit = Fix(kind: .quitProcess, label: "Close \(tool.name) now", target: pids.map(String.init).joined(separator: ","))
            if peak >= Audit.heavyOutBytesPerSecond {
                out.append(Finding(id: "remote-active-\(id)", category: .remoteAccess, severity: .alert,
                                   title: "\(tool.name) looks connected to someone right now",
                                   why: "\(tool.name) is open and sending a lot of data, which is what it does when another person is watching your screen. Close it now if you did not start this yourself. " + Audit.scamAdvice,
                                   detail: ["Sending about \(Int(peak / 1000)) KB/s"] + (remotes.isEmpty ? [] : ["Connected to: " + remotes.joined(separator: ", ")]),
                                   fixes: [quit]))
            } else {
                let isTrusted = trusted.contains(id)
                out.append(Finding(id: "remote-running-\(id)", category: .remoteAccess, severity: isTrusted ? .info : .attention,
                                   title: "\(tool.name) is open",
                                   why: isTrusted ? "You told Warden you use \(tool.name). It isn't sending much data, so nobody seems to be connected."
                                                  : "\(tool.name) lets another person see and control this Mac. Nothing suggests anyone is connected right now, but it is ready to be. If you didn't open it, close it. " + Audit.scamAdvice,
                                   detail: remotes.isEmpty ? [] : ["Talking to: " + remotes.joined(separator: ", ")],
                                   fixes: isTrusted ? [] : [quit]))
            }
        }

        let idle = installed.filter { running[$0.tool.id] == nil }
        if !idle.isEmpty {
            let recent = idle.contains { ($0.app.installed ?? .distantPast) > now.addingTimeInterval(-14 * 86400) }
            let f = DateFormatter(); f.dateFormat = "MMM d"
            out.append(Finding(
                id: "remote-installed", category: .remoteAccess, severity: recent ? .attention : .info,
                title: recent ? "A remote-control program was installed recently" : "Remote-control programs are installed",
                why: recent
                    ? "These programs let another person see and control this Mac once you give them a code. They are meant for IT support and for reaching your own computer, and they are exactly what “tech support” scammers ask people to install. If you didn't install this recently yourself, remove it. " + Audit.scamAdvice
                    : "These programs let another person see and control this Mac once you give them a code. They are meant for IT support and for reaching your own computer, and they are also what “tech support” scammers ask people to install. Fine if you still use them; if you don't remember installing them, or don't need them any more, remove them.",
                detail: idle.map { "\($0.tool.name) — \($0.app.installed.map { "installed \(f.string(from: $0)) (\(Int(now.timeIntervalSince($0) / 86400)) days ago)" } ?? "install date unknown")" },
                fixes: idle.prefix(3).map { Fix(kind: .revealInFinder, label: "Show \($0.tool.name) in Finder", target: $0.app.path) }))
        }

        let installedIDs = Set(installed.map { $0.tool.id }).union(running.keys)
        var leftovers: [String] = []
        for item in probe.launchItems() where item.scope != .userAgent {
            if let t = KnownTools.matchHelper(label: item.label), !t.builtIn, !installedIDs.contains(t.id) { leftovers.append("\(t.name): \(item.label)") }
        }
        if !leftovers.isEmpty {
            out.append(Finding(id: "remote-leftover-helper", category: .remoteAccess, severity: .attention,
                               title: "A remote-control helper is still installed",
                               why: "The program itself is gone, but a helper it installed is still set up to run with administrator rights. If you don't use that program any more, remove the helper too.",
                               detail: leftovers))
        }
        if out.isEmpty {
            out.append(Finding(id: "remote-none", category: .remoteAccess, severity: .ok, title: "No remote-control programs found",
                               why: "None of the usual remote-control programs (AnyDesk, TeamViewer and similar) is installed or running."))
        }
        return out
    }

    // MARK: sharing

    func sharing() -> [Finding] {
        let open = Set(probe.listeners().filter { !$0.localOnly }.map { $0.port })
        var out: [Finding] = []
        if open.contains(5900) || open.contains(3283) {
            out.append(Finding(id: "sharing-screen", category: .sharing, severity: .attention, title: "Screen Sharing is turned on",
                               why: "Other computers on your network can ask to see or control this screen (they still need an account name and password). If you don't use this, turn it off.",
                               detail: open.contains(5900) ? ["Listening on port 5900"] : ["Listening on port 3283 (Remote Management)"],
                               fixes: [.settings("Open Sharing settings", SettingsPane.sharing)]))
        }
        if open.contains(22) {
            out.append(Finding(id: "sharing-ssh", category: .sharing, severity: .attention, title: "Remote Login is turned on",
                               why: "Other computers can sign in to this Mac from a command line. That is for technical people; if you don't use it, turn it off.",
                               detail: ["Listening on port 22"], fixes: [.settings("Open Sharing settings", SettingsPane.sharing)]))
        }
        if open.contains(445) {
            out.append(Finding(id: "sharing-files", category: .sharing, severity: .info, title: "File Sharing is turned on",
                               why: "Other computers on your network can reach folders you chose to share. Fine at home if you use it; switch it off on public Wi-Fi.",
                               fixes: [.settings("Open Sharing settings", SettingsPane.sharing)]))
        }
        if out.isEmpty {
            out.append(Finding(id: "sharing-none", category: .sharing, severity: .ok, title: "Screen, file and remote-login sharing are off",
                               why: "Nothing on this Mac is set up to let other computers in."))
        }
        return out
    }

    // MARK: device management

    func device() -> [Finding] {
        let e = probe.enrollment()
        if e.mdm == .on || e.dep == .on {
            return [Finding(id: "device-managed", category: .device, severity: .info, title: "This Mac is managed by an organization",
                            why: "A company or school can install apps, change settings and see details about this Mac. That's normal for a work or school Mac. If this is a personal Mac and you didn't enrol it yourself, ask who set it up.",
                            fixes: [.settings("Open Privacy & Security", SettingsPane.privacy)])]
        }
        if e.mdm == .off && e.dep == .off {
            return [Finding(id: "device-unmanaged", category: .device, severity: .ok, title: "Nobody else manages this Mac",
                            why: "It isn't enrolled in any company or school device-management system.")]
        }
        return []
    }

    // MARK: basics

    func basics() -> [Finding] {
        var out: [Finding] = []
        switch probe.fileVault() {
        case .on: out.append(Finding(id: "basics-filevault", category: .basics, severity: .ok, title: "Your files are encrypted (FileVault is on)",
                                     why: "If someone gets hold of this Mac they cannot read your files without your password."))
        case .off: out.append(Finding(id: "basics-filevault", category: .basics, severity: .attention, title: "FileVault is off",
                                      why: "Anyone who gets hold of this Mac, lost or stolen, can read what is on it. Turning FileVault on scrambles your files so only your password opens them.",
                                      fixes: [.settings("Open Privacy & Security", SettingsPane.privacy)]))
        case .unknown: break
        }
        if probe.gatekeeper() == .off {
            out.append(Finding(id: "basics-gatekeeper", category: .basics, severity: .alert, title: "The Mac's app safety check is switched off",
                               why: "Gatekeeper normally stops unknown or tampered programs from opening. Someone (or something) turned it off. Unless you did this on purpose, ask for help.",
                               fixes: [.settings("Open Privacy & Security", SettingsPane.privacy)]))
        }
        if probe.sip() == .off {
            out.append(Finding(id: "basics-sip", category: .basics, severity: .alert, title: "System Integrity Protection is off",
                               why: "This is the Mac's core self-defence. It is only turned off on purpose by developers. If you don't know why it is off, ask for help."))
        }
        if probe.gatekeeper() == .on && probe.sip() == .on {
            out.append(Finding(id: "basics-system", category: .basics, severity: .ok, title: "The Mac's built-in protections are on",
                               why: "Gatekeeper and System Integrity Protection are both active."))
        }
        if probe.firewall() == .off {
            out.append(Finding(id: "basics-firewall", category: .basics, severity: .info, title: "The firewall is off",
                               why: "The firewall blocks other computers from connecting to programs on this Mac. At home behind a router it matters less; it is worth turning on when you use public Wi-Fi.",
                               fixes: [.settings("Open Network settings", SettingsPane.network)]))
        }
        if let u = probe.autoLoginUser() {
            out.append(Finding(id: "basics-autologin", category: .basics, severity: .attention, title: "This Mac signs in by itself",
                               why: "Anyone who switches it on gets into the account “\(u)” without a password.",
                               fixes: [.settings("Open Users & Groups", SettingsPane.users)]))
        }
        if probe.guestEnabled() == .on {
            out.append(Finding(id: "basics-guest", category: .basics, severity: .info, title: "The guest account is on",
                               why: "Anyone can use this Mac as a guest without a password. Their files disappear when they log out, but turn it off if you don't need it.",
                               fixes: [.settings("Open Users & Groups", SettingsPane.users)]))
        }
        if let s = probe.screenLockSeconds() {
            if s < 0 { out.append(Finding(id: "basics-screenlock", category: .basics, severity: .attention, title: "The screen never asks for a password",
                                          why: "When you walk away, anyone can sit down and use the Mac. Set it to ask for your password soon after the screen turns off.",
                                          fixes: [.settings("Open Privacy & Security", SettingsPane.privacy)])) }
            else if s > 900 { out.append(Finding(id: "basics-screenlock", category: .basics, severity: .info, title: "The Mac waits \(s / 60) minutes before asking for your password",
                                                 why: "A shorter wait is safer if you leave the Mac in a shared place.")) }
        }
        return out
    }

    // MARK: internet settings

    static let popularDomains = ["paypal", "apple.com", "icloud", "google", "microsoft", "amazon", "facebook", "instagram", "chase", "wellsfargo",
                                 "bankofamerica", "citibank", "americanexpress", "venmo", "cash.app", "coinbase", "binance", "irs.gov", "ssa.gov", "barclays", "hsbc", "lloyds"]

    func network() -> [Finding] {
        var out: [Finding] = []
        let proxies = probe.proxies()
        if !proxies.isEmpty {
            out.append(Finding(id: "network-proxy", category: .network, severity: .attention, title: "Your internet traffic goes through a proxy",
                               why: "A proxy sits between you and websites and can see or change what passes through. Companies use them legitimately; so do people who want to spy on you. If you didn't set this up, or this isn't a work Mac, ask for help.",
                               detail: proxies, fixes: [.settings("Open Network settings", SettingsPane.network)]))
        }
        var redirected: [String] = [], odd: [String] = []
        for h in probe.hostsEntries() {
            let quiet = ["127.0.0.1", "::1", "0.0.0.0", "255.255.255.255", "fe80::1%lo0"].contains(h.ip)
            let names = h.names.filter { !["localhost", "broadcasthost", "ip6-localhost", "ip6-loopback"].contains($0) }
            for n in names {
                let popular = Audit.popularDomains.contains { n.lowercased().contains($0) }
                if popular && !(h.ip == "127.0.0.1" || h.ip == "0.0.0.0" || h.ip == "::1") { redirected.append("\(n) → \(h.ip)") }
                else if !quiet { odd.append("\(n) → \(h.ip)") }
            }
        }
        if !redirected.isEmpty {
            out.append(Finding(id: "network-hosts", category: .network, severity: .alert, title: "A well-known website is being sent somewhere else",
                               why: "A hidden settings file on this Mac sends the address of a familiar website (a bank, Apple, Google…) to a different computer. That is a classic way to steal passwords. Ask someone you trust to look at this file (/etc/hosts) before you sign in to anything.",
                               detail: redirected))
        } else if !odd.isEmpty {
            out.append(Finding(id: "network-hosts", category: .network, severity: .attention, title: "Some website addresses are redirected on this Mac",
                               why: "The file /etc/hosts overrides where some names point. Developers do this on purpose; otherwise it can hide a problem.",
                               detail: odd))
        }
        return out
    }

    // MARK: things that start by themselves

    static let interpreters: Set<String> = ["sh", "bash", "zsh", "python", "python3", "perl", "ruby", "osascript", "node", "env", "open", "php"]
    static let appleRoots = ["/System/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/"]

    func startup() -> [Finding] {
        let items = probe.launchItems()
        var suspicious: [String] = [], stale: [String] = []
        var developers: [String: Int] = [:]
        var unknownDeveloperCount = 0
        for it in items {
            guard var prog = it.program, !prog.isEmpty else { continue }
            if Audit.appleRoots.contains(where: { prog.hasPrefix($0) }) && !Audit.interpreters.contains((prog as NSString).lastPathComponent) { continue }
            var viaInterpreter = false
            if Audit.interpreters.contains((prog as NSString).lastPathComponent) {
                viaInterpreter = true
                if let script = it.arguments.first(where: { $0.hasPrefix("/") }) { prog = script } else { continue }
            }
            let location = Audit.suspiciousLocation(prog)
            if !probe.fileExists(prog) {
                stale.append("\(it.label) → \(prog)"); continue
            }
            if viaInterpreter {
                if location != nil { suspicious.append("\(it.label) runs a script from \(location!): \(prog)") }
                continue
            }
            switch probe.signature(of: prog) {
            case .apple, .unreadable: continue
            case .unsigned: suspicious.append("\(it.label) is not signed by any developer: \(prog)")
            case .adhoc: if let l = location { suspicious.append("\(it.label) is unsigned code in \(l): \(prog)") } else { developers["Unsigned (self-built)", default: 0] += 1 }
            case .developer(let name, _):
                developers[name, default: 0] += 1
                if let l = location { suspicious.append("\(it.label) starts from \(l): \(prog)") }
            }
            if case .developer = probe.signature(of: prog) {} else { unknownDeveloperCount += 1 }
        }
        var out: [Finding] = []
        if !suspicious.isEmpty {
            out.append(Finding(id: "startup-suspicious", category: .startup, severity: .attention,
                               title: suspicious.count == 1 ? "Something unusual starts by itself" : "\(suspicious.count) unusual things start by themselves",
                               why: "These programs run automatically when you log in, but they are not signed by a known developer or they live in a place normal software doesn't use. Many are harmless (a tool you built or downloaded), but this is where unwanted software hides. If you don't recognise one, ask for help.",
                               detail: Array(suspicious.prefix(10)), fixes: [.settings("Open Login Items", SettingsPane.loginItems)]))
        }
        if !developers.isEmpty {
            let top = developers.sorted { ($0.value, $1.key) > ($1.value, $0.key) }
            out.append(Finding(id: "startup-summary", category: .startup, severity: .info,
                               title: "\(developers.values.reduce(0, +)) programs from \(developers.count) developers start by themselves",
                               why: "Normal for a Mac in use: updaters, sync tools and menu-bar apps. Look through them occasionally and remove what you no longer use.",
                               detail: top.prefix(12).map { "\($0.key): \($0.value)" }, fixes: [.settings("Open Login Items", SettingsPane.loginItems)]))
        }
        if !stale.isEmpty {
            out.append(Finding(id: "startup-stale", category: .startup, severity: .info,
                               title: "\(stale.count) leftover startup items point to programs that are gone",
                               why: "Harmless clutter left behind by apps that were deleted without their helpers.", detail: Array(stale.prefix(10))))
        }
        _ = unknownDeveloperCount
        return out
    }

    static func suspiciousLocation(_ path: String) -> String? {
        for (prefix, name) in [("/tmp/", "a temporary folder"), ("/private/tmp/", "a temporary folder"), ("/var/tmp/", "a temporary folder"),
                               ("/private/var/tmp/", "a temporary folder"), ("/var/folders/", "a temporary folder"), ("/Users/Shared/", "the shared folder")]
        where path.hasPrefix(prefix) { return name }
        if path.contains("/.") { return "a hidden folder" }
        return nil
    }

    // MARK: what apps may see and do

    static let capabilities: [(service: String, label: String)] = [
        ("kTCCServiceScreenCapture", "record your screen"),
        ("kTCCServiceAccessibility", "control your Mac"),
        ("kTCCServiceListenEvent", "watch what you type"),
        ("kTCCServicePostEvent", "type for you"),
        ("kTCCServiceSystemPolicyAllFiles", "read all your files"),
    ]

    func permissions() -> [Finding] {
        guard let grants = probe.tccGrants() else {
            return [Finding(id: "permissions-unreadable", category: .permissions, severity: .info,
                            title: "Warden can't see which apps may record your screen or control your Mac",
                            why: "macOS keeps that list private. To include it in the check, allow Warden under Privacy & Security → Full Disk Access. Warden only reads the list; nothing leaves your Mac.",
                            fixes: [.settings("Open Full Disk Access", SettingsPane.fullDisk)])]
        }
        let names = Dictionary(probe.installedApps().filter { !$0.bundleID.isEmpty }.map { ($0.bundleID, $0.name) }, uniquingKeysWith: { a, _ in a })
        func display(_ g: TCCGrant) -> String { g.clientIsPath ? (g.client as NSString).lastPathComponent : (names[g.client] ?? g.client) }
        var out: [Finding] = []
        var byCapability: [String: Set<String>] = [:]
        var remote: [String: (tool: RemoteTool, caps: Set<String>)] = [:]
        for g in grants where !g.client.hasPrefix("com.apple.") {
            guard let cap = Audit.capabilities.first(where: { $0.service == g.service }) else { continue }
            if let t = KnownTools.match(bundleID: g.clientIsPath ? nil : g.client, name: display(g), path: g.clientIsPath ? g.client : nil), !t.builtIn {
                remote[t.id, default: (t, [])].caps.insert(cap.label)
            } else {
                byCapability[cap.label, default: []].insert(display(g))
            }
        }
        for (id, r) in remote.sorted(by: { $0.key < $1.key }) {
            let sees = r.caps.contains("record your screen"), controls = r.caps.contains("control your Mac") || r.caps.contains("type for you")
            guard sees || controls else { continue }
            out.append(Finding(id: "permissions-remote-\(id)", category: .permissions, severity: .attention,
                               title: "\(r.tool.name) is allowed to " + [sees ? "record your screen" : nil, controls ? "control your Mac" : nil].compactMap { $0 }.joined(separator: " and "),
                               why: "You (or someone using this Mac) already gave \(r.tool.name) the permissions it needs to see and control everything on screen. If you no longer use it, remove the permission, or delete the program.",
                               fixes: [.settings("Open Screen Recording", SettingsPane.screenRecording), .settings("Open Accessibility", SettingsPane.accessibility)]))
        }
        let lines = Audit.capabilities.compactMap { c -> String? in
            guard let n = byCapability[c.label], !n.isEmpty else { return nil }
            return "Can \(c.label): " + n.sorted().prefix(8).joined(separator: ", ") + (n.count > 8 ? " and \(n.count - 8) more" : "")
        }
        if !lines.isEmpty {
            out.append(Finding(id: "permissions-sensitive", category: .permissions, severity: .info,
                               title: "Some apps may record your screen or control your Mac",
                               why: "Screen-sharing, window-management and password apps legitimately need these. Look through the list and remove access for anything you don't recognise or use.",
                               detail: lines, fixes: [.settings("Open Privacy & Security", SettingsPane.privacy)]))
        }
        return out
    }

    // MARK: accounts

    func accounts() -> [Finding] {
        var out: [Finding] = []
        let admins = probe.adminUsers()
        if admins.count > 1 {
            out.append(Finding(id: "accounts-admins", category: .accounts, severity: .attention, title: "\(admins.count) accounts can change anything on this Mac",
                               why: "Administrator accounts have full control. If one of these isn't yours or someone you trust, a scammer or malware may have created it.",
                               detail: admins, fixes: [.settings("Open Users & Groups", SettingsPane.users)]))
        } else if admins.count == 1 {
            out.append(Finding(id: "accounts-admins", category: .accounts, severity: .ok, title: "Only one administrator account",
                               why: "“\(admins[0])” is the only account that can change everything."))
        }
        let cutoff = probe.now().addingTimeInterval(-30 * 86400)
        let remote = probe.recentLogins().filter { $0.host != nil && ($0.when ?? .distantPast) > cutoff }
        if !remote.isEmpty {
            let f = DateFormatter(); f.dateFormat = "MMM d, HH:mm"
            out.append(Finding(id: "accounts-remote-logins", category: .accounts, severity: .attention, title: "Someone signed in from another computer",
                               why: "These sign-ins came over the network (Remote Login / SSH), not from the keyboard. If you didn't do this, turn Remote Login off and change your password.",
                               detail: remote.prefix(6).map { "\($0.user) from \($0.host ?? "?") — \($0.when.map { f.string(from: $0) } ?? "")" },
                               fixes: [.settings("Open Sharing settings", SettingsPane.sharing)]))
        }
        return out
    }
}
