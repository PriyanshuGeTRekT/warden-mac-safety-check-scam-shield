import Foundation
import Darwin

/// Everything Warden wants to know about the Mac. A fake implementation makes every scenario testable.
public protocol SystemProbe: AnyObject {
    func now() -> Date
    func listeners() -> [Listener]
    func installedApps() -> [InstalledApp]
    func runningProcesses() -> [RunningProcess]
    func establishedConnections() -> [Connection]
    /// Starts sampling per-process network counters in the background (idempotent, does not block).
    func startTrafficStream()
    /// The newest sample, with the moment it was taken. nil until the first sample exists.
    func trafficSnapshot() -> TrafficSnapshot?
    func launchItems() -> [LaunchItem]
    func signature(of path: String) -> CodeSignature
    func fileExists(_ path: String) -> Bool
    func enrollment() -> (dep: Tri, mdm: Tri)
    func fileVault() -> Tri
    func sip() -> Tri
    func gatekeeper() -> Tri
    func firewall() -> Tri
    func autoLoginUser() -> String?
    func guestEnabled() -> Tri
    func proxies() -> [String]
    func hostsEntries() -> [HostEntry]
    func recentLogins() -> [LoginRecord]
    func adminUsers() -> [String]
    /// nil = the permission database could not be read (Full Disk Access is missing)
    func tccGrants() -> [TCCGrant]?
    func screenLockSeconds() -> Int?
}

// MARK: - a pretend Mac

public final class FakeProbe: SystemProbe {
    public var date = Date()
    public var listenerList: [Listener] = []
    public var apps: [InstalledApp] = []
    public var procs: [RunningProcess] = []
    public var conns: [Connection] = []
    public var trafficByPid: [Int32: Traffic] = [:]
    /// Processes that keep sending data at this many bytes per second (counters grow with the real clock). For demos and app tests.
    public var liveStreams: [Int32: Double] = [:]
    private let streamEpoch = Date()
    public var launch: [LaunchItem] = []
    public var signatures: [String: CodeSignature] = [:]
    public var dep: Tri = .off
    public var mdm: Tri = .off
    public var fileVaultState: Tri = .on
    public var sipState: Tri = .on
    public var gatekeeperState: Tri = .on
    public var firewallState: Tri = .on
    public var autoLogin: String?
    public var guest: Tri = .off
    public var proxyList: [String] = []
    public var hosts: [HostEntry] = [HostEntry(ip: "127.0.0.1", names: ["localhost"]), HostEntry(ip: "255.255.255.255", names: ["broadcasthost"]),
                                     HostEntry(ip: "::1", names: ["localhost"])]
    public var logins: [LoginRecord] = []
    public var admins: [String] = ["dot"]
    public var tcc: [TCCGrant]? = []
    public var screenLock: Int? = 300
    /// nil = every path exists
    public var existingPaths: Set<String>?

    public init() {}

    public func now() -> Date { date }
    public func listeners() -> [Listener] { listenerList }
    public func installedApps() -> [InstalledApp] { apps }
    public func runningProcesses() -> [RunningProcess] { procs }
    public func establishedConnections() -> [Connection] { conns }
    public func startTrafficStream() {}
    public func trafficSnapshot() -> TrafficSnapshot? {
        if liveStreams.isEmpty { return TrafficSnapshot(at: date, byPid: trafficByPid) }
        let t = Date()
        var m = trafficByPid
        for (pid, rate) in liveStreams { m[pid] = Traffic(inBytes: 0, outBytes: UInt64(rate * t.timeIntervalSince(streamEpoch))) }
        return TrafficSnapshot(at: t, byPid: m)
    }
    public func launchItems() -> [LaunchItem] { launch }
    public func signature(of path: String) -> CodeSignature { signatures[path] ?? .apple }
    public func fileExists(_ path: String) -> Bool { existingPaths?.contains(path) ?? true }
    public func enrollment() -> (dep: Tri, mdm: Tri) { (dep, mdm) }
    public func fileVault() -> Tri { fileVaultState }
    public func sip() -> Tri { sipState }
    public func gatekeeper() -> Tri { gatekeeperState }
    public func firewall() -> Tri { firewallState }
    public func autoLoginUser() -> String? { autoLogin }
    public func guestEnabled() -> Tri { guest }
    public func proxies() -> [String] { proxyList }
    public func hostsEntries() -> [HostEntry] { hosts }
    public func recentLogins() -> [LoginRecord] { logins }
    public func adminUsers() -> [String] { admins }
    public func tccGrants() -> [TCCGrant]? { tcc }
    public func screenLockSeconds() -> Int? { screenLock }
}

// MARK: - running commands

enum Shell {
    /// Runs a command with a time limit. Output goes through temporary files, so a chatty command cannot block on a full pipe.
    @discardableResult
    static func run(_ path: String, _ args: [String], timeout: TimeInterval = 10) -> (status: Int32, out: String, err: String) {
        let id = UUID().uuidString
        let outURL = URL(fileURLWithPath: NSTemporaryDirectory() + "warden-\(id).out")
        let errURL = URL(fileURLWithPath: NSTemporaryDirectory() + "warden-\(id).err")
        FileManager.default.createFile(atPath: outURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        FileManager.default.createFile(atPath: errURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        defer { try? FileManager.default.removeItem(at: outURL); try? FileManager.default.removeItem(at: errURL) }
        guard let oh = try? FileHandle(forWritingTo: outURL), let eh = try? FileHandle(forWritingTo: errURL) else { return (-1, "", "no temp file") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.standardOutput = oh; p.standardError = eh; p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { try? oh.close(); try? eh.close(); return (-1, "", "\(error)") }
        let deadline = Date().addingTimeInterval(timeout)
        while p.isRunning && Date() < deadline { usleep(15_000) }
        if p.isRunning {
            p.terminate(); usleep(150_000)
            if p.isRunning { kill(p.processIdentifier, SIGKILL) }
        }
        p.waitUntilExit()
        try? oh.close(); try? eh.close()
        let out = (try? String(contentsOf: outURL, encoding: .utf8)) ?? ""
        let err = (try? String(contentsOf: errURL, encoding: .utf8)) ?? ""
        return (p.terminationStatus, out, err)
    }
}

// MARK: - the real Mac

public final class LiveProbe: SystemProbe {
    private var sigCache: [String: CodeSignature] = [:]
    private let lock = NSLock()

    public init() {}

    public func now() -> Date { Date() }

    public func listeners() -> [Listener] { Parse.listeners(netstat: Shell.run("/usr/sbin/netstat", ["-an", "-p", "tcp"]).out) }

    public func installedApps() -> [InstalledApp] {
        var out: [InstalledApp] = []
        let fm = FileManager.default
        for root in ["/Applications", "/Applications/Utilities", NSHomeDirectory() + "/Applications"] {
            guard let items = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for item in items where item.hasSuffix(".app") {
                let path = root + "/" + item
                let info = NSDictionary(contentsOfFile: path + "/Contents/Info.plist") as? [String: Any]
                let id = (info?["CFBundleIdentifier"] as? String) ?? ""
                let name = (info?["CFBundleDisplayName"] as? String) ?? (info?["CFBundleName"] as? String) ?? String(item.dropLast(4))
                let date = (try? fm.attributesOfItem(atPath: path))?[.creationDate] as? Date
                out.append(InstalledApp(bundleID: id, name: name, path: path, installed: date))
            }
        }
        return out
    }

    public func runningProcesses() -> [RunningProcess] {
        var out: [RunningProcess] = []
        for line in Shell.run("/bin/ps", ["-axo", "pid=,comm="]).out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard let sp = t.firstIndex(of: " "), let pid = Int32(t[..<sp]) else { continue }
            out.append(RunningProcess(pid: pid, command: t[t.index(after: sp)...].trimmingCharacters(in: .whitespaces)))
        }
        return out
    }

    public func establishedConnections() -> [Connection] {
        Parse.established(lsof: Shell.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:ESTABLISHED"], timeout: 15).out)
    }

    public func startTrafficStream() { NettopStream.shared.start() }
    /// Stops the background sampler. Call when the program exits (it also reaps strays left by a previous crash).
    public static func shutdown() { NettopStream.shared.stop() }
    public func trafficSnapshot() -> TrafficSnapshot? { NettopStream.shared.start(); return NettopStream.shared.latest }

    public func launchItems() -> [LaunchItem] {
        var out: [LaunchItem] = []
        let dirs: [(String, LaunchItem.Scope)] = [(NSHomeDirectory() + "/Library/LaunchAgents", .userAgent),
                                                  ("/Library/LaunchAgents", .systemAgent), ("/Library/LaunchDaemons", .systemDaemon)]
        let fm = FileManager.default
        for (dir, scope) in dirs {
            for f in ((try? fm.contentsOfDirectory(atPath: dir)) ?? []) where f.hasSuffix(".plist") {
                let path = dir + "/" + f
                guard let d = NSDictionary(contentsOfFile: path) as? [String: Any] else { continue }
                let label = (d["Label"] as? String) ?? String(f.dropLast(6))
                let args = (d["ProgramArguments"] as? [String]) ?? []
                let program = (d["Program"] as? String) ?? args.first
                out.append(LaunchItem(path: path, label: label, program: program, arguments: Array(args.dropFirst()), scope: scope))
            }
        }
        return out
    }

    public func signature(of path: String) -> CodeSignature {
        lock.lock(); if let c = sigCache[path] { lock.unlock(); return c }; lock.unlock()
        let r = Shell.run("/usr/bin/codesign", ["-dv", "--verbose=2", path], timeout: 6)
        let sig = Parse.codesign(r.out + "\n" + r.err)
        lock.lock(); sigCache[path] = sig; lock.unlock()
        return sig
    }

    public func fileExists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }

    public func enrollment() -> (dep: Tri, mdm: Tri) {
        let r = Shell.run("/usr/bin/profiles", ["status", "-type", "enrollment"], timeout: 8)
        return Parse.enrollment(r.out + r.err)
    }

    public func fileVault() -> Tri {
        let r = Shell.run("/usr/bin/fdesetup", ["status"], timeout: 6)
        return Parse.contains(r.out + r.err, on: ["FileVault is On"], off: ["FileVault is Off"])
    }

    public func sip() -> Tri {
        let r = Shell.run("/usr/bin/csrutil", ["status"], timeout: 6)
        return Parse.contains(r.out + r.err, on: ["status: enabled"], off: ["status: disabled"])
    }

    public func gatekeeper() -> Tri {
        let r = Shell.run("/usr/sbin/spctl", ["--status"], timeout: 6)
        return Parse.contains(r.out + r.err, on: ["assessments enabled"], off: ["assessments disabled"])
    }

    public func firewall() -> Tri {
        let r = Shell.run("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--getglobalstate"], timeout: 6)
        return Parse.contains(r.out + r.err, on: ["State = 1", "State = 2", "enabled"], off: ["State = 0", "disabled"])
    }

    public func autoLoginUser() -> String? {
        let r = Shell.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"], timeout: 5)
        let v = r.out.trimmingCharacters(in: .whitespacesAndNewlines)
        return r.status == 0 && !v.isEmpty ? v : nil
    }

    public func guestEnabled() -> Tri {
        let r = Shell.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"], timeout: 5)
        let v = r.out.trimmingCharacters(in: .whitespacesAndNewlines)
        return r.status != 0 ? .off : (v == "1" ? .on : .off)
    }

    public func proxies() -> [String] { Parse.proxies(scutil: Shell.run("/usr/sbin/scutil", ["--proxy"], timeout: 6).out) }

    public func hostsEntries() -> [HostEntry] {
        Parse.hosts((try? String(contentsOfFile: "/etc/hosts", encoding: .utf8)) ?? "")
    }

    public func recentLogins() -> [LoginRecord] {
        Parse.logins(last: Shell.run("/usr/bin/last", ["-n", "300"], timeout: 8).out, now: Date())
    }

    public func adminUsers() -> [String] {
        Parse.admins(dscl: Shell.run("/usr/bin/dscl", [".", "-read", "/Groups/admin", "GroupMembership"], timeout: 6).out)
    }

    public func tccGrants() -> [TCCGrant]? {
        var all: [TCCGrant] = []
        var readAny = false
        for p in [NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db", "/Library/Application Support/com.apple.TCC/TCC.db"] {
            if let g = TCC.read(path: p) { readAny = true; all += g }
        }
        return readAny ? all : nil
    }

    public func screenLockSeconds() -> Int? {
        let r = Shell.run("/usr/sbin/sysadminctl", ["-screenLock", "status"], timeout: 6)
        return Parse.screenLock(r.out + r.err)
    }
}


// MARK: - network counters, streamed

/// `nettop` needs about five seconds to start, so asking it once per check would stall the shield. Instead one `nettop`
/// runs in the background (through a pseudo-terminal, otherwise it buffers its output) and the newest sample is kept.
/// It costs next to nothing: a sample per second, no admin rights needed.
final class NettopStream {
    static let shared = NettopStream()

    private let lock = NSLock()
    private var process: Process?
    private var source: DispatchSourceRead?
    private var snapshot: TrafficSnapshot?
    private var pending: [Int32: Traffic] = [:]
    private var pendingAt: Date?
    private var carry = Data()
    private var registeredExit = false
    private var reaped = false

    var latest: TrafficSnapshot? { lock.lock(); defer { lock.unlock() }; return snapshot }

    /// A Warden that was killed outright cannot clean up after itself. Its sampler is recognisable (parent is launchd, exact
    /// arguments), so the next start removes it.
    @discardableResult
    func reapStrays() -> Int {
        // -ww: ps cuts the arguments at 80 columns otherwise, and the match would never succeed
        let r = Shell.run("/bin/ps", ["-wwaxo", "pid=,ppid=,args="], timeout: 5)
        var n = 0
        for line in r.out.split(separator: "\n") {
            let t = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard t.count == 3, t[1] == "1", t[2].contains("nettop -P -L 0 -s 1 -J bytes_in"), let pid = Int32(t[0]) else { continue }
            kill(pid, SIGTERM); n += 1
        }
        return n
    }

    func start() {
        lock.lock(); defer { lock.unlock() }
        if let p = process, p.isRunning { return }
        if !reaped { reaped = true; reapStrays() }
        let master = posix_openpt(O_RDWR | O_NOCTTY)
        guard master >= 0, grantpt(master) == 0, unlockpt(master) == 0, let name = ptsname(master) else { if master >= 0 { close(master) }; return }
        let slave = open(name, O_RDWR | O_NOCTTY)
        guard slave >= 0 else { close(master); return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
        p.arguments = ["-P", "-L", "0", "-s", "1", "-J", "bytes_in,bytes_out"]
        let h = FileHandle(fileDescriptor: slave, closeOnDealloc: false)
        p.standardOutput = h; p.standardError = h; p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { close(master); close(slave); return }
        close(slave)
        process = p
        carry = Data(); pending = [:]; pendingAt = nil
        let src = DispatchSource.makeReadSource(fileDescriptor: master, queue: DispatchQueue(label: "app.warden.nettop"))
        src.setEventHandler { [weak self] in self?.read(master) }
        src.setCancelHandler { close(master) }
        src.resume()
        source = src
        if !registeredExit { registeredExit = true; atexit { NettopStream.shared.stop() } }
    }

    func stop() {
        lock.lock(); defer { lock.unlock() }
        source?.cancel(); source = nil
        if let p = process, p.isRunning { p.terminate() }
        process = nil
    }

    private func read(_ fd: Int32) {
        var buf = [UInt8](repeating: 0, count: 65_536)
        let n = Darwin.read(fd, &buf, buf.count)
        guard n > 0 else { lock.lock(); source?.cancel(); source = nil; process = nil; lock.unlock(); return }
        carry.append(contentsOf: buf[0..<n])
        while let nl = carry.firstIndex(of: 10) {
            let line = String(decoding: carry[carry.startIndex..<nl], as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            carry.removeSubrange(carry.startIndex...nl)
            handle(line)
        }
    }

    private func handle(_ line: String) {
        lock.lock(); defer { lock.unlock() }
        if line.hasPrefix(",bytes_in") {
            if let at = pendingAt, !pending.isEmpty { snapshot = TrafficSnapshot(at: at, byPid: pending) }
            pending = [:]; pendingAt = Date()
        } else {
            for (pid, t) in Parse.nettop(line) { pending[pid] = t }
        }
    }
}
