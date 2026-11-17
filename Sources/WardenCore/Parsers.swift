import Foundation
import SQLite3

public enum Tri: Equatable { case on, off, unknown }

public struct Listener: Equatable, Hashable {
    public let port: Int
    /// Bound to 127.0.0.1 / ::1 only: nobody else can reach it.
    public let localOnly: Bool
    public init(port: Int, localOnly: Bool) { self.port = port; self.localOnly = localOnly }
}

public struct InstalledApp: Equatable {
    public let bundleID: String
    public let name: String
    public let path: String
    public let installed: Date?
    public init(bundleID: String, name: String, path: String, installed: Date? = nil) {
        self.bundleID = bundleID; self.name = name; self.path = path; self.installed = installed
    }
}

public struct RunningProcess: Equatable {
    public let pid: Int32
    /// Full executable path when the system gives one.
    public let command: String
    public var name: String { (command as NSString).lastPathComponent }
    public init(pid: Int32, command: String) { self.pid = pid; self.command = command }
}

public struct Connection: Equatable {
    public let pid: Int32
    public let command: String
    public let remoteHost: String
    public let remotePort: Int
    public init(pid: Int32, command: String, remoteHost: String, remotePort: Int) {
        self.pid = pid; self.command = command; self.remoteHost = remoteHost; self.remotePort = remotePort
    }
    public var isLocal: Bool { Parse.isPrivate(remoteHost) }
}

public struct LaunchItem: Equatable {
    public enum Scope: String { case userAgent, systemAgent, systemDaemon }
    public let path: String
    public let label: String
    public let program: String?
    public let arguments: [String]
    public let scope: Scope
    public init(path: String, label: String, program: String?, arguments: [String] = [], scope: Scope) {
        self.path = path; self.label = label; self.program = program; self.arguments = arguments; self.scope = scope
    }
}

public struct HostEntry: Equatable {
    public let ip: String
    public let names: [String]
    public init(ip: String, names: [String]) { self.ip = ip; self.names = names }
}

public struct LoginRecord: Equatable {
    public let user: String
    public let tty: String
    public let host: String?
    public let when: Date?
    public init(user: String, tty: String, host: String?, when: Date?) { self.user = user; self.tty = tty; self.host = host; self.when = when }
}

public struct TCCGrant: Equatable {
    public let service: String
    public let client: String
    public let clientIsPath: Bool
    public let lastModified: Date?
    public init(service: String, client: String, clientIsPath: Bool = false, lastModified: Date? = nil) {
        self.service = service; self.client = client; self.clientIsPath = clientIsPath; self.lastModified = lastModified
    }
}

public enum CodeSignature: Equatable {
    case unsigned, adhoc, apple, unreadable
    case developer(name: String, team: String)
}

public struct Traffic: Equatable {
    public var inBytes: UInt64
    public var outBytes: UInt64
    public init(inBytes: UInt64, outBytes: UInt64) { self.inBytes = inBytes; self.outBytes = outBytes }
}

public struct TrafficSnapshot: Equatable {
    public var at: Date
    public var byPid: [Int32: Traffic]
    public init(at: Date, byPid: [Int32: Traffic]) { self.at = at; self.byPid = byPid }
}

/// Pure functions that turn the text of system commands into data. Kept free of any I/O so they can be tested
/// against real samples.
public enum Parse {
    public static func listeners(netstat: String) -> [Listener] {
        var seen = Set<Listener>()
        for line in netstat.split(separator: "\n") where line.contains("LISTEN") {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true)
            guard cols.count >= 6, cols[0].hasPrefix("tcp") else { continue }
            let local = String(cols[3])
            guard let dot = local.lastIndex(of: "."), let port = Int(local[local.index(after: dot)...]) else { continue }
            let host = local[..<dot]
            let localOnly = host.hasPrefix("127.") || host == "::1" || host.hasPrefix("localhost")
            seen.insert(Listener(port: port, localOnly: localOnly))
        }
        return seen.sorted { ($0.port, $0.localOnly ? 1 : 0) < ($1.port, $1.localOnly ? 1 : 0) }
    }

    /// `lsof -nP -iTCP -sTCP:ESTABLISHED`
    public static func established(lsof: String) -> [Connection] {
        var out: [Connection] = []
        for line in lsof.split(separator: "\n") where line.contains("(ESTABLISHED)") {
            let toks = line.split(separator: " ", omittingEmptySubsequences: true)
            guard toks.count >= 9, let pid = Int32(toks[1]) else { continue }
            guard let name = toks.first(where: { $0.contains("->") }) else { continue }
            let remote = String(name.components(separatedBy: "->")[1])
            var host = remote, port = 0
            if remote.hasPrefix("["), let end = remote.firstIndex(of: "]") {
                host = String(remote[remote.index(after: remote.startIndex)..<end])
                port = Int(remote[remote.index(after: end)...].dropFirst()) ?? 0 // skip the ':' after the bracket
            } else if let c = remote.lastIndex(of: ":") {
                host = String(remote[..<c]); port = Int(remote[remote.index(after: c)...]) ?? 0
            }
            let cmd = String(toks[0]).replacingOccurrences(of: "\\x20", with: " ")
            out.append(Connection(pid: pid, command: cmd, remoteHost: host, remotePort: port))
        }
        return out
    }

    /// `last` lines: `user tty [host] Dow Mon d HH:mm …`. Only entries with a host are remote logins.
    public static func logins(last: String, now: Date = Date()) -> [LoginRecord] {
        let days: Set<String> = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "EEE MMM d HH:mm yyyy"
        let year = Calendar.current.component(.year, from: now)
        var out: [LoginRecord] = []
        for line in last.split(separator: "\n") {
            let t = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard t.count >= 6, !["reboot", "shutdown", "wtmp", "runlevel"].contains(t[0]) else { continue }
            var i = 2
            var host: String?
            if !days.contains(t[i]) { host = t[i]; i += 1 }
            guard i + 3 < t.count, days.contains(t[i]) else { continue }
            var when = f.date(from: "\(t[i]) \(t[i + 1]) \(t[i + 2]) \(t[i + 3]) \(year)")
            if let w = when, w > now.addingTimeInterval(86400) { when = Calendar.current.date(byAdding: .year, value: -1, to: w) }
            out.append(LoginRecord(user: t[0], tty: t[1], host: host, when: when))
        }
        return out
    }

    /// `scutil --proxy`
    public static func proxies(scutil: String) -> [String] {
        var kv: [String: String] = [:]
        for line in scutil.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2, !parts[1].hasPrefix("<") { kv[parts[0]] = parts[1] }
        }
        var out: [String] = []
        for p in ["HTTP", "HTTPS", "FTP", "SOCKS", "RTSP", "Gopher"] where kv["\(p)Enable"] == "1" {
            out.append("\(p) proxy: \(kv["\(p)Proxy"] ?? "?")" + (kv["\(p)Port"].map { ":\($0)" } ?? ""))
        }
        if kv["ProxyAutoConfigEnable"] == "1" { out.append("Automatic proxy script: \(kv["ProxyAutoConfigURLString"] ?? "?")") }
        return out
    }

    public static func hosts(_ s: String) -> [HostEntry] {
        var out: [HostEntry] = []
        for raw in s.split(separator: "\n") {
            let line = raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
            let t = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            if t.count >= 2 { out.append(HostEntry(ip: t[0], names: Array(t.dropFirst()))) }
        }
        return out
    }

    /// `dscl . -read /Groups/admin GroupMembership`
    public static func admins(dscl: String) -> [String] {
        guard let r = dscl.range(of: "GroupMembership:") else { return [] }
        return dscl[r.upperBound...].split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init)
            .filter { $0 != "root" && !$0.hasPrefix("_") }
    }

    /// `codesign -dv --verbose=2 <path>` (it writes to stderr)
    public static func codesign(_ s: String) -> CodeSignature {
        if s.contains("not signed at all") { return .unsigned }
        if s.contains("Signature=adhoc") { return .adhoc }
        var team = ""
        for line in s.split(separator: "\n") where line.hasPrefix("TeamIdentifier=") {
            team = String(line.dropFirst("TeamIdentifier=".count)); if team == "not set" { team = "" }
        }
        for line in s.split(separator: "\n") where line.hasPrefix("Authority=") {
            let a = String(line.dropFirst("Authority=".count))
            if a == "Software Signing" || a.hasPrefix("Apple Code Signing") || a == "Apple Mac OS Application Signing" && team.isEmpty { return .apple }
            if a.hasPrefix("Developer ID Application: ") || a.hasPrefix("Apple Development: ") || a.hasPrefix("Mac Developer: ") || a.hasPrefix("3rd Party Mac Developer Application: ") {
                var name = a.components(separatedBy: ": ").dropFirst().joined(separator: ": ")
                if let r = name.range(of: " (", options: .backwards), name.hasSuffix(")") { name = String(name[..<r.lowerBound]) }
                return .developer(name: name, team: team)
            }
            if a == "Apple Mac OS Application Signing" { return .developer(name: "Mac App Store", team: team) }
        }
        if s.contains("Identifier=") && s.contains("Format=") && team.isEmpty && !s.contains("Authority=") { return .adhoc }
        return .unreadable
    }

    /// `nettop -P -L 1 -J bytes_in,bytes_out` → `name.pid,bytes_in,bytes_out,`
    public static func nettop(_ s: String) -> [Int32: Traffic] {
        var out: [Int32: Traffic] = [:]
        for line in s.split(separator: "\n") {
            let f = line.split(separator: ",", omittingEmptySubsequences: false)
            guard f.count >= 3, let dot = f[0].lastIndex(of: "."), let pid = Int32(f[0][f[0].index(after: dot)...]),
                  let i = UInt64(f[1]), let o = UInt64(f[2]) else { continue }
            out[pid] = Traffic(inBytes: i, outBytes: o)
        }
        return out
    }

    /// `sysadminctl -screenLock status` → seconds until the password is required; 0 = immediately; -1 = never; nil = unknown.
    public static func screenLock(_ s: String) -> Int? {
        let l = s.lowercased()
        if let r = l.range(of: #"delay is (\d+) second"#, options: .regularExpression),
           let n = Int(l[r].filter { $0.isNumber }) { return n }
        if l.contains("immediate") { return 0 }
        if l.contains("is off") || l.contains("disabled") || l.contains("never") { return -1 }
        return nil
    }

    /// `profiles status -type enrollment`
    public static func enrollment(_ s: String) -> (dep: Tri, mdm: Tri) {
        func tri(_ key: String) -> Tri {
            guard let line = s.split(separator: "\n").first(where: { $0.contains(key) }) else { return .unknown }
            let v = line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
            return v.hasPrefix("yes") ? .on : (v.hasPrefix("no") ? .off : .unknown)
        }
        return (tri("Enrolled via DEP"), tri("MDM enrollment"))
    }

    public static func contains(_ s: String, on: [String], off: [String]) -> Tri {
        let l = s.lowercased()
        if off.contains(where: { l.contains($0.lowercased()) }) { return .off }
        if on.contains(where: { l.contains($0.lowercased()) }) { return .on }
        return .unknown
    }

    /// Addresses that are not on the public internet: loopback, home/office networks, link-local, carrier-grade NAT, VPN ranges.
    public static func isPrivate(_ host: String) -> Bool {
        var h = host.lowercased()
        if h.hasPrefix("::ffff:") { h = String(h.dropFirst(7)) }
        if h == "::1" || h == "localhost" || h == "*" { return true }
        if h.hasPrefix("fe80") || h.hasPrefix("fc") || h.hasPrefix("fd") { return true }
        let p = h.split(separator: ".").compactMap { Int($0) }
        guard p.count == 4 else { return false }
        switch (p[0], p[1]) {
        case (10, _), (127, _), (0, _), (192, 168), (169, 254): return true
        case (172, 16...31): return true
        case (100, 64...127): return true
        default: return false
        }
    }
}

/// Reads the privacy-permission database (needs Full Disk Access). Returns nil when it cannot be opened.
public enum TCC {
    public static func read(path: String) -> [TCCGrant]? {
        var db: OpaquePointer?
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else { sqlite3_close(db); return nil }
        defer { sqlite3_close(db) }
        for sql in ["SELECT service, client, client_type, last_modified FROM access WHERE auth_value = 2",
                    "SELECT service, client, client_type, last_modified FROM access WHERE allowed = 1"] {
            var st: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK else { sqlite3_finalize(st); continue }
            defer { sqlite3_finalize(st) }
            var out: [TCCGrant] = []
            while sqlite3_step(st) == SQLITE_ROW {
                guard let s = sqlite3_column_text(st, 0), let c = sqlite3_column_text(st, 1) else { continue }
                let ts = sqlite3_column_int64(st, 3)
                out.append(TCCGrant(service: String(cString: s), client: String(cString: c),
                                    clientIsPath: sqlite3_column_int(st, 2) == 1,
                                    lastModified: ts > 0 ? Date(timeIntervalSince1970: TimeInterval(ts)) : nil))
            }
            return out
        }
        return nil
    }
}
