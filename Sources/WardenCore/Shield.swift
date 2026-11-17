import Foundation
import Darwin

// MARK: - what the person has said they use

public enum WardenPaths {
    public static var home: URL {
        if let e = ProcessInfo.processInfo.environment["WARDEN_HOME"], !e.isEmpty { return URL(fileURLWithPath: e, isDirectory: true) }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Warden", isDirectory: true)
    }
    public static var hearthConfig: URL {
        if let e = ProcessInfo.processInfo.environment["HEARTH_HOME"], !e.isEmpty { return URL(fileURLWithPath: e).appendingPathComponent("config.json") }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Hearth/config.json")
    }
}

/// "I use AnyDesk, don't alarm me when it opens." Stored as a small JSON list.
public final class TrustStore {
    private var _ids: Set<String>
    private let url: URL?
    private let lock = NSLock()

    public init(url: URL?) {
        self.url = url
        if let u = url, let d = try? Data(contentsOf: u), let a = try? JSONDecoder().decode([String].self, from: d) { _ids = Set(a) } else { _ids = [] }
    }

    public static func standard() -> TrustStore { TrustStore(url: WardenPaths.home.appendingPathComponent("trusted.json")) }

    /// Safe to read from the shield thread while the interface changes it.
    public var ids: Set<String> { lock.lock(); defer { lock.unlock() }; return _ids }
    public func isTrusted(_ id: String) -> Bool { ids.contains(id) }
    public func trust(_ id: String) { lock.lock(); _ids.insert(id); lock.unlock(); save() }
    public func untrust(_ id: String) { lock.lock(); _ids.remove(id); lock.unlock(); save() }

    private func save() {
        guard let u = url else { return }
        let snapshot = ids
        try? FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? JSONEncoder().encode(snapshot.sorted()).write(to: u, options: .atomic)
    }
}

/// Who to call when something looks wrong: set once with `warden helper set`, or borrowed from Hearth's helper.
public struct HelperContact: Equatable, Codable {
    public let name: String
    public let handle: String
    public init(name: String, handle: String) { self.name = name; self.handle = handle }

    public static func load(wardenHome: URL = WardenPaths.home, hearthConfig: URL = WardenPaths.hearthConfig) -> HelperContact? {
        if let d = try? Data(contentsOf: wardenHome.appendingPathComponent("helper.json")),
           let c = try? JSONDecoder().decode(HelperContact.self, from: d), !c.name.isEmpty, !c.handle.isEmpty { return c }
        struct HearthPerson: Decodable { var name: String; var handle: String; var isHelper: Bool? }
        struct HearthCfg: Decodable { var people: [HearthPerson]? }
        if let d = try? Data(contentsOf: hearthConfig), let c = try? JSONDecoder().decode(HearthCfg.self, from: d),
           let p = c.people?.first(where: { $0.isHelper == true }) ?? c.people?.first { return HelperContact(name: p.name, handle: p.handle) }
        return nil
    }

    public func save(to home: URL = WardenPaths.home) throws {
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        try JSONEncoder().encode(self).write(to: home.appendingPathComponent("helper.json"), options: .atomic)
    }

    /// A FaceTime link; phone numbers start an audio call, Apple ID emails a video call.
    public var callURL: URL? { URL(string: (handle.contains("@") ? "facetime://" : "facetime-audio://") + handle) }
}

// MARK: - closing a program

public protocol ProcessController: AnyObject {
    /// Asks politely (SIGTERM), then insists (SIGKILL) if it is still there after two seconds. Returns true if it is gone.
    func terminate(pid: Int32) -> Bool
}

public final class LiveProcessController: ProcessController {
    public init() {}
    public func terminate(pid: Int32) -> Bool {
        guard pid > 1 else { return false }
        kill(pid, SIGTERM)
        for _ in 0..<20 { if kill(pid, 0) != 0 { return true }; usleep(100_000) }
        kill(pid, SIGKILL)
        usleep(200_000)
        return kill(pid, 0) != 0 && errno == ESRCH
    }
}

// MARK: - the live shield

public struct ShieldEvent: Equatable {
    public enum Kind: String { case launched, sessionLikely, sessionEnded, quit }
    public let kind: Kind
    public let tool: RemoteTool
    public let pid: Int32
    public let at: Date
    /// The person said they use this tool: show quietly instead of a stop sign.
    public let trusted: Bool
    public let detail: String

    public init(kind: Kind, tool: RemoteTool, pid: Int32, at: Date, trusted: Bool, detail: String) {
        self.kind = kind; self.tool = tool; self.pid = pid; self.at = at; self.trusted = trusted; self.detail = detail
    }
}

public struct ShieldSettings {
    public var heavyOutBytesPerSecond = Audit.heavyOutBytesPerSecond
    /// Consecutive busy checks before a session is announced (about 6 seconds at the default pace).
    public var sustainedChecks = 2
    /// Consecutive quiet checks before the session is considered over.
    public var quietChecks = 4
    public init() {}
}

/// Watches for remote-control programs. Call `tick()` every few seconds.
///
/// It reports (1) a tool opening, and (2) a *session likely* when a tool keeps sending a lot of data. An idle tool keeps a
/// connection to its company's servers and sends almost nothing, so "connected" alone would be a false alarm every time.
/// Traffic is a heuristic: a viewer watching a perfectly still screen can send little, so this can miss a quiet session.
public final class ShieldMonitor {
    public let probe: SystemProbe
    public let trust: TrustStore
    public let controller: ProcessController
    public var settings = ShieldSettings()

    private struct State {
        var tool: RemoteTool
        var pids: Set<Int32> = []
        var lastOut: [Int32: UInt64] = [:]
        var lastSampleAt: Date?
        var heavy = 0
        var quiet = 0
        var inSession = false
    }
    private var states: [String: State] = [:]
    private var started = false

    public init(probe: SystemProbe, trust: TrustStore, controller: ProcessController = LiveProcessController()) {
        self.probe = probe; self.trust = trust; self.controller = controller
        probe.startTrafficStream()
    }

    public var openTools: [RemoteTool] { states.values.map { $0.tool }.sorted { $0.name < $1.name } }
    public func isInSession(_ toolID: String) -> Bool { states[toolID]?.inSession ?? false }
    public func pids(of toolID: String) -> [Int32] { states[toolID]?.pids.sorted() ?? [] }

    @discardableResult
    public func tick() -> [ShieldEvent] {
        let t = probe.now()
        let first = !started
        started = true
        var byTool: [String: (tool: RemoteTool, pids: [Int32])] = [:]
        for p in probe.runningProcesses() {
            guard let tool = KnownTools.matchProcess(command: p.command), !tool.builtIn else { continue }
            byTool[tool.id, default: (tool, [])].pids.append(p.pid)
        }
        var events: [ShieldEvent] = []

        for (id, st) in states where byTool[id] == nil {
            events.append(ShieldEvent(kind: .quit, tool: st.tool, pid: st.pids.min() ?? 0, at: t, trusted: trust.isTrusted(id), detail: "\(st.tool.name) was closed."))
            states[id] = nil
        }

        let snapshot = byTool.isEmpty ? nil : probe.trafficSnapshot()
        for (id, entry) in byTool.sorted(by: { $0.key < $1.key }) {
            let trusted = trust.isTrusted(id)
            if states[id] == nil {
                states[id] = State(tool: entry.tool)
                events.append(ShieldEvent(kind: .launched, tool: entry.tool, pid: entry.pids.min() ?? 0, at: t, trusted: trusted,
                                          detail: first ? "\(entry.tool.name) was already open when Warden started." : "\(entry.tool.name) just opened."))
            }
            var st = states[id]!
            st.pids = Set(entry.pids)
            var total = 0.0
            var sampled = false
            // rates come from the *sample's own* timestamps, so a late or repeated sample never distorts them
            if let snap = snapshot, snap.at > (st.lastSampleAt ?? .distantPast) {
                if let last = st.lastSampleAt {
                    let dt = snap.at.timeIntervalSince(last)
                    if dt > 0.2 {
                        for pid in st.pids {
                            if let now = snap.byPid[pid]?.outBytes, let before = st.lastOut[pid], now >= before { total += Double(now - before) / dt; sampled = true }
                        }
                    }
                }
                for pid in st.pids { if let o = snap.byPid[pid]?.outBytes { st.lastOut[pid] = o } }
                st.lastSampleAt = snap.at
            }
            if sampled {
                if total >= settings.heavyOutBytesPerSecond { st.heavy += 1; st.quiet = 0 }
                else if total < settings.heavyOutBytesPerSecond / 4 { st.quiet += 1; st.heavy = 0 }
                if !st.inSession && st.heavy >= settings.sustainedChecks {
                    st.inSession = true
                    events.append(ShieldEvent(kind: .sessionLikely, tool: entry.tool, pid: entry.pids.min() ?? 0, at: t, trusted: trusted,
                                              detail: "\(entry.tool.name) is sending about \(Int(total / 1000)) KB/s, which is what it does when someone is watching your screen."))
                }
                if st.inSession && st.quiet >= settings.quietChecks {
                    st.inSession = false
                    events.append(ShieldEvent(kind: .sessionEnded, tool: entry.tool, pid: entry.pids.min() ?? 0, at: t, trusted: trusted,
                                              detail: "\(entry.tool.name) has gone quiet."))
                }
            }
            states[id] = st
        }
        return events
    }

    /// Closes every process of a tool. Each pid is re-checked first so a recycled process id can never close something else.
    @discardableResult
    public func close(toolID: String) -> [Int32] {
        guard let st = states[toolID] else { return [] }
        let live = Dictionary(probe.runningProcesses().map { ($0.pid, $0.command) }, uniquingKeysWith: { a, _ in a })
        var closed: [Int32] = []
        for pid in st.pids.sorted(by: >) {
            guard let cmd = live[pid], KnownTools.matchProcess(command: cmd)?.id == toolID else { continue }
            if controller.terminate(pid: pid) { closed.append(pid) }
        }
        return closed
    }

    /// Same, for a pid list coming from a finding's "Close it now" fix.
    @discardableResult
    public func close(pids: [Int32]) -> [Int32] {
        let live = Dictionary(probe.runningProcesses().map { ($0.pid, $0.command) }, uniquingKeysWith: { a, _ in a })
        return pids.filter { pid in
            guard let cmd = live[pid], KnownTools.matchProcess(command: cmd) != nil else { return false }
            return controller.terminate(pid: pid)
        }
    }
}
