import Foundation
import Darwin
import Testing
@testable import WardenCore

/// These run against the real Mac (read-only) and a harmless fake "AnyDesk".
@Suite(.serialized) struct LiveTests {
    @Test func liveProbeReadsTheRealMac() {
        let p = LiveProbe()
        let procs = p.runningProcesses()
        #expect(procs.contains { $0.pid == getpid() }, "sees itself in the process list")
        #expect(procs.count > 20)
        #expect(!p.installedApps().isEmpty)
        _ = p.listeners(); _ = p.proxies(); _ = p.hostsEntries(); _ = p.recentLogins(); _ = p.adminUsers()
        #expect(p.hostsEntries().contains { $0.names.contains("localhost") })
        #expect(p.signature(of: "/bin/ls") != .unsigned)
        let tri: [Tri] = [p.fileVault(), p.sip(), p.gatekeeper()]
        #expect(tri.allSatisfy { [.on, .off, .unknown].contains($0) })
    }

    @Test func liveConnectionsSeeLoopbackSockets() throws {
        // a listener and a client inside this very process
        let srv = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_addr.s_addr = inet_addr("127.0.0.1"); addr.sin_port = 0
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = bind(srv, $0, len) } }
        listen(srv, 1)
        withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(srv, $0, &len) } }
        let port = Int(UInt16(bigEndian: addr.sin_port))
        let cli = socket(AF_INET, SOCK_STREAM, 0)
        withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = connect(cli, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        let accepted = accept(srv, nil, nil)
        defer { close(cli); close(accepted); close(srv) }
        let mine = LiveProbe().establishedConnections().filter { $0.pid == getpid() && $0.remotePort == port }
        #expect(!mine.isEmpty, "lsof output parsed: our own loopback connection to port \(port)")
        #expect(mine.allSatisfy { $0.remoteHost == "127.0.0.1" && $0.isLocal }, "loopback is never 'someone far away'")
        let listening = LiveProbe().listeners().first { $0.port == port }
        #expect(listening?.localOnly == true, "a loopback-only listener is reported as local")
    }

    @Test func theShieldFindsARealFakeAnyDeskAndClosesIt() throws {
        let dir = NSTemporaryDirectory() + "warden-fake-\(UUID())"
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let macos = dir + "/AnyDesk.app/Contents/MacOS"
        try FileManager.default.createDirectory(atPath: macos, withIntermediateDirectories: true)
        try "import Foundation\nsleep(300)\n".write(toFile: dir + "/fake.swift", atomically: true, encoding: .utf8)
        let build = Shell.run("/usr/bin/swiftc", [dir + "/fake.swift", "-o", macos + "/AnyDesk"], timeout: 120)
        try #require(build.status == 0, "could not build the fake tool: \(build.err.prefix(300))")

        let p = Process()
        p.executableURL = URL(fileURLWithPath: macos + "/AnyDesk")
        try p.run()
        defer { if p.isRunning { p.terminate() } }
        usleep(400_000)

        let probe = LiveProbe()
        let monitor = ShieldMonitor(probe: probe, trust: TrustStore(url: nil))
        let events = monitor.tick()
        #expect(events.contains { $0.kind == .launched && $0.tool.id == "anydesk" && $0.pid == p.processIdentifier }, "\(events)")

        // the audit sees it too, and offers to close it
        var a = Audit(probe: probe)
        a.sampleSeconds = 0.3
        a.sleep = { Thread.sleep(forTimeInterval: $0) }
        let report = a.run()
        let f = try #require(report.findings.first { $0.id == "remote-running-anydesk" })
        #expect(f.fixes.first?.target.split(separator: ",").contains { Int32($0) == p.processIdentifier } == true)

        #expect(monitor.close(toolID: "anydesk") == [p.processIdentifier], "SIGTERM, then confirmed gone")
        p.waitUntilExit()
        #expect(!p.isRunning)
        #expect(monitor.tick().contains { $0.kind == .quit })
    }

    @Test func theTrafficStreamDeliversFreshSamplesWithoutBlocking() {
        let p = LiveProbe()
        let t0 = Date()
        p.startTrafficStream()
        #expect(Date().timeIntervalSince(t0) < 1, "starting the stream never waits for nettop")
        var first: TrafficSnapshot?
        let deadline = Date().addingTimeInterval(15)
        while first == nil && Date() < deadline { Thread.sleep(forTimeInterval: 0.2); first = p.trafficSnapshot() }
        #expect(first != nil, "a first sample arrives")
        #expect(first?.byPid[1] != nil, "launchd (pid 1) is in every sample")
        let t1 = Date()
        #expect(p.trafficSnapshot() != nil)
        #expect(Date().timeIntervalSince(t1) < 0.5, "reading the latest sample is instant")
        var second: TrafficSnapshot?
        let d2 = Date().addingTimeInterval(10)
        while Date() < d2 { Thread.sleep(forTimeInterval: 0.25); if let s = p.trafficSnapshot(), let f = first, s.at > f.at { second = s; break } }
        #expect(second != nil, "samples keep coming")
    }

    @Test func aSamplerLeftBehindByACrashIsReapedOnTheNextStart() throws {
        // an orphan: started by a shell that exits at once, so launchd (pid 1) adopts it, exactly what a killed Warden leaves
        let sh = Process()
        sh.executableURL = URL(fileURLWithPath: "/bin/sh")
        sh.arguments = ["-c", "/usr/bin/nettop -P -L 0 -s 1 -J bytes_in,bytes_out >/dev/null 2>&1 &"]
        try sh.run(); sh.waitUntilExit()
        usleep(500_000)
        func orphans() -> [Int32] {
            Shell.run("/bin/ps", ["-wwaxo", "pid=,ppid=,args="]).out.split(separator: "\n").compactMap { l in
                let t = l.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
                guard t.count == 3, t[1] == "1", t[2].contains("nettop -P -L 0 -s 1 -J bytes_in") else { return nil }
                return Int32(t[0])
            }
        }
        #expect(!orphans().isEmpty, "the test really created an orphan")
        #expect(NettopStream.shared.reapStrays() >= 1)
        usleep(800_000)
        #expect(orphans().isEmpty, "and it is gone")
    }

    @Test func aFullLiveAuditCompletesAndMakesSense() {
        let start = Date()
        let r = Audit(probe: LiveProbe(), trusted: []).run()
        #expect(Date().timeIntervalSince(start) < 60)
        #expect(!r.findings.isEmpty)
        #expect(Set(r.findings.map(\.id)).count == r.findings.count, "finding ids are unique")
        #expect(r.findings.allSatisfy { !$0.title.isEmpty && !$0.why.isEmpty })
    }
}
