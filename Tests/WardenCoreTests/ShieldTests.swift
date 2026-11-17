import Foundation
import Testing
@testable import WardenCore

final class FakeController: ProcessController {
    var terminated: [Int32] = []
    var succeed = true
    func terminate(pid: Int32) -> Bool { terminated.append(pid); return succeed }
}

final class ShieldRig {
    let probe = FakeProbe()
    let controller = FakeController()
    let trust = TrustStore(url: nil)
    lazy var monitor = ShieldMonitor(probe: probe, trust: trust, controller: controller)
    var out: UInt64 = 0

    func open(_ pids: [Int32] = [100], command: String = "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk") {
        probe.procs = pids.map { RunningProcess(pid: $0, command: command) }
        for pid in pids where probe.trafficByPid[pid] == nil { probe.trafficByPid[pid] = Traffic(inBytes: 0, outBytes: 0) }
    }
    /// Advance 3 seconds during which the tool sends `bytes`.
    @discardableResult func tick(sending bytes: UInt64 = 0, pid: Int32 = 100) -> [ShieldEvent] {
        probe.date = probe.date.addingTimeInterval(3)
        probe.trafficByPid[pid]?.outBytes += bytes
        return monitor.tick()
    }
}

@Suite struct ShieldTests {
    @Test func announcesAToolThatWasAlreadyOpenWhenWardenStarted() {
        let r = ShieldRig(); r.open()
        let e = r.monitor.tick()
        #expect(e.count == 1 && e[0].kind == .launched && e[0].detail.contains("already open") && !e[0].trusted)
        #expect(r.monitor.tick().isEmpty, "only once")
    }

    @Test func announcesAToolOpeningLater_onceEvenWithSeveralProcesses() {
        let r = ShieldRig()
        #expect(r.monitor.tick().isEmpty)
        r.open([200, 201, 202], command: "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer_Service")
        let e = r.tick()
        #expect(e.count == 1 && e[0].tool.id == "teamviewer" && e[0].detail.contains("just opened"))
        #expect(r.monitor.pids(of: "teamviewer") == [200, 201, 202])
    }

    @Test func ignoresEverythingThatIsNotARemoteTool() {
        let r = ShieldRig()
        r.probe.procs = [RunningProcess(pid: 1, command: "/sbin/launchd"), RunningProcess(pid: 2, command: "/Applications/Safari.app/Contents/MacOS/Safari"),
                         RunningProcess(pid: 3, command: "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent")]
        #expect(r.monitor.tick().isEmpty, "Apple's own agent is the audit's business, not the shield's")
    }

    @Test func trustedToolsAreFlaggedAsSuch() {
        let r = ShieldRig(); r.trust.trust("anydesk"); r.open()
        #expect(r.monitor.tick().first?.trusted == true)
    }

    @Test func aSessionIsAnnouncedAfterSustainedHeavyUploadAndEndsWhenItGoesQuiet() {
        let r = ShieldRig(); r.open()
        _ = r.monitor.tick()
        #expect(r.tick(sending: 2_000).isEmpty, "keep-alive chatter")
        #expect(r.tick(sending: 400_000).isEmpty, "one busy interval is not enough")
        let e = r.tick(sending: 450_000)
        #expect(e.count == 1 && e[0].kind == .sessionLikely && e[0].detail.contains("KB/s"))
        #expect(r.monitor.isInSession("anydesk"))
        #expect(r.tick(sending: 500_000).isEmpty, "not announced again while it continues")
        for _ in 0..<3 { #expect(r.tick(sending: 500).isEmpty) }
        let end = r.tick(sending: 500)
        #expect(end.count == 1 && end[0].kind == .sessionEnded && !r.monitor.isInSession("anydesk"))
    }

    @Test func middlingTrafficChangesNothingAndCounterResetsAreIgnored() {
        let r = ShieldRig(); r.open()
        _ = r.monitor.tick()
        for _ in 0..<6 { #expect(r.tick(sending: 90_000).isEmpty, "30 KB/s is between idle and a session") }
        r.probe.trafficByPid[100]!.outBytes = 5 // the tool restarted its counters
        #expect(r.tick(sending: 0).isEmpty)
    }

    @Test func trafficFromAllProcessesOfOneToolAddsUp() {
        let r = ShieldRig(); r.open([300, 301], command: "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer_Desktop")
        _ = r.monitor.tick()
        for _ in 0..<2 {
            r.probe.trafficByPid[301]!.outBytes += 100_000
            _ = r.tick(sending: 100_000, pid: 300) // 200 KB per 3 s ≈ 66 KB/s in total, 33 KB/s each
        }
        #expect(r.monitor.isInSession("teamviewer"))
    }

    @Test func quittingAndReopeningAreBothReported() {
        let r = ShieldRig(); r.open()
        _ = r.monitor.tick()
        r.probe.procs = []
        let q = r.tick()
        #expect(q.count == 1 && q[0].kind == .quit && r.monitor.openTools.isEmpty)
        r.open()
        #expect(r.tick().first?.kind == .launched)
    }

    @Test func closingChecksEachProcessIsStillTheTool() {
        let r = ShieldRig(); r.open([100, 101])
        _ = r.monitor.tick()
        // pid 101 has since been recycled for an unrelated program
        r.probe.procs = [RunningProcess(pid: 100, command: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk"),
                         RunningProcess(pid: 101, command: "/Applications/Notes.app/Contents/MacOS/Notes")]
        #expect(r.monitor.close(toolID: "anydesk") == [100])
        #expect(r.controller.terminated == [100], "never touches what it did not recognise")
        r.controller.terminated = []
        #expect(r.monitor.close(pids: [100, 101, 999]) == [100] && r.controller.terminated == [100])
        r.controller.succeed = false
        #expect(r.monitor.close(toolID: "anydesk").isEmpty, "processes running as administrator may refuse: reported, not hidden")
    }
}

@Suite struct TrustAndHelperTests {
    @Test func trustSurvivesARestart() throws {
        let url = URL(fileURLWithPath: NSTemporaryDirectory() + "/warden-trust-\(UUID())/trusted.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let a = TrustStore(url: url)
        a.trust("anydesk"); a.trust("teamviewer"); a.untrust("teamviewer")
        let b = TrustStore(url: url)
        #expect(b.ids == ["anydesk"] && b.isTrusted("anydesk") && !b.isTrusted("teamviewer"))
        try Data("garbage".utf8).write(to: url)
        #expect(TrustStore(url: url).ids.isEmpty, "a damaged file never crashes the shield")
    }

    @Test func helperComesFromWardenOrBorrowsHearthsHelper() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory() + "/warden-helper-\(UUID())")
        defer { try? FileManager.default.removeItem(at: dir) }
        let hearth = dir.appendingPathComponent("hearth.json")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        #expect(HelperContact.load(wardenHome: dir, hearthConfig: hearth) == nil)
        try Data(#"{"people":[{"name":"Mike","handle":"mike@example.com","isHelper":false},{"name":"Anna","handle":"+15550100199","isHelper":true}]}"#.utf8).write(to: hearth)
        #expect(HelperContact.load(wardenHome: dir, hearthConfig: hearth) == HelperContact(name: "Anna", handle: "+15550100199"))
        try HelperContact(name: "Sam", handle: "5550123").save(to: dir)
        #expect(HelperContact.load(wardenHome: dir, hearthConfig: hearth)?.name == "Sam", "Warden's own choice wins")
        #expect(HelperContact(name: "A", handle: "+155501").callURL?.absoluteString == "facetime-audio://+155501")
        #expect(HelperContact(name: "A", handle: "a@b.co").callURL?.absoluteString == "facetime://a@b.co")
    }
}
