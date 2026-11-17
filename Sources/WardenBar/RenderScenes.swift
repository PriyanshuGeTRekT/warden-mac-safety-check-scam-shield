import SwiftUI
import AppKit
import WardenCore

/// Demo Macs for screenshots and for the headless self-test.
@MainActor
enum RenderScenes {
    static func messyProbe() -> FakeProbe {
        let p = FakeProbe()
        let now = p.date
        p.apps = [
            InstalledApp(bundleID: "com.philandro.anydesk", name: "AnyDesk", path: "/Applications/AnyDesk.app", installed: now.addingTimeInterval(-2 * 86400)),
            InstalledApp(bundleID: "com.teamviewer.TeamViewer", name: "TeamViewer", path: "/Applications/TeamViewer.app", installed: now.addingTimeInterval(-200 * 86400)),
        ]
        p.procs = [RunningProcess(pid: 4242, command: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk")]
        p.liveStreams = [4242: 450_000] // AnyDesk keeps sending ~450 KB/s
        p.conns = [Connection(pid: 4242, command: "AnyDesk", remoteHost: "203.0.113.77", remotePort: 7070)]
        p.fileVaultState = .off
        p.firewallState = .off
        p.proxyList = ["HTTP proxy: 198.51.100.4:8080"]
        p.listenerList = [Listener(port: 5900, localOnly: false)]
        p.launch = [LaunchItem(path: "a", label: "com.helper.updater", program: "/Users/Shared/.cache/updater", scope: .userAgent),
                    LaunchItem(path: "b", label: "com.google.keystone", program: "/Library/Google/agent", scope: .systemAgent)]
        p.signatures = ["/Users/Shared/.cache/updater": .unsigned, "/Library/Google/agent": .developer(name: "Google LLC", team: "EQHXZ8M8AV")]
        p.tcc = nil
        p.admins = ["dorothy", "support-tech"]
        return p
    }

    static func calmProbe() -> FakeProbe {
        let p = FakeProbe()
        p.firewallState = .off
        p.tcc = nil
        p.apps = [InstalledApp(bundleID: "com.teamviewer.TeamViewer", name: "TeamViewer", path: "/Applications/TeamViewer.app", installed: p.date.addingTimeInterval(-200 * 86400))]
        p.launch = [LaunchItem(path: "b", label: "com.google.keystone", program: "/Library/Google/agent", scope: .systemAgent),
                    LaunchItem(path: "c", label: "com.microsoft.update", program: "/Library/Microsoft/agent", scope: .systemAgent)]
        p.signatures = ["/Library/Google/agent": .developer(name: "Google LLC", team: "EQHXZ8M8AV"),
                        "/Library/Microsoft/agent": .developer(name: "Microsoft Corporation", team: "UBF8T346G9")]
        return p
    }

    static func model(_ p: SystemProbe, helper: HelperContact? = nil, mutate: (AppModel) -> Void = { _ in }) -> AppModel {
        let m = AppModel(probe: p, trust: TrustStore(url: nil), controller: LiveProcessController())
        m.helper = helper
        mutate(m)
        return m
    }

    static func pump(_ timeout: TimeInterval, until cond: () -> Bool) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end { if cond() { return true }; RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
        return cond()
    }

    static func renderPNG<V: View>(_ view: V, size: CGSize, to path: String) {
        let host = NSHostingView(rootView: view)
        host.sizingOptions = []
        host.frame = CGRect(origin: .zero, size: size)
        let win = NSWindow(contentRect: CGRect(origin: CGPoint(x: -9000, y: -9000), size: size), styleMask: [.borderless], backing: .buffered, defer: false)
        win.appearance = NSAppearance(named: .aqua)
        win.contentView = host
        win.orderFrontRegardless()
        RunLoop.current.run(until: Date().addingTimeInterval(1.0))
        host.layoutSubtreeIfNeeded(); host.displayIfNeeded()
        if let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) {
            host.cacheDisplay(in: host.bounds, to: rep)
            try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: path))
        }
        win.orderOut(nil)
    }

    static func fitting<V: View>(_ v: V) -> CGSize { NSHostingView(rootView: v).fittingSize }

    static func event(_ kind: ShieldEvent.Kind, _ toolID: String, detail: String) -> ShieldEvent {
        ShieldEvent(kind: kind, tool: KnownTools.tool(id: toolID)!, pid: 4242, at: Date(), trusted: false, detail: detail)
    }

    @discardableResult
    static func run(outDir: String) -> [String] {
        NSApplication.shared.setActivationPolicy(.accessory)
        try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)
        var made: [String] = []
        func out(_ n: String) -> String { made.append(n); return outDir + "/" + n }
        let helper = HelperContact(name: "Anna", handle: "+15550100199")
        let popover = CGSize(width: 440, height: 640)

        let messy = messyProbe()
        let m1 = model(messy, helper: helper)
        var audit = Audit(probe: messy); audit.sampleSeconds = 1.2
        m1.report = audit.run()
        for f in m1.report!.findings where f.severity == .alert { m1.expanded.insert(f.id) }
        renderPNG(PopoverView(model: m1), size: popover, to: out("1-alert-report.png"))
        m1.expanded = ["remote-installed", "network-proxy"]
        renderPNG(PopoverView(model: m1), size: popover, to: out("2-expanded-cards.png"))

        let m2 = model(calmProbe(), helper: nil)
        m2.report = Audit(probe: calmProbe()).run()
        m2.trust.trust("anydesk"); m2.trustedIDs = m2.trust.ids
        renderPNG(PopoverView(model: m2), size: popover, to: out("3-calm-report.png"))

        let e1 = event(.launched, "anydesk", detail: "AnyDesk just opened.")
        renderPNG(ShieldAlertView(model: model(calmProbe(), helper: helper), event: e1), size: fitting(ShieldAlertView(model: model(calmProbe(), helper: helper), event: e1)), to: out("4-alert-opened.png"))
        let e2 = event(.sessionLikely, "anydesk", detail: "AnyDesk is sending about 350 KB/s, which is what it does when someone is watching your screen.")
        renderPNG(ShieldAlertView(model: model(calmProbe(), helper: helper), event: e2), size: fitting(ShieldAlertView(model: model(calmProbe(), helper: helper), event: e2)), to: out("5-alert-session.png"))
        let m3 = model(calmProbe(), helper: nil); m3.report = nil
        renderPNG(PopoverView(model: m3), size: popover, to: out("6-checking.png"))
        return made
    }

    static func pixelColors(_ path: String) -> (size: Int, colors: Int) {
        guard let data = FileManager.default.contents(atPath: path), let rep = NSBitmapImageRep(data: data) else { return (0, 0) }
        var seen = Set<UInt32>()
        for y in stride(from: 0, to: rep.pixelsHigh, by: max(rep.pixelsHigh / 60, 1)) {
            for x in stride(from: 0, to: rep.pixelsWide, by: max(rep.pixelsWide / 60, 1)) {
                guard let c = rep.colorAt(x: x, y: y)?.usingColorSpace(.sRGB) else { continue }
                seen.insert(UInt32(c.redComponent * 31) << 10 | UInt32(c.greenComponent * 31) << 5 | UInt32(c.blueComponent * 31))
            }
        }
        return (data.count, seen.count)
    }

    /// Drives the model the way the buttons do, with a pretend Mac and a pretend process controller.
    static func selftest(outDir: String) -> Int32 {
        NSApplication.shared.setActivationPolicy(.accessory)
        var failures = 0
        func check(_ ok: Bool, _ what: String) { print(ok ? "  ✓ \(what)" : "  ✗ \(what)"); if !ok { failures += 1 } }

        print("the Safety Check in the app")
        let messy = messyProbe()
        final class Ctl: ProcessController { var terminated: [Int32] = []; func terminate(pid: Int32) -> Bool { terminated.append(pid); return true } }
        let ctl = Ctl()
        let m = AppModel(probe: messy, trust: TrustStore(url: nil), controller: ctl)
        m.helper = HelperContact(name: "Anna", handle: "+15550100199")
        m.runAudit()
        check(pump(20) { m.report != nil }, "the audit runs in the background and fills in the report")
        check(m.report?.worst == .alert && m.severity == .alert, "AnyDesk streaming data makes it an alert")
        let f = m.report?.findings.first { $0.id == "remote-active-anydesk" }
        check(f != nil && m.expanded.contains("remote-active-anydesk"), "the alert card opens by itself")

        print("closing a tool from a finding")
        if let fix = f?.fixes.first {
            m.apply(fix)
            check(pump(10) { ctl.terminated == [4242] }, "'Close AnyDesk now' closes exactly that process")
        } else { check(false, "the alert has a Close fix") }

        print("the live shield events")
        let m2 = AppModel(probe: FakeProbe(), trust: TrustStore(url: nil), controller: ctl)
        let launched = ShieldEvent(kind: .launched, tool: KnownTools.tool(id: "anydesk")!, pid: 1, at: Date(), trusted: false, detail: "AnyDesk just opened.")
        var raised = 0
        m2.onAlert = { raised += 1 }
        m2.handle([launched])
        check(m2.alert?.tool.id == "anydesk" && raised == 1 && m2.severity == .alert, "an untrusted tool opening raises the stop sign")
        m2.handle([ShieldEvent(kind: .quit, tool: launched.tool, pid: 1, at: Date(), trusted: false, detail: "closed")])
        check(pump(10) { m2.alert == nil }, "closing the tool clears it")
        let trustedEvent = ShieldEvent(kind: .launched, tool: launched.tool, pid: 1, at: Date(), trusted: true, detail: "x")
        m2.handle([trustedEvent])
        check(m2.alert == nil && m2.toast != nil, "a tool the person uses only gets a quiet note")
        m2.handle([launched])
        m2.trustTool("anydesk")
        check(m2.alert == nil && m2.trustedIDs == ["anydesk"], "'I use this one' dismisses it and remembers")
        m2.untrustTool("anydesk")
        check(m2.trustedIDs.isEmpty, "and can be undone")
        m2.handle([ShieldEvent(kind: .sessionLikely, tool: KnownTools.tool(id: "teamviewer")!, pid: 2, at: Date(), trusted: false, detail: "busy")])
        check(m2.alert?.kind == .sessionLikely, "a likely session is a bigger alert than an opening")
        m2.dismissAlert()
        check(m2.alert == nil, "'I know what this is' dismisses")

        print("rendering every screen")
        for name in run(outDir: outDir) {
            let st = pixelColors(outDir + "/" + name)
            check(st.size > 6_000 && st.colors >= 5, "\(name) drew real content (\(st.size / 1024) KB, \(st.colors) colours)")
        }
        print(failures == 0 ? "WARDEN SELFTEST PASSED" : "WARDEN SELFTEST FAILED (\(failures))")
        return failures == 0 ? 0 : 1
    }
}
