import Foundation
import Testing
@testable import WardenCore

func audit(_ p: FakeProbe, trusted: Set<String> = [], whileSampling: @escaping () -> Void = {}) -> Report {
    var a = Audit(probe: p, trusted: trusted)
    a.sleep = { s in p.date = p.date.addingTimeInterval(s); whileSampling() } // time passes, and the tool keeps sending
    return a.run()
}

func finding(_ r: Report, _ id: String) -> Finding? { r.findings.first { $0.id == id } }

func anyDeskApp(daysAgo: Int, now: Date) -> InstalledApp {
    InstalledApp(bundleID: "com.philandro.anydesk", name: "AnyDesk", path: "/Applications/AnyDesk.app", installed: now.addingTimeInterval(-Double(daysAgo) * 86400))
}

let anyDeskProc = RunningProcess(pid: 100, command: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk")

@Suite struct AuditTests {
    @Test func aCleanMacIsReportedCalmly() {
        let r = audit(FakeProbe())
        #expect(r.worst == .ok)
        #expect(r.headline == "Nothing worrying found")
        #expect(r.findings.allSatisfy { $0.severity == .ok })
        #expect(finding(r, "remote-none") != nil && finding(r, "sharing-none") != nil && finding(r, "basics-filevault")?.severity == .ok)
    }

    // MARK: remote-control programs

    @Test func aRecentlyInstalledRemoteToolIsWorthALook_andAnOldOneIsJustGoodToKnow() {
        let p = FakeProbe()
        p.apps = [anyDeskApp(daysAgo: 3, now: p.date)]
        var f = finding(audit(p), "remote-installed")!
        #expect(f.severity == .attention && f.title.contains("recently") && f.why.contains("Hang up"))
        #expect(f.detail.first?.contains("AnyDesk") == true && f.detail.first?.contains("3 days ago") == true)
        #expect(f.fixes.first?.kind == .revealInFinder && f.fixes.first?.target == "/Applications/AnyDesk.app")
        p.apps = [anyDeskApp(daysAgo: 100, now: p.date)]
        f = finding(audit(p), "remote-installed")!
        #expect(f.severity == .info && !f.why.contains("Hang up"), "no scare for something installed months ago")
    }

    @Test func anIdleRunningToolIsAnAttentionItemWithAWayToCloseIt() {
        let p = FakeProbe()
        p.apps = [anyDeskApp(daysAgo: 100, now: p.date)]
        p.procs = [anyDeskProc]
        p.trafficByPid = [100: Traffic(inBytes: 10, outBytes: 1000)]
        let r = audit(p) { p.trafficByPid[100]!.outBytes += 3000 } // 1.5 KB/s: a keep-alive, nothing more
        let f = finding(r, "remote-running-anydesk")!
        #expect(f.severity == .attention && f.title == "AnyDesk is open")
        #expect(f.fixes == [Fix(kind: .quitProcess, label: "Close AnyDesk now", target: "100")])
        #expect(finding(r, "remote-active-anydesk") == nil)
        #expect(finding(r, "remote-installed") == nil, "an open tool is not also listed as merely installed")
    }

    @Test func aToolStreamingTheScreenIsAnAlert() {
        let p = FakeProbe()
        p.apps = [anyDeskApp(daysAgo: 1, now: p.date)]
        p.procs = [anyDeskProc, RunningProcess(pid: 101, command: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk")]
        p.trafficByPid = [100: Traffic(inBytes: 0, outBytes: 0), 101: Traffic(inBytes: 0, outBytes: 0)]
        p.conns = [Connection(pid: 100, command: "AnyDesk", remoteHost: "203.0.113.77", remotePort: 7070),
                   Connection(pid: 100, command: "AnyDesk", remoteHost: "192.168.1.2", remotePort: 7070)]
        let r = audit(p) { p.trafficByPid[100]!.outBytes += 700_000 }  // 350 KB/s
        #expect(r.worst == .alert && r.headline == "1 thing needs your attention now")
        let f = finding(r, "remote-active-anydesk")!
        #expect(f.title == "AnyDesk looks connected to someone right now")
        #expect(f.detail.contains { $0.contains("350 KB/s") } && f.detail.contains { $0.contains("203.0.113.77:7070") })
        #expect(!f.detail.joined().contains("192.168.1.2"), "only internet peers are named")
        #expect(f.fixes.first?.target == "100,101", "closing covers every process of the tool")
        #expect(r.findings.first?.id == "remote-active-anydesk", "the alert sorts to the top")
    }

    @Test func aToolThePersonSaysTheyUseIsQuieterAndHasNoCloseButton() {
        let p = FakeProbe()
        p.procs = [anyDeskProc]
        p.trafficByPid = [100: Traffic(inBytes: 0, outBytes: 0)]
        let f = finding(audit(p, trusted: ["anydesk"]), "remote-running-anydesk")!
        #expect(f.severity == .info && f.fixes.isEmpty && f.why.contains("You told Warden"))
    }

    @Test func aHelperLeftBehindAfterTheAppWasDeleted() {
        let p = FakeProbe()
        p.launch = [LaunchItem(path: "/Library/LaunchDaemons/com.teamviewer.Helper.plist", label: "com.teamviewer.Helper",
                               program: "/Library/PrivilegedHelperTools/com.teamviewer.Helper", scope: .systemDaemon)]
        #expect(finding(audit(p), "remote-leftover-helper")?.severity == .attention)
        p.apps = [InstalledApp(bundleID: "com.teamviewer.TeamViewer", name: "TeamViewer", path: "/Applications/TeamViewer.app", installed: p.date.addingTimeInterval(-90 * 86400))]
        #expect(finding(audit(p), "remote-leftover-helper") == nil, "with the app still installed the helper is expected")
    }

    @Test func appleRemoteManagementIsExplainedNotBlamed() {
        let p = FakeProbe()
        p.procs = [RunningProcess(pid: 55, command: "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent")]
        let f = finding(audit(p), "remote-running-ard")!
        #expect(f.severity == .attention && f.why.contains("work or school"))
        #expect(f.fixes.contains { $0.kind == .openSettings })
    }

    // MARK: sharing, management, basics

    @Test func sharingOnlyCountsWhatOtherComputersCanReach() {
        let p = FakeProbe()
        p.listenerList = [Listener(port: 22, localOnly: true), Listener(port: 5900, localOnly: true), Listener(port: 8080, localOnly: false)]
        #expect(finding(audit(p), "sharing-none") != nil, "services bound to localhost are private")
        p.listenerList = [Listener(port: 22, localOnly: false), Listener(port: 5900, localOnly: false), Listener(port: 445, localOnly: false)]
        let r = audit(p)
        #expect(finding(r, "sharing-screen")?.severity == .attention && finding(r, "sharing-ssh")?.severity == .attention)
        #expect(finding(r, "sharing-files")?.severity == .info && finding(r, "sharing-none") == nil)
    }

    @Test func managementStatus() {
        let p = FakeProbe()
        #expect(finding(audit(p), "device-unmanaged")?.severity == .ok)
        p.mdm = .on
        #expect(finding(audit(p), "device-managed")?.severity == .info)
        p.mdm = .unknown; p.dep = .unknown
        #expect(finding(audit(p), "device-managed") == nil && finding(audit(p), "device-unmanaged") == nil, "unknown is not reported as fine")
    }

    @Test func protectionBasics() {
        let p = FakeProbe()
        p.fileVaultState = .off; p.gatekeeperState = .off; p.sipState = .off; p.firewallState = .off
        p.autoLogin = "dot"; p.guest = .on; p.screenLock = -1
        let r = audit(p)
        #expect(finding(r, "basics-filevault")?.severity == .attention)
        #expect(finding(r, "basics-gatekeeper")?.severity == .alert && finding(r, "basics-sip")?.severity == .alert)
        #expect(finding(r, "basics-firewall")?.severity == .info && finding(r, "basics-guest")?.severity == .info)
        #expect(finding(r, "basics-autologin")?.why.contains("“dot”") == true)
        #expect(finding(r, "basics-screenlock")?.severity == .attention)
        #expect(finding(r, "basics-system") == nil, "no 'protections are on' reassurance when they are not")
        p.screenLock = 1800
        #expect(finding(audit(p), "basics-screenlock")?.severity == .info)
        p.screenLock = nil
        #expect(finding(audit(p), "basics-screenlock") == nil)
    }

    // MARK: tampering

    @Test func proxiesAndRedirectedWebsites() {
        let p = FakeProbe()
        p.proxyList = ["HTTP proxy: 198.51.100.4:8080"]
        #expect(finding(audit(p), "network-proxy")?.detail == ["HTTP proxy: 198.51.100.4:8080"])

        p.proxyList = []
        p.hosts.append(HostEntry(ip: "203.0.113.9", names: ["www.paypal.com"]))
        let a = finding(audit(p), "network-hosts")!
        #expect(a.severity == .alert && a.detail == ["www.paypal.com → 203.0.113.9"])

        p.hosts = FakeProbe().hosts + [HostEntry(ip: "10.0.0.5", names: ["intranet.corp"]), HostEntry(ip: "127.0.0.1", names: ["myapp.test"]),
                                       HostEntry(ip: "0.0.0.0", names: ["ads.tracker.example", "www.google-analytics.com"])]
        let b = finding(audit(p), "network-hosts")!
        #expect(b.severity == .attention && b.detail == ["intranet.corp → 10.0.0.5"], "developer entries and blocklists are left alone")

        p.hosts = FakeProbe().hosts
        #expect(finding(audit(p), "network-hosts") == nil)
    }

    @Test func startupItemsAreSortedIntoNormalAndUnusual() {
        let p = FakeProbe()
        p.launch = [
            LaunchItem(path: "/Library/LaunchDaemons/com.apple.thing.plist", label: "com.apple.thing", program: "/usr/libexec/thing", scope: .systemDaemon),
            LaunchItem(path: "a", label: "com.google.keystone", program: "/Library/Google/GoogleSoftwareUpdate/agent", scope: .systemAgent),
            LaunchItem(path: "b", label: "com.example.updater", program: "/Applications/Example.app/Contents/MacOS/updater", scope: .userAgent),
            LaunchItem(path: "c", label: "com.bad.dropper", program: "/Users/Shared/.hidden/run", scope: .userAgent),
            LaunchItem(path: "d", label: "com.bad.unsigned", program: "/opt/thing/unsigned", scope: .systemDaemon),
            LaunchItem(path: "e", label: "com.bad.script", program: "/bin/sh", arguments: ["-c", "/tmp/x.sh"], scope: .userAgent),
            LaunchItem(path: "f", label: "com.bad.script2", program: "/usr/bin/python3", arguments: ["/private/tmp/payload.py"], scope: .userAgent),
            LaunchItem(path: "g", label: "com.dev.build", program: "/Users/dot/code/tool/.build/debug/tool", scope: .userAgent),
        ]
        p.signatures = [
            "/Library/Google/GoogleSoftwareUpdate/agent": .developer(name: "Google LLC", team: "EQHXZ8M8AV"),
            "/Applications/Example.app/Contents/MacOS/updater": .developer(name: "Example Inc", team: "ABCDE12345"),
            "/Users/Shared/.hidden/run": .developer(name: "Some Dev", team: "ZZZZZ99999"),
            "/opt/thing/unsigned": .unsigned,
            "/Users/dot/code/tool/.build/debug/tool": .adhoc,
        ]
        let r = audit(p)
        let s = finding(r, "startup-suspicious")!
        #expect(s.severity == .attention && s.title == "5 unusual things start by themselves")
        let text = s.detail.joined(separator: "\n")
        #expect(text.contains("com.bad.dropper") && text.contains("com.bad.unsigned") && text.contains("com.bad.script ") && text.contains("com.bad.script2") && text.contains("com.dev.build"))
        #expect(!text.contains("google") && !text.contains("com.example.updater") && !text.contains("com.apple.thing"))
        let sum = finding(r, "startup-summary")!
        #expect(sum.severity == .info && sum.title == "3 programs from 3 developers start by themselves")
    }

    // MARK: permissions and accounts

    @Test func unreadablePermissionsAreSaidSoWithTheFixThatMakesThemReadable() {
        let p = FakeProbe()
        p.tcc = nil
        let f = finding(audit(p), "permissions-unreadable")!
        #expect(f.severity == .info && f.fixes.first?.target.hasSuffix("Privacy_AllFiles") == true)
    }

    @Test func permissionsSeparateRemoteToolsFromOrdinaryApps() {
        let p = FakeProbe()
        p.apps = [InstalledApp(bundleID: "us.zoom.xos", name: "zoom.us", path: "/Applications/zoom.us.app"), anyDeskApp(daysAgo: 400, now: p.date)]
        p.tcc = [
            TCCGrant(service: "kTCCServiceScreenCapture", client: "com.philandro.anydesk"),
            TCCGrant(service: "kTCCServiceAccessibility", client: "com.philandro.anydesk"),
            TCCGrant(service: "kTCCServiceScreenCapture", client: "us.zoom.xos"),
            TCCGrant(service: "kTCCServiceListenEvent", client: "/usr/local/bin/mystery", clientIsPath: true),
            TCCGrant(service: "kTCCServiceScreenCapture", client: "com.apple.screencaptureui"),
            TCCGrant(service: "kTCCServiceCamera", client: "us.zoom.xos"),
        ]
        let r = audit(p)
        let any = finding(r, "permissions-remote-anydesk")!
        #expect(any.severity == .attention && any.title == "AnyDesk is allowed to record your screen and control your Mac")
        let s = finding(r, "permissions-sensitive")!
        #expect(s.severity == .info)
        #expect(s.detail == ["Can record your screen: zoom.us", "Can watch what you type: mystery"])
    }

    @Test func accountsAndRemoteSignIns() {
        let p = FakeProbe()
        #expect(finding(audit(p), "accounts-admins")?.severity == .ok)
        p.admins = ["dot", "helpdesk2"]
        let a = finding(audit(p), "accounts-admins")!
        #expect(a.severity == .attention && a.detail == ["dot", "helpdesk2"])
        p.logins = [LoginRecord(user: "dot", tty: "console", host: nil, when: p.date),
                    LoginRecord(user: "dot", tty: "ttys001", host: "203.0.113.50", when: p.date.addingTimeInterval(-2 * 86400)),
                    LoginRecord(user: "dot", tty: "ttys002", host: "198.51.100.7", when: p.date.addingTimeInterval(-90 * 86400))]
        let r = finding(audit(p), "accounts-remote-logins")!
        #expect(r.severity == .attention && r.detail.count == 1 && r.detail[0].contains("203.0.113.50"))
    }

    // MARK: the report

    @Test func reportReadsWellAsPlainTextForSomeoneElse() {
        let p = FakeProbe()
        p.apps = [anyDeskApp(daysAgo: 2, now: p.date)]
        p.fileVaultState = .off
        let r = audit(p)
        #expect(r.headline == "2 things are worth a look")
        let t = r.summaryText(machine: "Dot's MacBook", os: "macOS 27.2")
        #expect(t.contains("Dot's MacBook") && t.contains("2 THINGS ARE WORTH A LOOK") && t.contains("— Worth a look —") && t.contains("• FileVault is off"))
        #expect(t.contains("AnyDesk") && t.contains("Looks good:"))
        #expect(!t.contains("Hang up"), "the long explanations stay out of a pasted summary")
    }
}
