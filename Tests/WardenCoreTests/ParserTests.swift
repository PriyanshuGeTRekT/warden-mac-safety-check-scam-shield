import Foundation
import Testing
import SQLite3
@testable import WardenCore

@Suite struct ParserTests {
    @Test func listenersFromNetstat() {
        let s = """
        Active Internet connections (including servers)
        Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
        tcp4       0      0  127.0.0.1.5037         *.*                    LISTEN
        tcp4       0      0  *.5000                 *.*                    LISTEN
        tcp6       0      0  *.7000                 *.*                    LISTEN
        tcp6       0      0  ::1.631                *.*                    LISTEN
        tcp4       0      0  192.168.1.5.52000      142.250.80.46.443      ESTABLISHED
        tcp6       0      0  *.5900                 *.*                    LISTEN
        tcp4       0      0  *.22                   *.*                    LISTEN
        """
        let l = Parse.listeners(netstat: s)
        #expect(l.map(\.port) == [22, 631, 5000, 5037, 5900, 7000])
        #expect(l.first { $0.port == 5037 }?.localOnly == true)
        #expect(l.first { $0.port == 631 }?.localOnly == true)
        #expect(l.first { $0.port == 5900 }?.localOnly == false)
        #expect(!l.contains { $0.port == 52000 }, "an established connection is not a listener")
    }

    @Test func establishedConnectionsFromLsof() {
        let s = """
        COMMAND     PID       USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
        identitys   715 sam          56u  IPv6 0x1111      0t0  TCP [fe80:18::1]:1024->[fe80:18::2]:1024 (ESTABLISHED)
        Google\\x20Chrome  4521 sam         24u  IPv4 0x1234      0t0  TCP 192.168.1.5:50123->142.250.80.46:443 (ESTABLISHED)
        AnyDesk    999 sam          12u  IPv6 0x9999      0t0  TCP [2001:db8::5]:51000->[2a00:1450:4001::200e]:443 (ESTABLISHED)
        node       111 sam          10u  IPv4 0x2222      0t0  TCP 127.0.0.1:3000 (LISTEN)
        """
        let c = Parse.established(lsof: s)
        #expect(c.count == 3)
        #expect(c[0].remoteHost == "fe80:18::2" && c[0].remotePort == 1024 && c[0].isLocal)
        #expect(c[1].command == "Google Chrome" && c[1].remoteHost == "142.250.80.46" && c[1].remotePort == 443 && !c[1].isLocal)
        #expect(c[2].pid == 999 && c[2].remoteHost == "2a00:1450:4001::200e" && !c[2].isLocal)
    }

    @Test func publicAndPrivateAddresses() {
        for h in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.0.9", "169.254.1.1", "100.64.0.1", "100.127.1.1", "::1", "fe80::1", "fd12::1", "::ffff:192.168.1.1", "localhost"] {
            #expect(Parse.isPrivate(h), "\(h) is not on the public internet")
        }
        for h in ["8.8.8.8", "172.32.0.1", "172.15.0.1", "100.63.0.1", "100.128.0.1", "142.250.80.46", "2a00:1450:4001::200e", "::ffff:8.8.8.8"] {
            #expect(!Parse.isPrivate(h), "\(h) is public")
        }
    }

    @Test func loginsFromLast() {
        let s = """
        sam        console                         Fri Nov 13 23:10   still logged in
        reboot time                                Fri Nov 13 23:07
        dot        ttys003  203.0.113.50           Tue Nov 17 09:10 - 09:30  (00:20)
        shutdown time                              Wed Nov 11 23:07
        dot        ttys001                         Mon Nov  2 08:00 - 08:05  (00:05)
        """
        let now = Calendar.current.date(from: DateComponents(year: 2026, month: 11, day: 17, hour: 12))!
        let l = Parse.logins(last: s, now: now)
        #expect(l.count == 3)
        #expect(l.filter { $0.host != nil }.map(\.host) == ["203.0.113.50"])
        #expect(l[1].user == "dot" && l[1].tty == "ttys003" && l[1].when != nil)
        #expect(l[0].host == nil && l[0].tty == "console")
    }

    @Test func proxiesFromScutil() {
        let none = """
        <dictionary> {
          ExcludeSimpleHostnames : 0
          FTPPassive : 1
        }
        """
        #expect(Parse.proxies(scutil: none).isEmpty)
        let on = """
        <dictionary> {
          ExceptionsList : <array> {
            0 : *.local
          }
          HTTPEnable : 1
          HTTPPort : 8080
          HTTPProxy : 10.9.8.7
          HTTPSEnable : 0
          ProxyAutoConfigEnable : 1
          ProxyAutoConfigURLString : http://evil.example/proxy.pac
          SOCKSEnable : 1
          SOCKSProxy : 198.51.100.4
          SOCKSPort : 1080
        }
        """
        #expect(Parse.proxies(scutil: on) == ["HTTP proxy: 10.9.8.7:8080", "SOCKS proxy: 198.51.100.4:1080", "Automatic proxy script: http://evil.example/proxy.pac"])
    }

    @Test func hostsFile() {
        let s = """
        ##
        # Host Database
        ##
        127.0.0.1	localhost
        255.255.255.255	broadcasthost
        ::1             localhost
        203.0.113.9  www.paypal.com paypal.com   # added by "support"

        0.0.0.0 ads.tracker.example
        """
        let h = Parse.hosts(s)
        #expect(h.count == 5)
        #expect(h[3] == HostEntry(ip: "203.0.113.9", names: ["www.paypal.com", "paypal.com"]))
    }

    @Test func adminGroup() {
        #expect(Parse.admins(dscl: "GroupMembership: root sam _mbsetupuser") == ["sam"])
        #expect(Parse.admins(dscl: "GroupMembership: root dot sam\n") == ["dot", "sam"])
        #expect(Parse.admins(dscl: "") == [])
    }

    @Test func codeSignatures() {
        let dev = """
        Executable=/Applications/TeamViewer.app/Contents/MacOS/TeamViewer
        Identifier=com.teamviewer.TeamViewer
        Format=app bundle with Mach-O universal (x86_64 arm64)
        Authority=Developer ID Application: TeamViewer Germany GmbH (H7UGFBUGV6)
        Authority=Developer ID Certification Authority
        Authority=Apple Root CA
        TeamIdentifier=H7UGFBUGV6
        """
        #expect(Parse.codesign(dev) == .developer(name: "TeamViewer Germany GmbH", team: "H7UGFBUGV6"))
        let apple = "Identifier=com.apple.ls\nAuthority=Software Signing\nAuthority=Apple Code Signing Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=not set"
        #expect(Parse.codesign(apple) == .apple)
        #expect(Parse.codesign("Identifier=a.out\nFormat=Mach-O thin (arm64)\nCodeDirectory v=20400 flags=0x20002(adhoc,linker-signed)\nSignature=adhoc\nTeamIdentifier=not set") == .adhoc)
        #expect(Parse.codesign("/tmp/x: code object is not signed at all") == .unsigned)
        #expect(Parse.codesign("something unexpected") == .unreadable)
        let mas = "Identifier=com.example.app\nAuthority=Apple Mac OS Application Signing\nAuthority=Apple Worldwide Developer Relations Certification Authority\nTeamIdentifier=ABCDE12345"
        #expect(Parse.codesign(mas) == .developer(name: "Mac App Store", team: "ABCDE12345"))
    }

    @Test func nettopTraffic() {
        let s = """
        ,bytes_in,bytes_out,
        launchd.1,0,0,
        mDNSResponder.519,23205107,17276790,
        Google Chrome H.4521,1500,2750,
        garbage line
        AnyDesk.999,12,34,
        """
        let t = Parse.nettop(s)
        #expect(t[519] == Traffic(inBytes: 23_205_107, outBytes: 17_276_790))
        #expect(t[4521] == Traffic(inBytes: 1500, outBytes: 2750), "process names may contain spaces")
        #expect(t[999]?.outBytes == 34 && t[1]?.inBytes == 0 && t.count == 4)
    }

    @Test func assortedStatusOutputs() {
        #expect(Parse.screenLock("2026-11-17 03:49:53.553 sysadminctl[1:2] screenLock delay is 300 seconds") == 300)
        #expect(Parse.screenLock("screenLock delay is immediate") == 0)
        #expect(Parse.screenLock("screenLock is off") == -1)
        #expect(Parse.screenLock("???") == nil)
        let e = Parse.enrollment("Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)")
        #expect(e.dep == .off && e.mdm == .on)
        #expect(Parse.enrollment("").mdm == .unknown)
        #expect(Parse.contains("FileVault is On.", on: ["FileVault is On"], off: ["FileVault is Off"]) == .on)
        #expect(Parse.contains("FileVault is Off.", on: ["FileVault is On"], off: ["FileVault is Off"]) == .off)
        #expect(Parse.contains("Firewall is disabled. (State = 0)", on: ["State = 1", "State = 2"], off: ["State = 0", "disabled"]) == .off)
        #expect(Parse.contains("", on: ["x"], off: ["y"]) == .unknown)
    }

    @Test func privacyDatabase() throws {
        let path = NSTemporaryDirectory() + "/warden-tcc-\(UUID()).db"
        defer { try? FileManager.default.removeItem(atPath: path) }
        var db: OpaquePointer?
        #expect(sqlite3_open(path, &db) == SQLITE_OK)
        sqlite3_exec(db, """
        CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER, auth_reason INTEGER, last_modified INTEGER);
        INSERT INTO access VALUES ('kTCCServiceScreenCapture','com.philandro.anydesk',0,2,4,1760000000);
        INSERT INTO access VALUES ('kTCCServiceAccessibility','com.philandro.anydesk',0,2,4,1760000100);
        INSERT INTO access VALUES ('kTCCServiceCamera','us.zoom.xos',0,0,4,1760000200);
        INSERT INTO access VALUES ('kTCCServiceListenEvent','/usr/local/bin/keylogger',1,2,4,0);
        """, nil, nil, nil)
        sqlite3_close(db)
        let g = try #require(TCC.read(path: path))
        #expect(g.count == 3, "denied (auth_value 0) entries are not grants")
        #expect(g.contains(TCCGrant(service: "kTCCServiceListenEvent", client: "/usr/local/bin/keylogger", clientIsPath: true, lastModified: nil)))
        #expect(g.first { $0.client == "com.philandro.anydesk" }?.lastModified != nil)
        #expect(TCC.read(path: "/nonexistent/TCC.db") == nil, "no Full Disk Access: unreadable, not empty")
    }
}

@Suite struct KnownToolsTests {
    @Test func recognisesTheUsualSuspectsByProcessPath() {
        let cases: [(String, String?)] = [
            ("/Applications/AnyDesk.app/Contents/MacOS/AnyDesk", "anydesk"),
            ("/Applications/TeamViewer.app/Contents/MacOS/TeamViewer_Service", "teamviewer"),
            ("/Applications/TeamViewerQS.app/Contents/MacOS/TeamViewerQS", "teamviewer"),
            ("/Users/dot/Downloads/RustDesk.app/Contents/MacOS/rustdesk", "rustdesk"),
            ("/Applications/ScreenConnect Client (abc123).app/Contents/MacOS/ScreenConnect Client", "screenconnect"),
            ("/Applications/Splashtop Streamer.app/Contents/MacOS/Splashtop Streamer", "splashtop"),
            ("/usr/local/bin/dwagent", "dwservice"),
            ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", nil),
            ("/System/Library/PrivateFrameworks/Parsec.framework/Support/parsecd", nil),
            ("/usr/bin/python3", nil),
            ("/Applications/Safari.app/Contents/MacOS/Safari", nil),
            ("/Applications/Synchronize Pro.app/Contents/MacOS/Synchronize Pro", nil),
            ("/Applications/Parallels Desktop.app/Contents/MacOS/prl_client_app", nil),
            ("/Library/PrivilegedHelperTools/com.teamviewer.Helper", nil),
        ]
        for (cmd, want) in cases { #expect(KnownTools.matchProcess(command: cmd)?.id == want, "\(cmd)") }
    }

    @Test func recognisesInstalledAppsByBundleIdOrName() {
        #expect(KnownTools.match(bundleID: "com.philandro.anydesk", name: nil)?.id == "anydesk")
        #expect(KnownTools.match(bundleID: "com.teamviewer.TeamViewerQS", name: nil)?.id == "teamviewer")
        #expect(KnownTools.match(bundleID: "", name: "AnyDesk")?.id == "anydesk")
        #expect(KnownTools.match(bundleID: "com.google.chromeremotedesktop", name: nil)?.id == "chromeremote")
        #expect(KnownTools.match(bundleID: "com.apple.Safari", name: "Safari") == nil)
        #expect(KnownTools.match(bundleID: "com.apple.RemoteDesktop", name: nil)?.builtIn == true)
        #expect(KnownTools.match(bundleID: "com.teamviewer", name: nil) == nil, "a prefix needs the trailing dot")
    }

    @Test func helpersAndScamFavourites() {
        #expect(KnownTools.matchHelper(label: "com.teamviewer.Helper")?.id == "teamviewer")
        #expect(KnownTools.matchHelper(label: "com.microsoft.update.agent") == nil)
        #expect(KnownTools.tool(id: "anydesk")?.scamFavourite == true)
        #expect(KnownTools.tool(id: "parsec")?.scamFavourite == false)
        #expect(Set(KnownTools.all.map(\.id)).count == KnownTools.all.count, "ids are unique")
    }
}
