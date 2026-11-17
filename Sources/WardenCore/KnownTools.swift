import Foundation

/// A program that lets someone else see or control this Mac from far away.
public struct RemoteTool: Equatable, Hashable {
    public let id: String
    public let name: String
    /// Bundle identifiers, matched exactly or as a prefix when they end with ".".
    public let bundleIDs: [String]
    /// Lower-case fragments of app/process names.
    public let names: [String]
    /// LaunchDaemon / helper-tool labels the tool installs.
    public let helperLabels: [String]
    /// Commonly used in "tech support" scams: a person should be extra careful with these.
    public let scamFavourite: Bool
    /// Made by Apple or otherwise built into the Mac.
    public let builtIn: Bool
    public let legitUse: String

    public init(id: String, name: String, bundleIDs: [String], names: [String], helperLabels: [String] = [],
                scamFavourite: Bool = true, builtIn: Bool = false, legitUse: String) {
        self.id = id; self.name = name; self.bundleIDs = bundleIDs; self.names = names
        self.helperLabels = helperLabels; self.scamFavourite = scamFavourite; self.builtIn = builtIn; self.legitUse = legitUse
    }
}

public enum KnownTools {
    public static let all: [RemoteTool] = [
        RemoteTool(id: "anydesk", name: "AnyDesk", bundleIDs: ["com.philandro.anydesk"], names: ["anydesk"],
                   helperLabels: ["com.philandro.anydesk"], legitUse: "IT support and working on your own computer from elsewhere"),
        RemoteTool(id: "teamviewer", name: "TeamViewer", bundleIDs: ["com.teamviewer."], names: ["teamviewer"],
                   helperLabels: ["com.teamviewer."], legitUse: "IT support and working on your own computer from elsewhere"),
        RemoteTool(id: "rustdesk", name: "RustDesk", bundleIDs: ["com.carriez.rustdesk"], names: ["rustdesk"],
                   helperLabels: ["com.carriez.rustdesk", "com.rustdesk."], legitUse: "open-source remote desktop"),
        RemoteTool(id: "screenconnect", name: "ConnectWise ScreenConnect", bundleIDs: ["com.elsinore.screenconnect", "com.connectwise."],
                   names: ["screenconnect", "connectwise"], helperLabels: ["screenconnect", "connectwisecontrol"],
                   legitUse: "IT support by a company that manages your computer"),
        RemoteTool(id: "splashtop", name: "Splashtop", bundleIDs: ["com.splashtop."], names: ["splashtop"],
                   helperLabels: ["com.splashtop."], legitUse: "IT support and remote access"),
        RemoteTool(id: "logmein", name: "LogMeIn / GoTo", bundleIDs: ["com.logmein.", "com.goto."],
                   names: ["logmein", "gotoassist", "goto resolve", "gotoresolve"], helperLabels: ["com.logmein.", "com.goto."],
                   legitUse: "IT support and remote access"),
        RemoteTool(id: "zohoassist", name: "Zoho Assist", bundleIDs: ["com.zohocorp.assist", "com.zoho.assist"], names: ["zoho assist", "zohoassist"],
                   legitUse: "IT support"),
        RemoteTool(id: "ultraviewer", name: "UltraViewer", bundleIDs: ["com.ultraviewer."], names: ["ultraviewer"], legitUse: "remote help"),
        RemoteTool(id: "supremo", name: "Supremo", bundleIDs: ["com.nanosystems.supremo"], names: ["supremo"], legitUse: "remote help"),
        RemoteTool(id: "ammyy", name: "Ammyy Admin", bundleIDs: ["com.ammyy."], names: ["ammyy"], legitUse: "remote help"),
        RemoteTool(id: "remotepc", name: "RemotePC", bundleIDs: ["com.idrive.remotepc", "com.iDrive.RemotePC"], names: ["remotepc"], legitUse: "remote access"),
        RemoteTool(id: "awesun", name: "AweSun", bundleIDs: ["com.oray.", "com.awesun."], names: ["awesun", "sunlogin"], legitUse: "remote access"),
        RemoteTool(id: "chromeremote", name: "Chrome Remote Desktop", bundleIDs: ["com.google.chromeremotedesktop"],
                   names: ["chromeremotedesktop", "chrome remote desktop", "chromoting"], helperLabels: ["org.chromium.chromoting"],
                   legitUse: "using your own computer from elsewhere"),
        RemoteTool(id: "vnc", name: "VNC", bundleIDs: ["com.realvnc.", "com.tightvnc.", "com.tigervnc."], names: ["vnc server", "vncserver", "vnc viewer", "tightvnc", "realvnc"],
                   helperLabels: ["com.realvnc."], scamFavourite: false, legitUse: "remote desktop for technical users"),
        RemoteTool(id: "nomachine", name: "NoMachine", bundleIDs: ["com.nomachine."], names: ["nomachine", "nxserver"],
                   helperLabels: ["com.nomachine."], scamFavourite: false, legitUse: "remote desktop"),
        RemoteTool(id: "dwservice", name: "DWService", bundleIDs: ["net.dwservice."], names: ["dwagent", "dwservice"], scamFavourite: false, legitUse: "remote support"),
        RemoteTool(id: "remoteutilities", name: "Remote Utilities", bundleIDs: ["com.remoteutilities."], names: ["remote utilities"], legitUse: "remote support"),
        RemoteTool(id: "jumpdesktop", name: "Jump Desktop Connect", bundleIDs: ["com.p5sys.jump.mac.connect"], names: ["jump desktop connect"],
                   scamFavourite: false, legitUse: "using your own computer from elsewhere"),
        RemoteTool(id: "beyondtrust", name: "BeyondTrust / Bomgar", bundleIDs: ["com.bomgar.", "com.beyondtrust."], names: ["bomgar", "beyondtrust"],
                   scamFavourite: false, legitUse: "company IT support"),
        RemoteTool(id: "parsec", name: "Parsec", bundleIDs: ["tv.parsec."], names: ["parsec"], scamFavourite: false, legitUse: "game streaming"),
        RemoteTool(id: "ard", name: "Apple Remote Management", bundleIDs: ["com.apple.remotedesktop"], names: ["ardagent", "remote management"],
                   scamFavourite: false, builtIn: true, legitUse: "company or school IT, or your own Macs"),
    ]

    public static func tool(id: String) -> RemoteTool? { all.first { $0.id == id } }

    static func matches(_ t: RemoteTool, bundleID: String) -> Bool {
        let b = bundleID.lowercased()
        return t.bundleIDs.contains { p in
            let p = p.lowercased()
            return p.hasSuffix(".") ? b.hasPrefix(p) : (b == p || b.hasPrefix(p + "."))
        }
    }

    static func matches(_ t: RemoteTool, text: String) -> Bool {
        let s = text.lowercased()
        return t.names.contains { s.contains($0) }
    }

    public static func match(bundleID: String?, name: String?, path: String? = nil) -> RemoteTool? {
        if let b = bundleID, !b.isEmpty, let t = all.first(where: { matches($0, bundleID: b) }) { return t }
        for text in [name, path.map { ($0 as NSString).lastPathComponent }].compactMap({ $0 }) {
            if let t = all.first(where: { matches($0, text: text) }) { return t }
        }
        return nil
    }

    /// For a running process: its executable path decides (an app bundle in the path names the app).
    public static func matchProcess(command: String) -> RemoteTool? {
        let lower = command.lowercased()
        // the app bundle name is the most reliable thing in the path: /Applications/AnyDesk.app/Contents/MacOS/AnyDesk
        if let r = lower.range(of: ".app/") {
            let bundle = String(lower[..<r.lowerBound])
            let app = (bundle as NSString).lastPathComponent
            if let t = all.first(where: { matches($0, text: app) }) { return t }
        }
        let exe = (lower as NSString).lastPathComponent
        return all.first { t in t.names.contains { exe == $0 || exe.hasPrefix($0 + "_") || exe.hasPrefix($0 + " ") } }
    }

    public static func matchHelper(label: String) -> RemoteTool? {
        let l = label.lowercased()
        return all.first { t in t.helperLabels.contains { l.hasPrefix($0.lowercased()) || l.contains($0.lowercased()) } }
    }
}
