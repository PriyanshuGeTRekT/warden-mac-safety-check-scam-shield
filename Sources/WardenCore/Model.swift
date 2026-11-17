import Foundation

public enum Severity: Int, Codable, Comparable, CaseIterable {
    case ok = 0, info, attention, alert

    public static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }

    public var label: String {
        switch self {
        case .ok: return "Looks good"
        case .info: return "Good to know"
        case .attention: return "Worth a look"
        case .alert: return "Needs attention now"
        }
    }
}

public enum Category: String, Codable, CaseIterable {
    case remoteAccess, sharing, device, network, startup, permissions, accounts, basics

    public var label: String {
        switch self {
        case .remoteAccess: return "Remote control"
        case .sharing: return "Sharing"
        case .device: return "Who manages this Mac"
        case .network: return "Internet settings"
        case .startup: return "Things that start by themselves"
        case .permissions: return "What apps may see and do"
        case .accounts: return "Accounts"
        case .basics: return "Protection basics"
        }
    }
}

/// Warden never changes system settings itself: it opens the right place, or closes a running tool the person chose to close.
public struct Fix: Codable, Equatable, Hashable {
    public enum Kind: String, Codable { case openSettings, revealInFinder, quitProcess }
    public var kind: Kind
    public var label: String
    /// URL (openSettings), path (revealInFinder) or process id (quitProcess)
    public var target: String

    public init(kind: Kind, label: String, target: String) { self.kind = kind; self.label = label; self.target = target }

    public static func settings(_ label: String, _ pane: String) -> Fix {
        Fix(kind: .openSettings, label: label, target: "x-apple.systempreferences:" + pane)
    }
}

public enum SettingsPane {
    public static let sharing = "com.apple.Sharing-Settings.extension"
    public static let privacy = "com.apple.settings.PrivacySecurity.extension"
    public static let fullDisk = "com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles"
    public static let screenRecording = "com.apple.settings.PrivacySecurity.extension?Privacy_ScreenCapture"
    public static let accessibility = "com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility"
    public static let loginItems = "com.apple.LoginItems-Settings.extension"
    public static let users = "com.apple.Users-Groups-Settings.extension"
    public static let network = "com.apple.Network-Settings.extension"
}

public struct Finding: Codable, Equatable, Identifiable {
    public var id: String
    public var category: Category
    public var severity: Severity
    public var title: String
    /// What this means, in plain words.
    public var why: String
    /// Evidence: app names, ports, paths.
    public var detail: [String]
    public var fixes: [Fix]

    public init(id: String, category: Category, severity: Severity, title: String, why: String,
                detail: [String] = [], fixes: [Fix] = []) {
        self.id = id; self.category = category; self.severity = severity
        self.title = title; self.why = why; self.detail = detail; self.fixes = fixes
    }
}

public struct Report: Codable, Equatable {
    public var generated: Date
    public var findings: [Finding]

    public init(generated: Date, findings: [Finding]) {
        self.generated = generated
        self.findings = findings.sorted { ($0.severity, $1.id) > ($1.severity, $0.id) }
    }

    public var worst: Severity { findings.map { $0.severity }.max() ?? .ok }
    public func count(_ s: Severity) -> Int { findings.filter { $0.severity == s }.count }

    public var headline: String {
        let a = count(.alert), t = count(.attention)
        if a > 0 { return a == 1 ? "1 thing needs your attention now" : "\(a) things need your attention now" }
        if t > 0 { return t == 1 ? "1 thing is worth a look" : "\(t) things are worth a look" }
        return "Nothing worrying found"
    }

    /// Plain text a person can paste into a message to whoever helps them with the computer.
    public func summaryText(machine: String, os: String) -> String {
        var lines = ["Warden safety check — \(machine), \(os)",
                     "Checked on \(DateFormatter.localizedString(from: generated, dateStyle: .medium, timeStyle: .short))",
                     headline.uppercased(), ""]
        for sev in [Severity.alert, .attention, .info] {
            let fs = findings.filter { $0.severity == sev }
            guard !fs.isEmpty else { continue }
            lines.append("— \(sev.label) —")
            for f in fs {
                lines.append("• \(f.title)")
                for d in f.detail.prefix(6) { lines.append("    \(d)") }
            }
            lines.append("")
        }
        let ok = findings.filter { $0.severity == .ok }
        if !ok.isEmpty { lines.append("Looks good: " + ok.map { $0.title }.joined(separator: "; ")) }
        return lines.joined(separator: "\n")
    }
}
