import SwiftUI
import AppKit
import WardenCore
import UserNotifications
import ServiceManagement

/// `WARDEN_DEBUG=1` prints what the shield sees to stderr.
func debugLog(_ s: @autoclosure () -> String) {
    if ProcessInfo.processInfo.environment["WARDEN_DEBUG"] != nil { FileHandle.standardError.write(("warden: " + s() + "\n").data(using: .utf8)!) }
}

@MainActor
final class AppModel: ObservableObject {
    let probe: SystemProbe
    let trust: TrustStore
    let monitor: ShieldMonitor

    @Published var report: Report?
    @Published var checking = false
    @Published var shieldOn = true
    @Published var alert: ShieldEvent?
    @Published var expanded: Set<String> = []
    @Published var toast: String?
    @Published var helper: HelperContact?
    @Published var trustedIDs: Set<String> = []

    var onAlert: (() -> Void)?
    private let queue = DispatchQueue(label: "app.warden.shield", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var toastTask: Task<Void, Never>?
    private var launchObserver: NSObjectProtocol?

    init(probe: SystemProbe = LiveProbe(), trust: TrustStore = .standard(), controller: ProcessController = LiveProcessController()) {
        self.probe = probe
        self.trust = trust
        self.monitor = ShieldMonitor(probe: probe, trust: trust, controller: controller)
        self.trustedIDs = trust.ids
        self.helper = HelperContact.load()
    }

    var severity: Severity { alert != nil ? .alert : (report?.worst ?? .ok) }

    // MARK: lifecycle

    func start() {
        runAudit()
        startShield()
        if Bundle.main.bundleURL.pathExtension == "app" {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        }
        // a program opening is noticed at once instead of at the next 3-second check
        launchObserver = NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main) { [weak self] _ in
            self?.checkShieldNow()
        }
    }

    // MARK: the audit

    func runAudit() {
        guard !checking else { return }
        checking = true
        let probe = self.probe, trusted = trust.ids
        Task.detached(priority: .userInitiated) { [model = self] in
            let r = Audit(probe: probe, trusted: trusted).run()
            await MainActor.run {
                model.report = r
                model.checking = false
                for f in r.findings where f.severity == .alert { model.expanded.insert(f.id) }
            }
        }
    }

    func toggle(_ id: String) {
        if expanded.contains(id) { expanded.remove(id) } else { expanded.insert(id) }
    }

    // MARK: the shield

    func setShield(_ on: Bool) {
        shieldOn = on
        if on { startShield() } else { timer?.cancel(); timer = nil }
    }

    func startShield() {
        guard timer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 1, repeating: 3, leeway: .milliseconds(500))
        t.setEventHandler { [model = self] in
            let events = model.monitor.tick()
            debugLog("shield tick: \(events.count) event(s) \(events.map { $0.kind.rawValue })")
            if !events.isEmpty { DispatchQueue.main.async { model.handle(events) } }
        }
        t.resume()
        timer = t
    }

    func checkShieldNow() {
        queue.async { [model = self] in
            let events = model.monitor.tick()
            if !events.isEmpty { DispatchQueue.main.async { model.handle(events) } }
        }
    }

    func handle(_ events: [ShieldEvent]) {
        debugLog("handle \(events.map { "\($0.kind.rawValue):\($0.tool.id) trusted=\($0.trusted)" })")
        for e in events {
            switch e.kind {
            case .launched, .sessionLikely:
                if e.trusted {
                    show(e.kind == .launched ? "\(e.tool.name) opened (you use this one)." : "A \(e.tool.name) session seems to be active.")
                    continue
                }
                alert = e
                onAlert?()
                notify(e)
            case .sessionEnded:
                if alert?.tool.id == e.tool.id { show("\(e.tool.name) has gone quiet.") }
            case .quit:
                if alert?.tool.id == e.tool.id { alert = nil }
                runAudit()
            }
        }
    }

    private func notify(_ e: ShieldEvent) {
        guard Bundle.main.bundleURL.pathExtension == "app" else { return }
        let c = UNMutableNotificationContent()
        c.title = e.kind == .sessionLikely ? "Someone may be controlling your Mac" : "\(e.tool.name) just opened"
        c.body = e.kind == .sessionLikely ? "\(e.tool.name) seems to be connected. Open Warden to close it." : "If someone told you to open this, stop and hang up."
        c.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "warden-\(e.tool.id)-\(e.kind.rawValue)", content: c, trigger: nil))
    }

    // MARK: actions

    func dismissAlert() { alert = nil }

    func closeAlertedTool() {
        guard let e = alert else { return }
        queue.async { [model = self] in
            _ = model.monitor.tick() // make sure its processes are known
            let closed = model.monitor.close(toolID: e.tool.id)
            DispatchQueue.main.async {
                if closed.isEmpty {
                    model.show("Couldn't close \(e.tool.name). Quit it from its own menu, or from Activity Monitor.")
                } else {
                    model.alert = nil
                    model.show("\(e.tool.name) was closed.")
                    model.runAudit()
                }
            }
        }
    }

    func apply(_ fix: Fix) {
        switch fix.kind {
        case .openSettings:
            if let u = URL(string: fix.target) { NSWorkspace.shared.open(u) }
        case .revealInFinder:
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: fix.target)])
        case .quitProcess:
            let pids = fix.target.split(separator: ",").compactMap { Int32($0) }
            queue.async { [model = self] in
                let closed = model.monitor.close(pids: pids)
                DispatchQueue.main.async {
                    model.show(closed.isEmpty ? "Couldn't close it. Quit it from its own menu, or from Activity Monitor." : "Closed.")
                    model.runAudit()
                }
            }
        }
    }

    func trustTool(_ id: String) {
        trust.trust(id)
        trustedIDs = trust.ids
        if alert?.tool.id == id { alert = nil }
        runAudit()
    }

    func untrustTool(_ id: String) {
        trust.untrust(id)
        trustedIDs = trust.ids
        runAudit()
    }

    func callHelper() {
        guard let u = helper?.callURL else { return }
        NSWorkspace.shared.open(u)
    }

    /// The shield only protects while Warden runs, so it should start with the Mac.
    var openAtLogin: Bool {
        get { SMAppService.mainApp.status == .enabled }
        set {
            objectWillChange.send()
            do { if newValue { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() } }
            catch { show("macOS didn't allow that. Check System Settings › General › Login Items.") }
        }
    }

    func copySummary() {
        guard let r = report else { return }
        let text = r.summaryText(machine: Host.current().localizedName ?? "this Mac", os: ProcessInfo.processInfo.operatingSystemVersionString)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        show("Copied. Paste it into a message to whoever helps you with your computer.")
    }

    func show(_ text: String) {
        toast = text
        toastTask?.cancel()
        toastTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            if !Task.isCancelled { self?.toast = nil }
        }
    }
}
