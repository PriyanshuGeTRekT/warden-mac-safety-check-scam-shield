import AppKit
import SwiftUI
import Combine
import UserNotifications
import WardenCore

/// The shield-with-a-tick icon, drawn in code: `WardenBar --make-icon <dir.iconset>`.
@MainActor
enum IconMaker {
    struct IconView: View {
        let s: CGFloat
        var body: some View {
            ZStack {
                RoundedRectangle(cornerRadius: s * 0.225, style: .continuous)
                    .fill(LinearGradient(colors: [Color(red: 0.10, green: 0.62, blue: 0.60), Color(red: 0.08, green: 0.36, blue: 0.62)],
                                         startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: s * 0.82, height: s * 0.82)
                    .shadow(color: .black.opacity(0.25), radius: s * 0.02, y: s * 0.012)
                Image(systemName: "checkmark.shield.fill").font(.system(size: s * 0.44, weight: .bold)).foregroundStyle(.white)
            }.frame(width: s, height: s)
        }
    }
    static func run(dir: String) {
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        for (name, px) in [("icon_16x16", 16), ("icon_16x16@2x", 32), ("icon_32x32", 32), ("icon_32x32@2x", 64), ("icon_128x128", 128), ("icon_128x128@2x", 256),
                           ("icon_256x256", 256), ("icon_256x256@2x", 512), ("icon_512x512", 512), ("icon_512x512@2x", 1024)] as [(String, CGFloat)] {
            let r = ImageRenderer(content: IconView(s: px)); r.scale = 1
            if let img = r.nsImage, let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff), let png = rep.representation(using: .png, properties: [:]) {
                try? png.write(to: URL(fileURLWithPath: dir + "/" + name + ".png"))
            }
        }
    }
}

/// Floats above everything, so the stop sign cannot be hidden behind the very window that is causing it.
@MainActor
final class AlertPanel: NSPanel {
    init(model: AppModel, event: ShieldEvent) {
        let host = NSHostingView(rootView: ShieldAlertView(model: model, event: event))
        host.sizingOptions = [.intrinsicContentSize]
        super.init(contentRect: NSRect(origin: .zero, size: host.fittingSize), styleMask: [.titled, .nonactivatingPanel, .fullSizeContentView],
                   backing: .buffered, defer: false)
        titlebarAppearsTransparent = true
        titleVisibility = .hidden
        isFloatingPanel = true
        level = .screenSaver
        collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        hidesOnDeactivate = false
        isMovableByWindowBackground = true
        contentView = host
        setContentSize(host.fittingSize)
        if let f = NSScreen.main?.visibleFrame { setFrameOrigin(NSPoint(x: f.midX - frame.width / 2, y: f.maxY - frame.height - 60)) }
    }
    override var canBecomeKey: Bool { true }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate, UNUserNotificationCenterDelegate {
    var statusItem: NSStatusItem!
    let popover = NSPopover()
    var model: AppModel!
    var panel: AlertPanel?
    var bag = Set<AnyCancellable>()
    var signalSources: [DispatchSourceSignal] = []

    func applicationWillTerminate(_ n: Notification) { LiveProbe.shutdown() }

    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.accessory)
        model = AppModel()
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.target = self
        statusItem.button?.action = #selector(toggle(_:))
        popover.behavior = .transient
        popover.delegate = self
        popover.contentSize = NSSize(width: 440, height: 640)
        popover.contentViewController = NSHostingController(rootView: PopoverView(model: model))
        if Bundle.main.bundleURL.pathExtension == "app" { UNUserNotificationCenter.current().delegate = self }
        model.start()
        for sig in [SIGTERM, SIGINT, SIGHUP] {
            signal(sig, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
            src.setEventHandler { LiveProbe.shutdown(); exit(0) }
            src.resume()
            signalSources.append(src)
        }
        updateIcon()
        model.objectWillChange.sink { [weak self] _ in DispatchQueue.main.async { self?.refresh() } }.store(in: &bag)
    }

    func refresh() {
        updateIcon()
        debugLog("refresh: alert=\(model.alert?.tool.id ?? "none") panelVisible=\(panel?.isVisible ?? false)")
        if let e = model.alert {
            if panel == nil || panel?.isVisible == false {
                let p = AlertPanel(model: model, event: e)
                panel = p
                p.orderFrontRegardless()
                debugLog("panel shown: frame=\(p.frame) visible=\(p.isVisible) level=\(p.level.rawValue)")
                NSSound(named: "Basso")?.play()
            }
        } else if let p = panel {
            p.orderOut(nil); panel = nil
        }
    }

    func updateIcon() {
        guard let button = statusItem?.button else { return }
        let sev = model.severity
        let name = sev == .ok || sev == .info ? "checkmark.shield" : "exclamationmark.shield.fill"
        var img = NSImage(systemSymbolName: name, accessibilityDescription: "Warden")
        switch sev {
        case .alert: img = img?.withSymbolConfiguration(.init(paletteColors: [.systemRed])); img?.isTemplate = false
        case .attention: img = img?.withSymbolConfiguration(.init(paletteColors: [.systemOrange])); img?.isTemplate = false
        default: img?.isTemplate = true
        }
        button.image = img
        button.toolTip = model.alert != nil ? "Warden: a remote-control program needs your attention" : "Warden — \(model.report?.headline ?? "checking…")"
    }

    @objc func toggle(_ sender: Any?) {
        if popover.isShown { popover.performClose(sender) }
        else if let b = statusItem.button { popover.show(relativeTo: b.bounds, of: b, preferredEdge: .minY); NSApp.activate(ignoringOtherApps: true) }
    }

    nonisolated func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification, withCompletionHandler h: @escaping (UNNotificationPresentationOptions) -> Void) { h([.banner, .sound]) }
    nonisolated func userNotificationCenter(_ c: UNUserNotificationCenter, didReceive r: UNNotificationResponse, withCompletionHandler h: @escaping () -> Void) {
        Task { @MainActor in self.toggle(nil) }
        h()
    }
}

let args = CommandLine.arguments
if let i = args.firstIndex(of: "--make-icon"), args.count > i + 1 { MainActor.assumeIsolated { IconMaker.run(dir: args[i + 1]) }; exit(0) }
if let i = args.firstIndex(of: "--render") {
    let dir = args.count > i + 1 ? args[i + 1] : "."
    MainActor.assumeIsolated { RenderScenes.run(outDir: dir) }
    print("rendered to \(dir)"); exit(0)
}
if args.contains("--selftest") {
    let dir = NSTemporaryDirectory() + "/warden-selftest-\(UUID().uuidString)"
    let code = MainActor.assumeIsolated { RenderScenes.selftest(outDir: dir) }
    try? FileManager.default.removeItem(atPath: dir)
    exit(code)
}
let app = NSApplication.shared
let delegate = MainActor.assumeIsolated { AppDelegate() }
app.delegate = delegate
app.run()
