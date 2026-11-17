import SwiftUI
import AppKit
import WardenCore

extension Severity {
    var color: Color {
        switch self {
        case .ok: return Color(red: 0.13, green: 0.58, blue: 0.33)
        case .info: return Color(red: 0.22, green: 0.45, blue: 0.85)
        case .attention: return Color(red: 0.88, green: 0.50, blue: 0.05)
        case .alert: return Color(red: 0.84, green: 0.16, blue: 0.16)
        }
    }
    var symbol: String {
        switch self {
        case .ok: return "checkmark.circle.fill"
        case .info: return "info.circle.fill"
        case .attention: return "exclamationmark.triangle.fill"
        case .alert: return "exclamationmark.octagon.fill"
        }
    }
}

struct PopoverView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        ZStack(alignment: .bottom) {
            VStack(spacing: 0) {
                header
                shieldRow
                Divider()
                content
                Divider()
                footer
            }
            if let t = model.toast {
                Text(t).font(.system(size: 12, weight: .medium)).multilineTextAlignment(.center)
                    .padding(.horizontal, 14).padding(.vertical, 9)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color(nsColor: .labelColor).opacity(0.9)))
                    .foregroundStyle(Color(nsColor: .windowBackgroundColor)).padding(.bottom, 52).padding(.horizontal, 24)
            }
        }
        .frame(width: 440, height: 640)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    var header: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous).fill(model.severity == .ok ? Severity.ok.color : model.severity.color)
                Image(systemName: model.severity == .ok ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                    .font(.system(size: 20, weight: .bold)).foregroundStyle(.white)
            }.frame(width: 40, height: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text("Warden").font(.system(size: 15, weight: .bold))
                Text(model.checking && model.report == nil ? "Checking your Mac…" : (model.report?.headline ?? "Checking your Mac…"))
                    .font(.system(size: 12)).foregroundStyle(model.severity >= .attention ? model.severity.color : Color.secondary)
            }
            Spacer()
            Button { model.runAudit() } label: {
                if model.checking { ProgressView().controlSize(.small) } else { Label("Check again", systemImage: "arrow.clockwise") }
            }.disabled(model.checking).controlSize(.small)
        }
        .padding(.horizontal, 14).padding(.top, 12).padding(.bottom, 8)
    }

    var shieldRow: some View {
        HStack(spacing: 8) {
            Image(systemName: model.shieldOn ? "dot.radiowaves.left.and.right" : "moon.zzz.fill").foregroundStyle(model.shieldOn ? Severity.ok.color : Color.secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text("Shield").font(.system(size: 12, weight: .semibold))
                Text(model.shieldOn ? "Warns you the moment a remote-control program opens" : "Off — nothing is watching right now")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("", isOn: Binding(get: { model.shieldOn }, set: { model.setShield($0) })).labelsHidden().toggleStyle(.switch).controlSize(.small)
        }
        .padding(.horizontal, 14).padding(.bottom, 10)
    }

    @ViewBuilder var content: some View {
        if let r = model.report {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 8) {
                    ForEach([Severity.alert, .attention, .info], id: \.self) { sev in
                        let items = r.findings.filter { $0.severity == sev }
                        if !items.isEmpty {
                            Text(sev.label.uppercased()).font(.system(size: 10, weight: .bold)).foregroundStyle(sev.color).padding(.top, 6)
                            ForEach(items) { f in FindingCard(model: model, finding: f) }
                        }
                    }
                    let good = r.findings.filter { $0.severity == .ok }
                    if !good.isEmpty {
                        Text("LOOKS GOOD").font(.system(size: 10, weight: .bold)).foregroundStyle(Severity.ok.color).padding(.top, 6)
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(good) { f in
                                HStack(alignment: .top, spacing: 8) {
                                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Severity.ok.color).font(.system(size: 13))
                                    Text(f.title).font(.system(size: 12))
                                }
                            }
                        }
                        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Severity.ok.color.opacity(0.08)))
                    }
                    if !model.trustedIDs.isEmpty {
                        Text("TOOLS YOU SAID YOU USE").font(.system(size: 10, weight: .bold)).foregroundStyle(.secondary).padding(.top, 6)
                        ForEach(model.trustedIDs.sorted(), id: \.self) { id in
                            HStack {
                                Text(KnownTools.tool(id: id)?.name ?? id).font(.system(size: 12))
                                Spacer()
                                Button("Warn me again") { model.untrustTool(id) }.controlSize(.small)
                            }
                        }
                    }
                }
                .padding(12)
            }
        } else {
            VStack(spacing: 10) {
                Spacer(); ProgressView(); Text("Looking at your Mac…").foregroundStyle(.secondary); Spacer()
            }.frame(maxWidth: .infinity)
        }
    }

    var footer: some View {
        VStack(spacing: 6) {
            HStack {
                Button { model.copySummary() } label: { Label("Copy a summary for my family", systemImage: "doc.on.doc") }
                    .controlSize(.small).disabled(model.report == nil)
                Spacer()
                if let h = model.helper {
                    Button { model.callHelper() } label: { Label("Call \(h.name)", systemImage: "phone.fill") }.controlSize(.small)
                }
            }
            HStack {
                Toggle("Open Warden when this Mac starts", isOn: Binding(get: { model.openAtLogin }, set: { model.openAtLogin = $0 }))
                    .toggleStyle(.checkbox).controlSize(.small).font(.system(size: 11))
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }.controlSize(.small)
                    .help("Quit Warden. The shield stops until you open it again.")
            }
            Text("Warden only looks. It changes nothing on your Mac and sends nothing anywhere.")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }
}

struct FindingCard: View {
    @ObservedObject var model: AppModel
    let finding: Finding

    var open: Bool { model.expanded.contains(finding.id) }

    var toolID: String? {
        for p in ["remote-running-", "remote-active-"] where finding.id.hasPrefix(p) {
            let id = String(finding.id.dropFirst(p.count))
            return KnownTools.tool(id: id)?.builtIn == false ? id : nil
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button { model.toggle(finding.id) } label: {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: finding.severity.symbol).foregroundStyle(finding.severity.color).font(.system(size: 16))
                    Text(finding.title).font(.system(size: 13, weight: .semibold)).multilineTextAlignment(.leading).frame(maxWidth: .infinity, alignment: .leading)
                    Image(systemName: open ? "chevron.up" : "chevron.down").font(.system(size: 10, weight: .semibold)).foregroundStyle(.tertiary).padding(.top, 4)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if open {
                Text(finding.why).font(.system(size: 12)).foregroundStyle(.primary.opacity(0.85)).fixedSize(horizontal: false, vertical: true)
                if !finding.detail.isEmpty {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(finding.detail.prefix(10), id: \.self) { d in
                            Text("• " + d).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(2)
                        }
                    }
                    .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.05)))
                }
                HStack(spacing: 8) {
                    ForEach(finding.fixes, id: \.self) { fix in
                        if fix.kind == .quitProcess {
                            Button(fix.label) { model.apply(fix) }.buttonStyle(.borderedProminent).tint(Severity.alert.color).controlSize(.small)
                        } else {
                            Button(fix.label) { model.apply(fix) }.controlSize(.small)
                        }
                    }
                    if let id = toolID, finding.severity < .alert {
                        Button("I use this one") { model.trustTool(id) }.controlSize(.small)
                    }
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(finding.severity.color.opacity(finding.severity == .alert ? 0.12 : 0.07)))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).stroke(finding.severity.color.opacity(finding.severity >= .attention ? 0.4 : 0.15), lineWidth: 1))
    }
}

/// The stop sign: appears above everything when a remote-control program opens or seems connected.
struct ShieldAlertView: View {
    @ObservedObject var model: AppModel
    let event: ShieldEvent

    var session: Bool { event.kind == .sessionLikely }
    var color: Color { session ? Severity.alert.color : Severity.attention.color }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: session ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill").font(.system(size: 40)).foregroundStyle(color)
                VStack(alignment: .leading, spacing: 4) {
                    Text(session ? "Someone may be controlling your Mac" : "\(event.tool.name) just opened")
                        .font(.system(size: 20, weight: .bold)).fixedSize(horizontal: false, vertical: true)
                    Text(event.detail).font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            VStack(alignment: .leading, spacing: 8) {
                Text("Did someone phone, message or email you and tell you to open this?").font(.system(size: 14, weight: .semibold))
                Text("Then it is a scam. Hang up. Real support from Apple, your bank or your internet provider never asks you to install a program like this, and never needs a code, a password or your card number.")
                    .font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
            }
            .padding(14).frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(color.opacity(0.12)))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).stroke(color.opacity(0.5), lineWidth: 1.5))

            VStack(spacing: 10) {
                Button { model.closeAlertedTool() } label: {
                    Text("Close \(event.tool.name) now").font(.system(size: 17, weight: .bold)).frame(maxWidth: .infinity).padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent).tint(Severity.alert.color).controlSize(.large)
                if let h = model.helper {
                    Button { model.callHelper() } label: {
                        Label("Call \(h.name)", systemImage: "phone.fill").font(.system(size: 15, weight: .semibold)).frame(maxWidth: .infinity).padding(.vertical, 4)
                    }.buttonStyle(.bordered).controlSize(.large)
                }
                HStack {
                    Button("I know what this is") { model.dismissAlert() }
                    Spacer()
                    Button("I use \(event.tool.name) — don't warn me") { model.trustTool(event.tool.id) }
                }.controlSize(.small)
            }
        }
        .padding(24)
        .frame(width: 520)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}
