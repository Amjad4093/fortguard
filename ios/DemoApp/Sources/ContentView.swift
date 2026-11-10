import FortGuardSDK
import SwiftUI

/// One transfer screen that uses the SDK the way a bank app would, plus test controls
/// (server address, attestation level, forced conditions) that a real app would not have.
struct ContentView: View {
    @AppStorage("fgServer") private var server = "http://192.168.1.100:8080"
    @AppStorage("fgApiKey") private var apiKey = "dev-only-api-key"
    @AppStorage("fgUser") private var userId = "usr_" + String(UUID().uuidString.prefix(8)).lowercased()
    @AppStorage("fgName") private var customerName = "Demo Customer"
    @State private var shareLocation = FortGuard.shared.isLocationConsent
    @State private var level = "STRONG"
    @State private var consent = true
    @State private var forced: Set<String> = []
    @State private var account = ""
    @State private var amount = ""
    @State private var accountLength = 0
    @State private var amountLength = 0
    @State private var newPayee = true
    @State private var result = ""
    @State private var resultColor = Color.secondary
    @State private var busy = false
    @State private var showBatch = false
    @FocusState private var focus: Field?

    private static let levelBox = LevelBox()
    private let forcedOptions: [(String, String)] = [
        ("active_call", "On a call"), ("screen_sharing", "Screen sharing"),
        ("active_remote_software", "Remote-access tool"), ("is_rooted", "Jailbroken"), ("vpn", "VPN"),
    ]

    var body: some View {
        NavigationView {
            ScrollViewReader { proxy in
            Form {
                Section(footer: Text("Test app for the FortGuard SDK. Attestation is simulated by a server running with --dev. Typed text never leaves the phone: only edit timing and the field name.")) {
                    TextField("Your full name", text: $customerName)
                        .onChange(of: customerName) { FortGuard.shared.identify(userId: userId, customerName: $0) }
                        .onAppear { FortGuard.shared.identify(userId: userId, customerName: customerName) }
                    Toggle("Share my approximate location (rounded to about 1 km)", isOn: $shareLocation)
                        .onChange(of: shareLocation) { FortGuard.shared.setLocationConsent($0) }
                    TextField("Server address", text: $server)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("API key (plays the bank's server)", text: $apiKey)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Picker("Attestation level", selection: $level) {
                        ForEach(["STRONG", "DEVICE", "BASIC"], id: \.self) { Text($0) }
                    }
                    .pickerStyle(.segmented)
                    .onChange(of: level) { Self.levelBox.value = $0 }
                    HStack {
                        Button("Connect") { connect() }
                        Spacer()
                        Button("Re-enroll") { FortGuard.shared.reenroll { show($0.message, .secondary) } }
                    }
                }

                Section(header: Text("Status")) {
                    TimelineView(.periodic(from: .now, by: 1)) { _ in
                        Text(statusText()).font(.footnote).textSelection(.enabled)
                    }
                    HStack {
                        Button("New session") { account = ""; amount = ""; FortGuard.shared.newSession(); result = "" }
                        Spacer()
                        Button("Last batch") { showBatch = true }
                    }
                }

                Section(header: Text("Force conditions (testing only)"),
                        footer: Text("The SDK detects these itself. Forcing one on tests the server's rules; it cannot hide a real detection.")) {
                    ForEach(forcedOptions, id: \.0) { key, label in
                        Toggle(label, isOn: Binding(
                            get: { forced.contains(key) },
                            set: { on in
                                if on { forced.insert(key) } else { forced.remove(key) }
                                FortGuard.shared.setDebugOverride(key, on)
                            }))
                    }
                    Toggle("User consents to behavioral capture", isOn: $consent)
                        .onChange(of: consent) { FortGuard.shared.setConsent($0) }
                }

                Section(header: Text("Transfer")) {
                    TextField("Beneficiary account", text: $account)
                        .textInputAutocapitalization(.characters).autocorrectionDisabled()
                        .focused($focus, equals: .beneficiaryAccount)
                        .onChange(of: account) { new in
                            FortGuard.shared.recordEdit(field: .beneficiaryAccount, oldLength: accountLength, newLength: new.count)
                            accountLength = new.count
                        }
                    TextField("Amount (PKR)", text: $amount)
                        .keyboardType(.decimalPad)
                        .focused($focus, equals: .amount)
                        .onChange(of: amount) { new in
                            FortGuard.shared.recordEdit(field: .amount, oldLength: amountLength, newLength: new.count)
                            amountLength = new.count
                        }
                    Toggle("New beneficiary", isOn: $newPayee)
                    Button(busy ? "Checking…" : "Check risk") { checkRisk() }
                        .disabled(busy)
                        .accessibilityIdentifier("checkRisk")
                }
                .onChange(of: focus) { f in if let f = f { FortGuard.shared.recordFocus(field: f) } }

                if !result.isEmpty {
                    Section(header: Text("Decision")) {
                        Text(result).foregroundColor(resultColor).textSelection(.enabled)
                            .accessibilityIdentifier("decision")
                    }
                    .id("decision")
                }
            }
            .onChange(of: result) { _ in
                // bring the decision into view when it arrives
                DispatchQueue.main.async { withAnimation { proxy.scrollTo("decision", anchor: .top) } }
            }
            }
            .navigationTitle("FortGuard Demo")
        }
        .navigationViewStyle(.stack)
        .sheet(isPresented: $showBatch) {
            NavigationView {
                ScrollView {
                    Text(FortGuard.shared.lastBatchJSON ?? "Nothing sent yet.")
                        .font(.system(.caption2, design: .monospaced)).textSelection(.enabled).padding()
                }
                .navigationTitle("Last batch (no typed text)")
                .toolbar { Button("Close") { showBatch = false } }
            }
        }
        .onAppear {
            if let s = UserDefaults.standard.string(forKey: "fgServerOverride") ?? ProcessInfo.processInfo.launchArgumentValue("-fgServer") {
                server = s
            }
            connect()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { FortGuard.shared.attachToKeyWindow() }
            if UserDefaults.standard.bool(forKey: "fgAutoTest") { autoTest() }
        }
    }

    private func connect() {
        Self.levelBox.value = level
        FortGuard.shared.configure(.init(baseURL: server, appId: Bundle.main.bundleIdentifier ?? "com.example.mobilebank",
                                         devAttestation: true, devAttestationLevel: { ContentView.levelBox.value },
                                         allowDebugOverrides: true))
        FortGuard.shared.setConsent(consent)
    }

    private func statusText() -> String {
        let s = FortGuard.shared.status()
        let flagged = s.environment.filter { $0.key != "os" && $0.key != "os_version" && $0.value == .bool(true) }.keys.sorted()
        return """
        Device: \(s.deviceGuid ?? "starting")
        Enrollment: \(s.enrolledLevel.map { "enrolled, attestation \($0) (simulated)" } ?? "not yet")
        Session: \(s.sessionId ?? "-")
        Motion sensors: \(s.motionSensors)
        Captured: \(s.counts.touch) touch, \(s.counts.keys) edits, \(s.counts.ui) UI, \(s.counts.sensor) motion
        Device checks: \(flagged.isEmpty ? "nothing flagged" : flagged.joined(separator: ", "))
        Last: \(s.lastMessage)
        """
    }

    private func show(_ text: String, _ color: Color) { result = text; resultColor = color }

    private func checkRisk() {
        let acct = account.trimmingCharacters(in: .whitespaces)
        guard (8...40).contains(acct.count) else { return show("Enter a beneficiary account of 8 to 40 characters.", .red) }
        guard let amt = Double(amount.replacingOccurrences(of: ",", with: "")), amt > 0 else { return show("Enter an amount greater than zero.", .red) }
        busy = true
        show("Sending telemetry and asking for a decision…", .secondary)
        let server = self.server, key = apiKey, user = userId, payee = newPayee
        FortGuard.shared.submit { outcome in
            guard outcome.ok, let session = FortGuard.shared.sessionId else {
                busy = false
                return show("Telemetry not accepted: \(outcome.message)", .red)
            }
            DispatchQueue.global().async {
                let r = DemoBackend.evaluate(server: server, apiKey: key, sessionId: session, userId: user, amount: amt,
                                             beneficiary: acct, newPayee: payee)
                DispatchQueue.main.async {
                    busy = false
                    switch r {
                    case .success(let d): showDecision(d)
                    case .failure(let e): show("Evaluate failed: \(e.description)", .red)
                    }
                }
            }
        }
    }

    private func showDecision(_ d: DemoBackend.Decision) {
        var lines = ["\(d.level.replacingOccurrences(of: "_", with: " "))   \(d.score) / 1000",
                     DemoBackend.actions[d.action] ?? d.action, ""]
        if d.breakdown.isEmpty { lines.append("No risk signals fired.") }
        for (reason, points) in d.breakdown { lines.append("+\(points)  \(DemoBackend.reasons[reason] ?? reason)") }
        lines.append("")
        lines.append("Bot \(Int(d.bot * 100))%, coercion \(Int(d.coercion * 100))%, remote tool \(d.remoteTool ? "yes" : "no"). Scored in \(d.latencyMs) ms.")
        let color: Color = d.level == "ALLOW" ? .green : (d.level == "STEP_UP" ? .orange : .red)
        show(lines.joined(separator: "\n"), color)
    }

    /// Used by the cloud build: fills the form like a person, then asks for a decision.
    private func autoTest() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
            let target = "PK36EXMP00992201029381"
            for (i, _) in target.enumerated() {
                DispatchQueue.main.asyncAfter(deadline: .now() + Double(i) * 0.15 + Double(i % 3) * 0.05) {
                    account = String(target.prefix(i + 1))
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 4.5) {
                for (i, ch) in "250000".enumerated() {
                    DispatchQueue.main.asyncAfter(deadline: .now() + Double(i) * 0.2) { amount += String(ch) }
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 7) { checkRisk() }
        }
    }
}

/// Lets the SDK read the picker from its background queue without touching SwiftUI state.
final class LevelBox {
    private let lock = NSLock()
    private var stored = "STRONG"
    var value: String {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); stored = newValue; lock.unlock() }
    }
}

extension ProcessInfo {
    func launchArgumentValue(_ name: String) -> String? {
        guard let i = arguments.firstIndex(of: name), i + 1 < arguments.count else { return nil }
        return arguments[i + 1]
    }
}
