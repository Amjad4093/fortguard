#if os(iOS)
import UIKit

/// FortGuard SDK for iOS.
///
/// ```swift
/// FortGuard.shared.configure(.init(baseURL: "https://risk.bank.example", appId: Bundle.main.bundleIdentifier!))
/// FortGuard.shared.attachToKeyWindow()                       // when the protected screen appears
/// FortGuard.shared.watch(beneficiaryField, field: .beneficiaryAccount)   // UIKit text fields
/// FortGuard.shared.recordEdit(field: .amount, oldLength: old, newLength: new) // SwiftUI .onChange
/// FortGuard.shared.submit { _ in bank.confirmTransfer(fortguardSession: FortGuard.shared.sessionId) }
/// ```
///
/// The SDK never reads what the user types. It records touch, the timing of edits, motion sensors and
/// device checks, signs each batch with a Secure Enclave key and sends it every few seconds.
public final class FortGuard {
    public struct Config {
        public var baseURL: String
        public var appId: String
        /// DEVELOPMENT ONLY: simulated attestation from a server running with --dev.
        public var devAttestation: Bool
        public var devAttestationLevel: () -> String
        /// Lets a test app force environment flags on. Never enable in a production build.
        public var allowDebugOverrides: Bool
        public var flushInterval: TimeInterval
        /// Production attestation (App Attest) goes here when it is built.
        public var attestationProvider: AttestationProvider?

        public init(baseURL: String, appId: String, devAttestation: Bool = true,
                    devAttestationLevel: @escaping () -> String = { "STRONG" }, allowDebugOverrides: Bool = false,
                    flushInterval: TimeInterval = 5, attestationProvider: AttestationProvider? = nil) {
            self.baseURL = baseURL
            self.appId = appId
            self.devAttestation = devAttestation
            self.devAttestationLevel = devAttestationLevel
            self.allowDebugOverrides = allowDebugOverrides
            self.flushInterval = flushInterval
            self.attestationProvider = attestationProvider
        }
    }

    public struct Status {
        public let deviceGuid: String?
        public let sessionId: String?
        public let enrolledLevel: String?
        public let counts: Counts
        public let environment: [String: JSON]
        public let motionSensors: String
        public let lastMessage: String
    }

    public static let shared = FortGuard()

    private let queue = DispatchQueue(label: "com.fortguard.sdk")
    private let buffer = EventBuffer()
    private let lock = NSLock()
    private var engine: FortGuardEngine?
    private var config: Config?
    private var env: EnvironmentChecks?
    private lazy var motion = MotionCapture(buffer: buffer)
    private var recorder: TouchRecorder?
    private weak var attachedWindow: UIWindow?
    private var timer: DispatchSourceTimer?
    private var observers: [FieldObserver] = []
    private var overrides: [String: Bool] = [:]
    private var message = "not started"

    private init() {}

    private var lastMessage: String {
        get { lock.lock(); defer { lock.unlock() }; return message }
        set { lock.lock(); message = newValue; lock.unlock() }
    }

    public var sessionId: String? { engine?.sessionId }

    /// Call on the main thread. Safe to call again, for example after changing the server address.
    public func configure(_ config: Config, log: @escaping (String) -> Void = { _ in }) {
        self.config = config
        if env == nil { env = EnvironmentChecks() }
        let checks = env!
        let defaults = UserDefaults.standard
        let guid = defaults.string(forKey: "fortguard.device_guid") ?? {
            let g = Ids.random("dev_", 12)
            defaults.set(g, forKey: "fortguard.device_guid")
            return g
        }()
        timer?.cancel()
        queue.async { [weak self] in
            guard let self = self else { return }
            do {
                let key = try KeyStore.loadOrCreate()
                let api = ApiClient(baseURL: config.baseURL)
                let attestation: AttestationProvider = config.attestationProvider
                    ?? DevAttestationProvider(api: api, level: config.devAttestationLevel)
                let engine = FortGuardEngine(api: api, appId: config.appId, deviceGuid: guid, key: key, attestation: attestation,
                                             environment: { [weak self] in self?.environmentSnapshot(checks) ?? checks.snapshot() },
                                             platform: "iOS", log: { [weak self] m in self?.lastMessage = m; log(m) }, buffer: self.buffer)
                engine.consentBehavioral = self.buffer.enabled
                engine.identity = FortGuard.storedIdentity()
                self.engine = engine
                let outcome = engine.enroll()
                self.lastMessage = outcome.message
                log(outcome.message)
            } catch {
                self.lastMessage = "start failed: \(error)"
                log(self.lastMessage)
            }
        }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + config.flushInterval, repeating: config.flushInterval)
        t.setEventHandler { [weak self] in _ = self?.engine?.flush() }
        t.resume()
        timer = t
    }

    private func environmentSnapshot(_ checks: EnvironmentChecks) -> [String: JSON] {
        var snap = checks.snapshot()
        guard config?.allowDebugOverrides == true else { return snap }
        lock.lock(); let forced = overrides; lock.unlock()
        for (k, on) in forced where on && snap[k] != nil { snap[k] = .bool(true) } // can force on, never hide
        return snap
    }

    /// Test apps only (needs allowDebugOverrides): force an environment flag on.
    /// Says which customer is using this phone, so the back office can record their time in the app and show
    /// their name. Values that fail the checks are ignored; the identity is sent with each later batch.
    public func identify(userId: String, customerName: String) {
        let name = FortGuard.cleanName(customerName)
        guard FortGuard.isValidCustomerId(userId), !name.isEmpty else { return }
        UserDefaults.standard.set(userId, forKey: FortGuard.identityUserKey)
        UserDefaults.standard.set(name, forKey: FortGuard.identityNameKey)
        let fields = ["user_id": userId, "customer_name": name]
        queue.async { [weak self] in self?.engine?.identity = fields }
    }

    static let identityUserKey = "fortguard.identity_user"
    static let identityNameKey = "fortguard.identity_name"

    static func isValidCustomerId(_ userId: String) -> Bool {
        (1...64).contains(userId.count) && userId.allSatisfy { ch in
            ch.isASCII && (ch.isLetter || ch.isNumber || ch == "_" || ch == "-")
        }
    }

    static func cleanName(_ raw: String) -> String {
        let printable = String(String.UnicodeScalarView(raw.unicodeScalars.filter { $0.value >= 32 }))
        return String(printable.trimmingCharacters(in: .whitespaces).prefix(80))
    }

    static func storedIdentity() -> [String: String] {
        let d = UserDefaults.standard
        guard let user = d.string(forKey: identityUserKey), let name = d.string(forKey: identityNameKey),
              isValidCustomerId(user), !cleanName(name).isEmpty else { return [:] }
        return ["user_id": user, "customer_name": cleanName(name)]
    }

    /// Whether the customer agrees to share their approximate location. Coordinates are sent only with consent,
    /// and only when the system has granted location permission. Call from the main thread.
    public func setLocationConsent(_ on: Bool) { env?.setLocationConsent(on) }

    public var isLocationConsent: Bool { UserDefaults.standard.bool(forKey: EnvironmentChecks.locationConsentKey) }

    public func setDebugOverride(_ key: String, _ on: Bool) {
        lock.lock(); overrides[key] = on; lock.unlock()
    }

    // MARK: capture

    /// Start capturing on a window. Call on the main thread when a protected screen appears.
    public func attach(window: UIWindow) {
        if attachedWindow !== window {
            if let r = recorder { attachedWindow?.removeGestureRecognizer(r) }
            let r = TouchRecorder(buffer: buffer)
            window.addGestureRecognizer(r)
            recorder = r
            attachedWindow = window
        }
        env?.startObserving()
        motion.start()
    }

    /// Finds the app's key window (handy from SwiftUI). Call on the main thread.
    public func attachToKeyWindow() {
        let window = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow }
        if let w = window { attach(window: w) }
    }

    /// Stop capturing and send what is buffered. Call on the main thread.
    public func detach() {
        if let r = recorder { attachedWindow?.removeGestureRecognizer(r) }
        recorder = nil
        attachedWindow = nil
        motion.stop()
        flush()
    }

    /// UIKit: record typing rhythm, focus and paste for a text field. The text is never sent.
    public func watch(_ textField: UITextField, field: Field) {
        observers.append(FieldObserver(field: field, textField: textField, sdk: self))
    }

    /// SwiftUI: call from .onChange with the text length before and after. Many characters at once
    /// count as a paste; anything else as one key press. Only lengths are used.
    public func recordEdit(field: Field, oldLength: Int, newLength: Int) {
        let now = FortGuardEngine.nowMs()
        if newLength - oldLength >= 6 { buffer.ui("PASTE", field: field, ts: now) }
        else if newLength != oldLength { buffer.key("DOWN", field: field, ts: now) }
    }

    public func recordFocus(field: Field) { buffer.ui("FOCUS", field: field, ts: FortGuardEngine.nowMs()) }

    /// User consent for behavioral capture. When false nothing behavioral is collected or sent.
    public func setConsent(_ granted: Bool) {
        buffer.enabled = granted
        if !granted { buffer.clear() }
        queue.async { [weak self] in self?.engine?.consentBehavioral = granted }
    }

    // MARK: sending

    /// Send what is buffered now. The completion runs on the main thread.
    public func flush(_ completion: ((FortGuardEngine.Outcome) -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self = self else { return }
            let o = self.engine?.flush(force: true)
                ?? FortGuardEngine.Outcome(ok: false, message: "SDK not ready: \(self.lastMessage)", response: nil)
            self.lastMessage = o.message
            if let c = completion { DispatchQueue.main.async { c(o) } }
        }
    }

    /// Mark the user pressing confirm, then send everything. Then your backend asks for the decision.
    public func submit(_ completion: @escaping (FortGuardEngine.Outcome) -> Void) {
        buffer.ui("SUBMIT", field: .other, ts: FortGuardEngine.nowMs())
        flush(completion)
    }

    public func reenroll(_ completion: @escaping (FortGuardEngine.Outcome) -> Void) {
        queue.async { [weak self] in
            guard let self = self else { return }
            let o = self.engine?.enroll(force: true)
                ?? FortGuardEngine.Outcome(ok: false, message: "SDK not ready: \(self.lastMessage)", response: nil)
            self.lastMessage = o.message
            DispatchQueue.main.async { completion(o) }
        }
    }

    @discardableResult
    public func newSession() -> String? {
        let id = engine?.newSession()
        buffer.clear()
        return id
    }

    /// Forget this device: deletes the key and the device ID. The next configure enrolls a new device.
    public func resetDevice() {
        timer?.cancel()
        engine = nil
        KeyStore.delete()
        UserDefaults.standard.removeObject(forKey: "fortguard.device_guid")
        buffer.clear()
        lastMessage = "device reset"
    }

    public var lastBatchJSON: String? { engine?.lastBatchJSON }

    public func status() -> Status {
        let sensors: String
        if !motion.available { sensors = "not available (simulator)" }
        else { sensors = motion.running ? "on" : "off (no screen attached)" }
        return Status(deviceGuid: engine?.deviceGuid, sessionId: engine?.sessionId, enrolledLevel: engine?.enrolledLevel,
                      counts: buffer.counts(), environment: env.map { environmentSnapshot($0) } ?? [:],
                      motionSensors: sensors, lastMessage: lastMessage)
    }
}
#endif
