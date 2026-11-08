import Foundation

/// Blocking HTTP client. Call it from a background queue.
public final class ApiClient {
    public struct Response {
        public let status: Int
        public let body: [String: Any]
        public var ok: Bool { (200...299).contains(status) }
        public var errorCode: String? { (body["error"] as? [String: Any])?["code"] as? String }
        public var errorMessage: String? { (body["error"] as? [String: Any])?["message"] as? String }
        public func describe() -> String {
            ok ? "HTTP \(status)" : "HTTP \(status) \(errorCode ?? "") \(errorMessage ?? "")".trimmingCharacters(in: .whitespaces)
        }
    }

    private let base: String
    private let timeout: TimeInterval

    public init(baseURL: String, timeout: TimeInterval = 10) {
        var b = baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        while b.hasSuffix("/") { b.removeLast() }
        self.base = b
        self.timeout = timeout
    }

    public func post(_ path: String, body: String, headers: [String: String] = [:]) -> Response {
        guard let url = URL(string: base + path) else {
            return Response(status: 0, body: ["error": ["code": "bad_url", "message": "invalid server address"]])
        }
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.httpMethod = "POST"
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        for (k, v) in headers { request.setValue(v, forHTTPHeaderField: k) }
        request.httpBody = Data(body.utf8)

        let done = DispatchSemaphore(value: 0)
        var result = Response(status: 0, body: ["error": ["code": "network", "message": "no response"]])
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let http = response as? HTTPURLResponse {
                let parsed = data.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]
                result = Response(status: http.statusCode, body: parsed ?? [:])
            } else {
                result = Response(status: 0, body: ["error": ["code": "network", "message": error?.localizedDescription ?? "no response"]])
            }
            done.signal()
        }.resume()
        done.wait()
        return result
    }

    public func postJSON(_ path: String, _ body: [String: JSON], headers: [String: String] = [:]) -> Response {
        post(path, body: CanonicalJSON.encode(.object(body)), headers: headers)
    }
}

public struct AttestationRequest {
    public let deviceGuid: String
    public let appId: String
    public let platform: String
    public let challenge: String
    public let publicKeyB64: String
}

/// Produces the attestation token sent with enrollment.
public protocol AttestationProvider {
    func attest(_ request: AttestationRequest) throws -> String
}

public struct FortGuardError: Error, CustomStringConvertible {
    public let description: String
    public init(_ description: String) { self.description = description }
}

/// DEVELOPMENT ONLY: asks a server running with --dev to mint a simulated token.
/// Production uses Apple App Attest (DCAppAttestService) with a matching server verifier; not built yet.
public final class DevAttestationProvider: AttestationProvider {
    private let api: ApiClient
    private let level: () -> String

    public init(api: ApiClient, level: @escaping () -> String = { "STRONG" }) {
        self.api = api
        self.level = level
    }

    public func attest(_ r: AttestationRequest) throws -> String {
        let response = api.postJSON("/v1/dev/attest", [
            "device_guid": .string(r.deviceGuid), "app_id": .string(r.appId), "platform": .string(r.platform),
            "challenge": .string(r.challenge), "public_key": .string(r.publicKeyB64), "level": .string(level()),
        ])
        guard response.ok, let token = response.body["attestation"] as? String else {
            throw FortGuardError("dev attestation failed: \(response.describe()) (is the server running with --dev?)")
        }
        return token
    }
}

/// Platform-neutral heart of the SDK: enrollment, batching, signing and upload.
/// No UIKit, so it builds and is tested on macOS too. Network methods block: call from a background queue.
public final class FortGuardEngine {
    public struct Outcome {
        public let ok: Bool
        public let message: String
        public let response: ApiClient.Response?
    }

    public let appId: String
    public let deviceGuid: String
    public let platform: String
    public let buffer: EventBuffer
    private let api: ApiClient
    private let key: DeviceKey
    private let attestation: AttestationProvider
    private let environment: () -> [String: JSON]
    private let clock: () -> Int64
    private let log: (String) -> Void
    private let lock = NSRecursiveLock()
    private var seq: Int64 = 0

    public private(set) var sessionId: String = Ids.random("sess_", 16)
    public private(set) var enrolledLevel: String?
    public private(set) var lastBatchJSON: String?
    public var consentBehavioral = true {
        didSet {
            buffer.enabled = consentBehavioral
            if !consentBehavioral { buffer.clear() }
        }
    }

    public static func nowMs() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    public init(api: ApiClient, appId: String, deviceGuid: String, key: DeviceKey, attestation: AttestationProvider,
                environment: @escaping () -> [String: JSON], platform: String = "iOS",
                clock: @escaping () -> Int64 = FortGuardEngine.nowMs, log: @escaping (String) -> Void = { _ in },
                buffer: EventBuffer = EventBuffer()) {
        self.api = api
        self.appId = appId
        self.deviceGuid = deviceGuid
        self.key = key
        self.attestation = attestation
        self.environment = environment
        self.platform = platform
        self.clock = clock
        self.log = log
        self.buffer = buffer
    }

    public var publicKeyB64: String { base64url(key.publicKeySPKI) }

    @discardableResult
    public func newSession() -> String {
        lock.lock(); defer { lock.unlock() }
        sessionId = Ids.random("sess_", 16)
        seq = 0
        buffer.clear()
        return sessionId
    }

    /// Challenge, attestation, enrollment. Re-run with force after the attestation level changes.
    public func enroll(force: Bool = false) -> Outcome {
        lock.lock(); defer { lock.unlock() }
        if let level = enrolledLevel, !force { return Outcome(ok: true, message: "already enrolled (\(level))", response: nil) }
        let ch = api.postJSON("/v1/devices/challenge", [:])
        guard ch.status == 201, let challenge = ch.body["challenge"] as? String else {
            return Outcome(ok: false, message: "challenge failed: \(ch.describe())", response: ch)
        }
        let token: String
        do {
            token = try attestation.attest(AttestationRequest(deviceGuid: deviceGuid, appId: appId, platform: platform,
                                                              challenge: challenge, publicKeyB64: publicKeyB64))
        } catch {
            return Outcome(ok: false, message: "\(error)", response: nil)
        }
        let r = api.postJSON("/v1/devices/enroll", [
            "device_guid": .string(deviceGuid), "app_id": .string(appId), "platform": .string(platform),
            "public_key": .string(publicKeyB64), "challenge": .string(challenge), "attestation": .string(token),
        ])
        guard r.status == 201 else { return Outcome(ok: false, message: "enrollment failed: \(r.describe())", response: r) }
        enrolledLevel = r.body["integrity_level"] as? String
        log("enrolled, attestation level \(enrolledLevel ?? "?")")
        return Outcome(ok: true, message: "enrolled (\(enrolledLevel ?? "?"))", response: r)
    }

    /// Builds, signs and sends one batch. With force false an empty buffer sends nothing.
    public func flush(force: Bool = false) -> Outcome {
        lock.lock(); defer { lock.unlock() }
        let drained = buffer.drain()
        if drained.isEmpty && !force { return Outcome(ok: true, message: "nothing to send", response: nil) }
        if enrolledLevel == nil {
            let e = enroll()
            if !e.ok { return e }
        }
        var r = send(drained)
        if r.status == 401 && r.errorCode == "unknown_device" {
            log("server does not know this device (restarted?), enrolling again")
            enrolledLevel = nil
            let e = enroll(force: true)
            if !e.ok { return e }
            r = send(drained)
        }
        if r.status == 400 && r.errorCode == "stale_timestamp" {
            return Outcome(ok: false, message: "this phone's clock differs from the server's by more than 5 minutes", response: r)
        }
        log("telemetry \(r.describe())")
        return Outcome(ok: r.status == 202, message: r.describe(), response: r)
    }

    private func send(_ d: EventBuffer.Drained) -> ApiClient.Response {
        let payload: [String: JSON] = [
            "session_id": .string(sessionId),
            "device_guid": .string(deviceGuid),
            "app_id": .string(appId),
            "timestamp_ms": .int(clock()),
            "nonce": .string(Ids.random("n_", 20)),
            "seq": .int(seq),
            "consent": .object(["behavioral": .bool(consentBehavioral)]),
            "environment": .object(environment()),
            "touch_events": .array(d.touch),
            "key_events": .array(d.keys),
            "ui_events": .array(d.ui),
            "sensor_data": .object(["accelerometer": .array(d.accel), "gyroscope": .array(d.gyro)]),
        ]
        seq += 1
        do {
            let signed = try TelemetrySigning.sign(payload, key: key)
            let body = CanonicalJSON.encode(.object(signed))
            lastBatchJSON = body
            return api.post("/v1/telemetry/stream", body: body)
        } catch {
            return ApiClient.Response(status: 0, body: ["error": ["code": "signing_failed", "message": "\(error)"]])
        }
    }
}
