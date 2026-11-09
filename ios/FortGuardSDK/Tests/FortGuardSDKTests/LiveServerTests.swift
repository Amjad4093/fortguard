import XCTest
@testable import FortGuardSDK

/// Runs the real protocol against a FortGuard server started with --dev. Skipped unless the address is set:
///
///     python -m fortguard.app --dev
///     FORTGUARD_TEST_SERVER=http://127.0.0.1:8080 swift test
final class LiveServerTests: XCTestCase {
    private var server: String? { ProcessInfo.processInfo.environment["FORTGUARD_TEST_SERVER"] }

    private func environment(call: Bool = false) -> [String: JSON] {
        ["os": "iOS", "os_version": "18.0", "is_rooted": false, "is_emulator": false, "has_hooking_framework": false,
         "active_remote_software": false, "screen_sharing": false, "active_call": .bool(call), "vpn": false, "mock_location": false]
    }

    private func makeEngine(call: Bool = false) throws -> (FortGuardEngine, ApiClient) {
        let url = try XCTUnwrap(server)
        let api = ApiClient(baseURL: url)
        let env = environment(call: call)
        let engine = FortGuardEngine(api: api, appId: "com.example.mobilebank", deviceGuid: Ids.random("dev_", 12),
                                     key: SoftwareDeviceKey(), attestation: DevAttestationProvider(api: api), environment: { env })
        return (engine, api)
    }

    func testEnrollSignSendAndEvaluate() throws {
        try XCTSkipIf(server == nil, "set FORTGUARD_TEST_SERVER to run")
        let (engine, api) = try makeEngine()
        XCTAssertTrue(engine.enroll().ok)
        let now = FortGuardEngine.nowMs()
        for i in 0..<12 { engine.buffer.key("DOWN", field: .amount, ts: now - 5000 + Int64(i * (120 + (i * 37) % 90))) }
        let flushed = engine.flush()
        XCTAssertTrue(flushed.ok, flushed.message)
        let r = api.postJSON("/v1/risk/evaluate", [
            "session_id": .string(engine.sessionId), "user_id": "usr_swifttest", "event_type": "FUNDS_TRANSFER",
            "transaction_details": ["amount": 5000.0, "currency": "PKR", "beneficiary_account": "PK36EXMP00992201029381",
                                    "is_new_beneficiary": false],
        ], headers: ["X-API-Key": ProcessInfo.processInfo.environment["FORTGUARD_API_KEY"] ?? "dev-only-api-key"])
        XCTAssertEqual(r.status, 200, r.describe())
        XCTAssertEqual(r.body["risk_level"] as? String, "ALLOW")
    }

    func testServerRejectsTamperedBatchAndReplay() throws {
        try XCTSkipIf(server == nil, "set FORTGUARD_TEST_SERVER to run")
        let (engine, api) = try makeEngine(call: true)
        XCTAssertTrue(engine.flush(force: true).ok)
        let sent = try XCTUnwrap(engine.lastBatchJSON)
        let tampered = sent.replacingOccurrences(of: "\"active_call\":true", with: "\"active_call\":false")
        XCTAssertEqual(api.post("/v1/telemetry/stream", body: tampered).errorCode, "bad_signature")
        XCTAssertEqual(api.post("/v1/telemetry/stream", body: sent).errorCode, "replay_detected")
    }
}
