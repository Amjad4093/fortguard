import CryptoKit
import XCTest
@testable import FortGuardSDK

final class CoreTests: XCTestCase {

    // Canonical JSON must equal Python's json.dumps(sort_keys=True, separators=(",", ":")) after parsing.

    func testNumbersPrintLikePython() {
        let cases: [(Double, String)] = [
            (0, "0"), (-0.0, "0"), (0.001, "0.001"), (0.1, "0.1"), (1.5, "1.5"), (100, "100"),
            (12345.678, "12345.678"), (-0.0004, "0"), (1e-7, "0"), (3, "3"), (9.81, "9.81"),
            (-12.3456, "-12.346"), (0.0015, "0.002"),
        ]
        for (value, expected) in cases { XCTAssertEqual(CanonicalJSON.number(value), expected, "for \(value)") }
    }

    func testKeysSortedAndNoSpaces() {
        let v: JSON = ["b": 1, "a": [true, .null, "x"], "c": ["z": 1, "y": 2.5]]
        XCTAssertEqual(CanonicalJSON.encode(v), #"{"a":[true,null,"x"],"b":1,"c":{"y":2.5,"z":1}}"#)
    }

    func testStringsEscapeLikePython() {
        XCTAssertEqual(CanonicalJSON.encode(.string("q\"b\\n\nt\tc\u{01}é")), "\"q\\\"b\\\\n\\nt\\tc\\u0001é\"")
    }

    func testLongTimestampsStayExact() {
        XCTAssertEqual(CanonicalJSON.encode(.int(1_800_000_000_123)), "1800000000123")
    }

    func testNonFiniteNumbersNeverCrash() {
        XCTAssertEqual(CanonicalJSON.number(.nan), "0")
        XCTAssertEqual(CanonicalJSON.number(.infinity), "0")
    }

    func testSignatureCoversEverythingButItselfAndVerifies() throws {
        let key = SoftwareDeviceKey()
        let signed = try TelemetrySigning.sign(["session_id": "sess_abcdefgh", "seq": 1, "x": 1.25], key: key)
        guard case .string(let sigText)? = signed["signature"] else { return XCTFail("no signature") }
        var b64 = sigText.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        let sig = try P256.Signing.ECDSASignature(derRepresentation: XCTUnwrap(Data(base64Encoded: b64)))
        let pub = try P256.Signing.PublicKey(derRepresentation: key.publicKeySPKI)
        XCTAssertTrue(pub.isValidSignature(sig, for: TelemetrySigning.signingBytes(signed)))
        var tampered = signed
        tampered["x"] = 1.5
        XCTAssertFalse(pub.isValidSignature(sig, for: TelemetrySigning.signingBytes(tampered)))
        let text = String(decoding: TelemetrySigning.signingBytes(signed), as: UTF8.self)
        XCTAssertTrue(text.hasPrefix(TelemetrySigning.context))
        XCTAssertFalse(text.contains("signature"))
    }

    func testIdsMatchServerPattern() {
        let re = try! NSRegularExpression(pattern: "^[A-Za-z0-9_\\-]{8,64}$")
        for _ in 0..<200 {
            let id = Ids.random("sess_", 16)
            XCTAssertNotNil(re.firstMatch(in: id, range: NSRange(id.startIndex..., in: id)))
        }
    }

    func testKeyEventsCarryOnlyTypeTimeAndField() {
        let b = EventBuffer()
        b.key("DOWN", field: .beneficiaryAccount, ts: 1000)
        b.ui("PASTE", field: .beneficiaryAccount, ts: 1001)
        let d = b.drain()
        guard case .object(let k) = d.keys[0], case .object(let u) = d.ui[0] else { return XCTFail("not objects") }
        XCTAssertEqual(Set(k.keys), ["event_type", "ts", "field"])
        XCTAssertEqual(Set(u.keys), ["event_type", "field", "ts"])
        XCTAssertTrue(b.drain().isEmpty)
    }

    func testCapsDropAndCount() {
        let b = EventBuffer(maxKeys: 3)
        for i in 0..<5 { b.key("DOWN", field: .amount, ts: Int64(1000 + i)) }
        XCTAssertEqual(b.drain().keys.count, 3)
        XCTAssertEqual(b.counts().dropped, 2)
    }

    func testNoConsentKeepsNothing() {
        let b = EventBuffer()
        b.enabled = false
        b.touch("DOWN", x: 1, y: 2, pressure: 0.5, size: 10, ts: 1000)
        b.accel(x: 0, y: 9.8, z: 0, ts: 1000)
        XCTAssertTrue(b.drain().isEmpty)
    }

    func testValuesClampedToServerLimits() {
        let b = EventBuffer()
        b.touch("DOWN", x: 50_000, y: -50_000, pressure: 7, size: 5_000, ts: 1000)
        guard case .object(let t) = b.drain().touch[0] else { return XCTFail() }
        XCTAssertEqual(t["x"], .double(9999)); XCTAssertEqual(t["y"], .double(-9999))
        XCTAssertEqual(t["pressure"], .double(2)); XCTAssertEqual(t["size"], .double(1000))
    }
}
