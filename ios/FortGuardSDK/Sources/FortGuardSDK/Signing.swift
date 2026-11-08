import CryptoKit
import Foundation

/// The device's signing key. On an iPhone it lives in the Secure Enclave and cannot be exported.
public protocol DeviceKey {
    /// X.509 SubjectPublicKeyInfo (DER) of the P-256 public key.
    var publicKeySPKI: Data { get }
    /// ECDSA P-256 with SHA-256, DER-encoded signature.
    func sign(_ data: Data) throws -> Data
}

/// A software P-256 key: used in tests and on the simulator, which has no Secure Enclave.
public struct SoftwareDeviceKey: DeviceKey {
    public let privateKey: P256.Signing.PrivateKey

    public init(privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.privateKey = privateKey
    }

    public var publicKeySPKI: Data { privateKey.publicKey.derRepresentation }

    public func sign(_ data: Data) throws -> Data {
        try privateKey.signature(for: data).derRepresentation
    }
}

public enum TelemetrySigning {
    /// Domain separation; must match the server's TELEMETRY_CONTEXT.
    public static let context = "fortguard.telemetry.v1\n"

    public static func signingBytes(_ payload: [String: JSON]) -> Data {
        var body = payload
        body.removeValue(forKey: "signature")
        return Data((context + CanonicalJSON.encode(.object(body))).utf8)
    }

    /// Returns a copy of the payload with "signature" added.
    public static func sign(_ payload: [String: JSON], key: DeviceKey) throws -> [String: JSON] {
        var signed = payload
        signed["signature"] = .string(base64url(try key.sign(signingBytes(payload))))
        return signed
    }
}

public func base64url(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

public enum Ids {
    private static let alphabet = Array("abcdefghijklmnopqrstuvwxyz0123456789")

    /// prefix + n random characters; always matches the server's ID pattern.
    public static func random(_ prefix: String, _ n: Int) -> String {
        var generator = SystemRandomNumberGenerator()
        return prefix + String((0..<n).map { _ in alphabet.randomElement(using: &generator)! })
    }
}
