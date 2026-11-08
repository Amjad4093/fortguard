#if os(iOS)
import CryptoKit
import Foundation
import Security

/// A Secure Enclave P-256 key: it signs inside the enclave and its private part can never leave it.
struct EnclaveDeviceKey: DeviceKey {
    let key: SecureEnclave.P256.Signing.PrivateKey
    var publicKeySPKI: Data { key.publicKey.derRepresentation }
    func sign(_ data: Data) throws -> Data { try key.signature(for: data).derRepresentation }
}

/// Keeps the device key between launches. With a Secure Enclave the Keychain holds only an encrypted
/// handle that works on this phone alone; on the simulator (no enclave) it holds a software key.
enum KeyStore {
    private static let service = "com.fortguard.sdk"
    private static let account = "device-key-v1"

    static func loadOrCreate() throws -> DeviceKey {
        if SecureEnclave.isAvailable {
            if let blob = read(), let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob) {
                return EnclaveDeviceKey(key: key)
            }
            let key = try SecureEnclave.P256.Signing.PrivateKey()
            save(key.dataRepresentation)
            return EnclaveDeviceKey(key: key)
        }
        if let blob = read(), let key = try? P256.Signing.PrivateKey(rawRepresentation: blob) {
            return SoftwareDeviceKey(privateKey: key)
        }
        let key = P256.Signing.PrivateKey()
        save(key.rawRepresentation)
        return SoftwareDeviceKey(privateKey: key)
    }

    static func delete() {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service, kSecAttrAccount as String: account]
        SecItemDelete(query as CFDictionary)
    }

    private static func read() -> Data? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service, kSecAttrAccount as String: account,
                                    kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        return item as? Data
    }

    private static func save(_ data: Data) {
        delete()
        let attributes: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                         kSecAttrService as String: service, kSecAttrAccount as String: account,
                                         kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                         kSecValueData as String: data]
        SecItemAdd(attributes as CFDictionary, nil)
    }
}
#endif
