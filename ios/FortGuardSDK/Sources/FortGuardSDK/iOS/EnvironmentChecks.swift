#if os(iOS)
import CallKit
import Foundation
import MachO
import UIKit

/// On-device checks reported in the "environment" block of every batch.
///
/// Best-effort signals a determined attacker on a jailbroken phone can hide. That is why the server
/// also relies on Apple App Attest, which the app cannot fake. Treat them as "raises suspicion".
final class EnvironmentChecks {
    private let callObserver = CXCallObserver()
    private let lock = NSLock()
    private var captured = false
    private var observer: NSObjectProtocol?
    private let osVersion: String
    private lazy var jailbroken: Bool = Self.checkJailbreak()
    private lazy var hooking: Bool = Self.checkHooking()

    /// Call on the main thread.
    init() {
        let v = UIDevice.current.systemVersion.filter { $0.isLetter || $0.isNumber || ".-_ ".contains($0) }
        osVersion = v.isEmpty ? "unknown" : String(v.prefix(32))
    }

    /// Call on the main thread when a screen is attached: tracks screen recording, mirroring and AirPlay.
    func startObserving() {
        updateCaptured()
        guard observer == nil else { return }
        observer = NotificationCenter.default.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            self?.updateCaptured()
        }
    }

    private func updateCaptured() {
        let value = UIScreen.main.isCaptured
        lock.lock(); captured = value; lock.unlock()
    }

    func snapshot() -> [String: JSON] {
        lock.lock(); let screen = captured; lock.unlock()
        return [
            "os": "iOS",
            "os_version": .string(osVersion),
            "is_rooted": .bool(jailbroken),
            "is_emulator": .bool(Self.isSimulator),
            "has_hooking_framework": .bool(hooking),
            "active_remote_software": .bool(false), // iOS does not allow remote control; screen sharing is caught by isCaptured
            "screen_sharing": .bool(screen),
            "active_call": .bool(inCall()),
            "vpn": .bool(Self.vpnActive()),
            "mock_location": .bool(false),          // needs location access; not collected in this version
        ]
    }

    /// Phone calls and CallKit VoIP calls (WhatsApp, FaceTime and others), as scammers often use.
    private func inCall() -> Bool { callObserver.calls.contains { !$0.hasEnded } }

    static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    private static func checkJailbreak() -> Bool {
        if isSimulator { return false } // the simulator sees the Mac's file system
        let paths = ["/Applications/Cydia.app", "/Applications/Sileo.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
                     "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt/", "/var/jb", "/usr/bin/ssh"]
        if paths.contains(where: { FileManager.default.fileExists(atPath: $0) }) { return true }
        let probe = "/private/fortguard-jb-probe.txt"
        if (try? "x".write(toFile: probe, atomically: true, encoding: .utf8)) != nil {
            try? FileManager.default.removeItem(atPath: probe)
            return true // apps cannot write outside their sandbox on a stock iPhone
        }
        return false
    }

    private static func checkHooking() -> Bool {
        let marks = ["frida", "cynject", "libhooker", "substrate", "substitute", "tweakinject", "ellekit"]
        for i in 0..<_dyld_image_count() {
            guard let raw = _dyld_get_image_name(i) else { continue }
            let name = String(cString: raw).lowercased()
            if marks.contains(where: { name.contains($0) }) { return true }
        }
        return false
    }

    private static func vpnActive() -> Bool {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
              let scoped = settings["__SCOPED__"] as? [String: Any] else { return false }
        return scoped.keys.contains { key in ["tap", "tun", "ppp", "ipsec"].contains { key.hasPrefix($0) } }
    }
}
#endif
