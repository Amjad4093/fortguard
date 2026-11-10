#if os(iOS)
import CallKit
import CoreLocation
import Foundation
import MachO
import Network
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
    private let pathMonitor = NWPathMonitor()
    private let locationManager = CLLocationManager()
    private var liveNetwork = "none"
    private var networkChanges = 0
    private var lastNetwork: String?
    private var fix: CLLocation?
    private var lastLocationRequest: Date?

    /// Call on the main thread.
    init() {
        let v = UIDevice.current.systemVersion.filter { $0.isLetter || $0.isNumber || ".-_ ".contains($0) }
        osVersion = v.isEmpty ? "unknown" : String(v.prefix(32))
        // Network changes are followed live, so a switch between Wi-Fi and mobile data is seen when it happens.
        pathMonitor.pathUpdateHandler = { [weak self] path in self?.notePath(path) }
        pathMonitor.start(queue: DispatchQueue(label: "com.fortguard.sdk.path"))
        locationManager.delegate = self
        locationManager.desiredAccuracy = kCLLocationAccuracyKilometer
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
        refreshLocationIfDue()
        lock.lock()
        let screen = captured, network = liveNetwork, changes = networkChanges, current = fix
        lock.unlock()
        var out: [String: JSON] = [
            "os": "iOS",
            "os_version": .string(osVersion),
            "is_rooted": .bool(jailbroken),
            "is_emulator": .bool(Self.isSimulator),
            "has_hooking_framework": .bool(hooking),
            "active_remote_software": .bool(false), // iOS does not allow remote control; screen sharing is caught by isCaptured
            "screen_sharing": .bool(screen),
            "active_call": .bool(inCall()),
            "vpn": .bool(Self.vpnActive()),
            // Only a fix the system marks as simulated counts; the app cannot see the phone's own GPS setting.
            "mock_location": .bool(current?.sourceInformation?.isSimulatedBySoftware ?? false),
            "network_type": .string(network),
            "network_changes": .int(Int64(changes)),
        ]
        if let loc = sharedLocation(current) { out["location"] = .object(loc) }
        return out
    }

    /// Phone calls and CallKit VoIP calls (WhatsApp, FaceTime and others), as scammers often use.
    /// iOS does not show cellular (GSM) calls to apps, so only calls made through CallKit are seen here.
    private func inCall() -> Bool { callObserver.calls.contains { !$0.hasEnded } }

    // --- Network -------------------------------------------------------------------------------------

    private func notePath(_ path: NWPath) {
        let now: String
        if path.status != .satisfied { now = "none" }
        else if path.usesInterfaceType(.wifi) { now = "wifi" }
        else if path.usesInterfaceType(.cellular) { now = "cellular" }
        else if path.usesInterfaceType(.wiredEthernet) { now = "ethernet" }
        else { now = "other" }
        lock.lock()
        if let last = lastNetwork, last != now { networkChanges += 1 }
        lastNetwork = now
        liveNetwork = now
        lock.unlock()
    }

    // --- Approximate location, only with the customer's consent ---------------------------------------

    static let locationConsentKey = "fortguard.location_consent"

    /// Called from the app when the customer turns sharing on or off. Turning it on asks for permission once.
    func setLocationConsent(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: Self.locationConsentKey)
        if on && locationManager.authorizationStatus == .notDetermined {
            locationManager.requestWhenInUseAuthorization()
        }
    }

    private var locationAuthorized: Bool {
        [.authorizedWhenInUse, .authorizedAlways].contains(locationManager.authorizationStatus)
    }

    /// Asks for a fresh fix at most every five minutes, and only when the customer has agreed.
    private func refreshLocationIfDue() {
        guard UserDefaults.standard.bool(forKey: Self.locationConsentKey), locationAuthorized else { return }
        lock.lock()
        let due = lastLocationRequest.map { Date().timeIntervalSince($0) > 300 } ?? true
        if due { lastLocationRequest = Date() }
        lock.unlock()
        if due { DispatchQueue.main.async { [weak self] in self?.locationManager.requestLocation() } }
    }

    /// Coordinates rounded to about 1 km, only with consent and for a fix under 30 minutes old.
    private func sharedLocation(_ fix: CLLocation?) -> [String: JSON]? {
        guard let fix = fix, UserDefaults.standard.bool(forKey: Self.locationConsentKey), fix.horizontalAccuracy >= 0 else { return nil }
        let age = Date().timeIntervalSince(fix.timestamp)
        guard age >= 0, age <= 1800 else { return nil }
        func round2(_ v: Double) -> Double { (v * 100).rounded() / 100 }
        return [
            "lat": .double(round2(fix.coordinate.latitude)),
            "lng": .double(round2(fix.coordinate.longitude)),
            "accuracy_m": .int(Int64(min(fix.horizontalAccuracy, 100000))),
            "fix_age_s": .int(Int64(age)),
        ]
    }

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

extension EnvironmentChecks: CLLocationManagerDelegate {
    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard let latest = locations.last else { return }
        lock.lock(); fix = latest; lock.unlock()
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {}
}
#endif
