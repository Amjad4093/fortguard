import Foundation

/// Which input a key or UI event belongs to. Only these names ever leave the device.
public enum Field: String {
    case username, password, otp
    case beneficiaryAccount = "beneficiary_account"
    case amount, other
}

public struct Counts {
    public let touch: Int
    public let keys: Int
    public let ui: Int
    public let sensor: Int
    public let dropped: Int
}

/// Thread-safe buffer of behavioral events waiting to be sent.
///
/// Privacy by construction: methods take an event type, a time and a field, never text.
public final class EventBuffer {
    public struct Drained {
        public let touch: [JSON]
        public let keys: [JSON]
        public let ui: [JSON]
        public let accel: [JSON]
        public let gyro: [JSON]
        public var isEmpty: Bool { touch.isEmpty && keys.isEmpty && ui.isEmpty && accel.isEmpty && gyro.isEmpty }
    }

    private let lock = NSLock()
    private var touchEvents: [JSON] = []
    private var keyEvents: [JSON] = []
    private var uiEvents: [JSON] = []
    private var accelSamples: [JSON] = []
    private var gyroSamples: [JSON] = []
    private var totals = [0, 0, 0, 0]
    private var dropped = 0
    private var isEnabled = true
    private let maxTouch: Int, maxKeys: Int, maxUi: Int, maxSensor: Int

    public init(maxTouch: Int = 4000, maxKeys: Int = 1500, maxUi: Int = 400, maxSensor: Int = 4000) {
        self.maxTouch = maxTouch
        self.maxKeys = maxKeys
        self.maxUi = maxUi
        self.maxSensor = maxSensor
    }

    public var enabled: Bool {
        get { lock.lock(); defer { lock.unlock() }; return isEnabled }
        set { lock.lock(); isEnabled = newValue; lock.unlock() }
    }

    private static func clamp(_ v: Double, _ lo: Double, _ hi: Double) -> Double {
        guard v.isFinite else { return 0 }
        return min(max(v, lo), hi)
    }

    public func touch(_ type: String, x: Double, y: Double, pressure: Double, size: Double, ts: Int64) {
        guard ["DOWN", "MOVE", "UP"].contains(type) else { return }
        let item: JSON = .object([
            "event_type": .string(type),
            "x": .double(Self.clamp(x, -9999, 9999)),
            "y": .double(Self.clamp(y, -9999, 9999)),
            "pressure": .double(Self.clamp(pressure, 0, 2)),
            "size": .double(Self.clamp(size, 0, 1000)),
            "timestamp_ms": .int(ts),
        ])
        lock.lock(); defer { lock.unlock() }
        guard isEnabled else { return }
        if touchEvents.count >= maxTouch { dropped += 1; return }
        touchEvents.append(item); totals[0] += 1
    }

    public func key(_ type: String, field: Field, ts: Int64) {
        guard type == "DOWN" || type == "UP" else { return }
        let item: JSON = .object(["event_type": .string(type), "ts": .int(ts), "field": .string(field.rawValue)])
        lock.lock(); defer { lock.unlock() }
        guard isEnabled else { return }
        if keyEvents.count >= maxKeys { dropped += 1; return }
        keyEvents.append(item); totals[1] += 1
    }

    public func ui(_ type: String, field: Field, ts: Int64) {
        guard ["FOCUS", "PASTE", "SUBMIT"].contains(type) else { return }
        let item: JSON = .object(["event_type": .string(type), "field": .string(field.rawValue), "ts": .int(ts)])
        lock.lock(); defer { lock.unlock() }
        guard isEnabled else { return }
        if uiEvents.count >= maxUi { dropped += 1; return }
        uiEvents.append(item); totals[2] += 1
    }

    private static func sample(_ x: Double, _ y: Double, _ z: Double, _ ts: Int64) -> JSON {
        .object(["x": .double(clamp(x, -999, 999)), "y": .double(clamp(y, -999, 999)),
                 "z": .double(clamp(z, -999, 999)), "ts": .int(ts)])
    }

    public func accel(x: Double, y: Double, z: Double, ts: Int64) {
        let item = Self.sample(x, y, z, ts)
        lock.lock(); defer { lock.unlock() }
        guard isEnabled else { return }
        if accelSamples.count >= maxSensor { dropped += 1; return }
        accelSamples.append(item); totals[3] += 1
    }

    public func gyro(x: Double, y: Double, z: Double, ts: Int64) {
        let item = Self.sample(x, y, z, ts)
        lock.lock(); defer { lock.unlock() }
        guard isEnabled else { return }
        if gyroSamples.count >= maxSensor { dropped += 1; return }
        gyroSamples.append(item); totals[3] += 1
    }

    public func drain() -> Drained {
        lock.lock(); defer { lock.unlock() }
        let d = Drained(touch: touchEvents, keys: keyEvents, ui: uiEvents, accel: accelSamples, gyro: gyroSamples)
        touchEvents = []; keyEvents = []; uiEvents = []; accelSamples = []; gyroSamples = []
        return d
    }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        touchEvents = []; keyEvents = []; uiEvents = []; accelSamples = []; gyroSamples = []
        totals = [0, 0, 0, 0]; dropped = 0
    }

    public func counts() -> Counts {
        lock.lock(); defer { lock.unlock() }
        return Counts(touch: totals[0], keys: totals[1], ui: totals[2], sensor: totals[3], dropped: dropped)
    }
}
