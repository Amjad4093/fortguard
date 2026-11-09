#if os(iOS)
import CoreMotion
import UIKit
import UIKit.UIGestureRecognizerSubclass

/// Wall-clock milliseconds for a timestamp measured in seconds since boot (UITouch, CMLogItem).
func wallMs(fromUptime t: TimeInterval) -> Int64 {
    FortGuardEngine.nowMs() - Int64((ProcessInfo.processInfo.systemUptime - t) * 1000)
}

/// Watches every touch on a window without ever claiming it: taps and swipes reach the app unchanged.
final class TouchRecorder: UIGestureRecognizer, UIGestureRecognizerDelegate {
    private let buffer: EventBuffer
    private var lastMove: Int64 = 0

    init(buffer: EventBuffer) {
        self.buffer = buffer
        super.init(target: nil, action: nil)
        cancelsTouchesInView = false
        delaysTouchesBegan = false
        delaysTouchesEnded = false
        delegate = self
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) { record(touches, "DOWN") }
    override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent) { record(touches, "MOVE") }
    override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent) { record(touches, "UP"); finishIfDone(event) }
    override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent) { record(touches, "UP"); finishIfDone(event) }

    private func finishIfDone(_ event: UIEvent) {
        let active = event.allTouches?.filter { $0.phase != .ended && $0.phase != .cancelled } ?? []
        if active.isEmpty { state = .failed } // never "recognizes", so it never interferes
    }

    private func record(_ touches: Set<UITouch>, _ type: String) {
        for t in touches {
            let ts = wallMs(fromUptime: t.timestamp)
            if type == "MOVE" {
                if ts - lastMove < 8 { continue }
                lastMove = ts
            }
            let p = t.location(in: nil)
            let pressure = t.maximumPossibleForce > 0 ? Double(t.force / t.maximumPossibleForce) : 0
            buffer.touch(type, x: Double(p.x), y: Double(p.y), pressure: pressure, size: Double(t.majorRadius * 2), ts: ts)
        }
    }

    func gestureRecognizer(_ g: UIGestureRecognizer, shouldRecognizeSimultaneouslyWith other: UIGestureRecognizer) -> Bool { true }
}

/// Accelerometer (converted from g to m/s^2, gravity included) and gyroscope (rad/s) at about 50 Hz.
final class MotionCapture {
    private let manager = CMMotionManager()
    private let queue = OperationQueue()
    private let buffer: EventBuffer
    private(set) var running = false

    init(buffer: EventBuffer) {
        self.buffer = buffer
        queue.maxConcurrentOperationCount = 1
    }

    var available: Bool { manager.isAccelerometerAvailable }

    func start() {
        guard !running else { return }
        running = true
        let buffer = self.buffer
        if manager.isAccelerometerAvailable {
            manager.accelerometerUpdateInterval = 0.02
            manager.startAccelerometerUpdates(to: queue) { data, _ in
                guard let d = data else { return }
                buffer.accel(x: d.acceleration.x * 9.81, y: d.acceleration.y * 9.81, z: d.acceleration.z * 9.81,
                             ts: wallMs(fromUptime: d.timestamp))
            }
        }
        if manager.isGyroAvailable {
            manager.gyroUpdateInterval = 0.02
            manager.startGyroUpdates(to: queue) { data, _ in
                guard let d = data else { return }
                buffer.gyro(x: d.rotationRate.x, y: d.rotationRate.y, z: d.rotationRate.z, ts: wallMs(fromUptime: d.timestamp))
            }
        }
    }

    func stop() {
        manager.stopAccelerometerUpdates()
        manager.stopGyroUpdates()
        running = false
    }
}

/// For UIKit apps: typing rhythm, focus and paste for one text field. Only the length of the text is
/// looked at, to tell an edit from a paste; the text itself is never stored or sent.
final class FieldObserver: NSObject {
    private let field: Field
    private let sdk: FortGuard
    private var lastLength = 0

    init(field: Field, textField: UITextField, sdk: FortGuard) {
        self.field = field
        self.sdk = sdk
        self.lastLength = textField.text?.count ?? 0
        super.init()
        textField.addTarget(self, action: #selector(changed(_:)), for: .editingChanged)
        textField.addTarget(self, action: #selector(focused), for: .editingDidBegin)
    }

    @objc private func changed(_ tf: UITextField) {
        let n = tf.text?.count ?? 0
        sdk.recordEdit(field: field, oldLength: lastLength, newLength: n)
        lastLength = n
    }

    @objc private func focused() { sdk.recordFocus(field: field) }
}
#endif
