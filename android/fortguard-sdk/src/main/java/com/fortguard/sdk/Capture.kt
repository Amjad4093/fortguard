package com.fortguard.sdk

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import android.os.SystemClock
import android.text.Editable
import android.text.TextWatcher
import android.view.MotionEvent
import android.view.Window
import android.widget.EditText
import com.fortguard.sdk.core.EventBuffer
import com.fortguard.sdk.core.Field

/** Wall-clock milliseconds for an event stamped with SystemClock.uptimeMillis(). */
private fun wallFromUptime(uptimeMs: Long): Long =
    System.currentTimeMillis() - (SystemClock.uptimeMillis() - uptimeMs)

/** Sees every touch on an Activity's window before the app does, and passes it on unchanged. */
internal class TouchCallback(
    val base: Window.Callback,
    private val buffer: EventBuffer,
) : Window.Callback by base {
    private var lastMove = 0L

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        runCatching { record(event) }
        return base.dispatchTouchEvent(event)
    }

    private fun record(ev: MotionEvent) {
        val type = when (ev.actionMasked) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_POINTER_DOWN -> "DOWN"
            MotionEvent.ACTION_MOVE -> "MOVE"
            MotionEvent.ACTION_UP, MotionEvent.ACTION_POINTER_UP, MotionEvent.ACTION_CANCEL -> "UP"
            else -> return
        }
        val ts = wallFromUptime(ev.eventTime)
        if (type == "MOVE") {
            if (ts - lastMove < 8) return
            lastMove = ts
        }
        val i = if (type == "MOVE") 0 else ev.actionIndex
        val x = if (Build.VERSION.SDK_INT >= 29) ev.getRawX(i) else ev.rawX
        val y = if (Build.VERSION.SDK_INT >= 29) ev.getRawY(i) else ev.rawY
        buffer.touch(type, x.toDouble(), y.toDouble(), ev.getPressure(i).toDouble(), ev.getTouchMajor(i).toDouble(), ts)
    }
}

/**
 * Typing rhythm for one input field.
 *
 * Soft keyboards do not report key press and release, only that the text changed, so each edit is
 * sent as one DOWN event. The text itself is never read: only that an edit happened, when, and in
 * which field. Many characters arriving in one edit is reported as a paste.
 */
internal class FieldWatcher(private val buffer: EventBuffer, private val field: Field) : TextWatcher {
    override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit

    override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
        val now = System.currentTimeMillis()
        when {
            count >= PASTE_MIN_CHARS && count - before >= PASTE_MIN_CHARS -> buffer.ui("PASTE", field, now)
            count > 0 || before > 0 -> buffer.key("DOWN", field, now)
        }
    }

    override fun afterTextChanged(s: Editable?) = Unit

    companion object {
        /** Keyboards insert word suggestions too, so a paste is judged by size. Use number or
         *  no-suggestion inputs for account and amount fields, as the demo does. */
        const val PASTE_MIN_CHARS = 6
    }
}

internal fun watchField(editText: EditText, field: Field, buffer: EventBuffer) {
    editText.addTextChangedListener(FieldWatcher(buffer, field))
    val previous = editText.onFocusChangeListener
    editText.setOnFocusChangeListener { v, hasFocus ->
        if (hasFocus) buffer.ui("FOCUS", field, System.currentTimeMillis())
        previous?.onFocusChange(v, hasFocus)
    }
}

/** Sensor type to the wire name it is sent under. Scalar sensors put their value in x only. */
private val EXTRA_SENSOR_NAMES: Map<Int, String> = linkedMapOf(
    Sensor.TYPE_MAGNETIC_FIELD to "magnetometer",
    Sensor.TYPE_GRAVITY to "gravity",
    Sensor.TYPE_LINEAR_ACCELERATION to "linear_acceleration",
    Sensor.TYPE_ROTATION_VECTOR to "rotation_vector",
    Sensor.TYPE_LIGHT to "light",
    Sensor.TYPE_PROXIMITY to "proximity",
    Sensor.TYPE_PRESSURE to "pressure",
)
private val SCALAR_SENSOR_TYPES = setOf(Sensor.TYPE_LIGHT, Sensor.TYPE_PROXIMITY, Sensor.TYPE_PRESSURE)

/**
 * Every motion, position and environment sensor the phone has, at about 50 Hz while a screen is open.
 * Accelerometer and gyroscope feed the risk score; the others are stored for analysis.
 * None of these need a permission.
 */
internal class MotionCapture(context: Context, private val buffer: EventBuffer) : SensorEventListener {
    private val sensors = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
    private val lastSent = HashMap<Int, Long>()
    @Volatile var running = false
        private set
    val hasAccelerometer get() = sensors.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null
    val hasGyroscope get() = sensors.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null

    /** Names of the sensors this phone has, for the on-screen panel. */
    fun available(): List<String> {
        val names = mutableListOf<String>()
        if (hasAccelerometer) names += "accelerometer"
        if (hasGyroscope) names += "gyroscope"
        for ((type, name) in EXTRA_SENSOR_NAMES) if (sensors.getDefaultSensor(type) != null) names += name
        return names
    }

    fun start() {
        if (running) return
        for (type in listOf(Sensor.TYPE_ACCELEROMETER, Sensor.TYPE_GYROSCOPE) + EXTRA_SENSOR_NAMES.keys) {
            sensors.getDefaultSensor(type)?.let { sensors.registerListener(this, it, PERIOD_US) }
        }
        running = true
    }

    fun stop() {
        sensors.unregisterListener(this)
        running = false
    }

    override fun onSensorChanged(e: SensorEvent) {
        // SensorEvent.timestamp is elapsed-realtime nanoseconds; convert to wall-clock ms.
        val ts = System.currentTimeMillis() - (SystemClock.elapsedRealtimeNanos() - e.timestamp) / 1_000_000
        val type = e.sensor.type
        val gap = if (type == Sensor.TYPE_ACCELEROMETER || type == Sensor.TYPE_GYROSCOPE) MIN_GAP_MS else MIN_GAP_EXTRA_MS
        val last = lastSent[type] ?: 0L
        if (ts - last < gap) return
        lastSent[type] = ts
        when (type) {
            Sensor.TYPE_ACCELEROMETER -> buffer.accel(e.values[0].toDouble(), e.values[1].toDouble(), e.values[2].toDouble(), ts)
            Sensor.TYPE_GYROSCOPE -> buffer.gyro(e.values[0].toDouble(), e.values[1].toDouble(), e.values[2].toDouble(), ts)
            else -> {
                val name = EXTRA_SENSOR_NAMES[type] ?: return
                if (type in SCALAR_SENSOR_TYPES) {
                    buffer.sensor(name, e.values[0].toDouble(), 0.0, 0.0, ts)
                } else {
                    val y = if (e.values.size > 1) e.values[1].toDouble() else 0.0
                    val z = if (e.values.size > 2) e.values[2].toDouble() else 0.0
                    buffer.sensor(name, e.values[0].toDouble(), y, z, ts)
                }
            }
        }
    }

    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit

    private companion object {
        const val PERIOD_US = 20_000
        const val MIN_GAP_MS = 18L
        // Slower sensors (light, proximity, pressure) report on change; this keeps any one from flooding.
        const val MIN_GAP_EXTRA_MS = 50L
    }
}
