package com.fortguard.sdk.core

/** Which input a key or UI event belongs to. Only these names ever leave the device. */
enum class Field(val wire: String) {
    USERNAME("username"),
    PASSWORD("password"),
    OTP("otp"),
    BENEFICIARY_ACCOUNT("beneficiary_account"),
    AMOUNT("amount"),
    OTHER("other"),
}

data class Counts(val touch: Int, val keys: Int, val ui: Int, val sensor: Int, val dropped: Int)

/**
 * Thread-safe buffer of behavioral events waiting to be sent.
 *
 * Privacy by construction: the methods take an event type, a time, a field and character counts,
 * never text. There is no way to put a typed character into any event.
 */
class EventBuffer(
    private val maxTouch: Int = 4000,
    private val maxKeys: Int = 1500,
    private val maxUi: Int = 400,
    private val maxSensor: Int = 4000,
    private val maxExtraSensor: Int = 4000,
) {
    private val touch = ArrayList<Map<String, Any?>>()
    private val keys = ArrayList<Map<String, Any?>>()
    private val ui = ArrayList<Map<String, Any?>>()
    private val accel = ArrayList<Map<String, Any?>>()
    private val gyro = ArrayList<Map<String, Any?>>()
    private val extra = LinkedHashMap<String, ArrayList<Map<String, Any?>>>()
    // Slots: 0 touch, 1 keys, 2 ui, 3 accelerometer and gyroscope, 4 the other sensors.
    // The other sensors have their own budget, so motion samples can never crowd them out.
    private var totals = IntArray(5)
    private var dropped = 0

    // Lifetime figures for the on-screen panel. They are not cleared when a batch is sent.
    private val seen = LinkedHashMap<String, Long>()
    private var typedChars = 0L
    private var correctedChars = 0L

    @Volatile var enabled: Boolean = true

    // Kill switches from the bank's signed configuration. A kind switched off is not collected at all.
    @Volatile var allowTouch: Boolean = true
    @Volatile var allowKeys: Boolean = true
    @Volatile var allowMotion: Boolean = true
    @Volatile var allowSensors: Boolean = true

    private fun bump(name: String) {
        seen[name] = (seen[name] ?: 0L) + 1L
    }

    private fun add(list: ArrayList<Map<String, Any?>>, cap: Int, item: Map<String, Any?>, slot: Int, name: String) {
        if (!enabled) return
        synchronized(this) {
            if (list.size >= cap) { dropped++; return }
            list.add(item)
            totals[slot]++
            bump(name)
        }
    }

    /**
     * [tdx], [tdy]: where a touch-down landed inside the control it hit, from -1 (left or top edge)
     * through 0 (the centre) to 1. Leave them out when the control is not known.
     */
    fun touch(type: String, x: Double, y: Double, pressure: Double, size: Double, ts: Long, tdx: Double? = null, tdy: Double? = null) {
        require(type == "DOWN" || type == "MOVE" || type == "UP")
        if (!allowTouch) return
        val event = linkedMapOf<String, Any?>(
            "event_type" to type, "x" to x.coerceIn(-9999.0, 9999.0), "y" to y.coerceIn(-9999.0, 9999.0),
            "pressure" to pressure.coerceIn(0.0, 2.0), "size" to size.coerceIn(0.0, 1000.0), "timestamp_ms" to ts,
        )
        if (type == "DOWN" && tdx != null && tdy != null) {
            event["tdx"] = tdx.coerceIn(-1.0, 1.0)
            event["tdy"] = tdy.coerceIn(-1.0, 1.0)
        }
        add(touch, maxTouch, event, 0, "touch")
    }

    /**
     * One keystroke or edit. [inserted] and [deleted] are character counts only (never the characters),
     * which give typing speed and correction rate on the server.
     */
    fun key(type: String, field: Field, ts: Long, inserted: Int = 0, deleted: Int = 0) {
        require(type == "DOWN" || type == "UP")
        if (!allowKeys) return
        val item = LinkedHashMap<String, Any?>()
        item["event_type"] = type
        item["ts"] = ts
        item["field"] = field.wire
        if (inserted > 0) item["inserted"] = inserted.coerceAtMost(1000)
        if (deleted > 0) item["deleted"] = deleted.coerceAtMost(1000)
        add(keys, maxKeys, item, 1, "keystrokes")
        if (enabled) synchronized(this) {
            typedChars += inserted.coerceAtMost(1000)
            correctedChars += deleted.coerceAtMost(1000)
        }
    }

    fun ui(type: String, field: Field, ts: Long) {
        require(type == "FOCUS" || type == "PASTE" || type == "SUBMIT")
        if (!allowKeys) return
        add(ui, maxUi, mapOf("event_type" to type, "field" to field.wire, "ts" to ts), 2, "ui_events")
    }

    fun accel(x: Double, y: Double, z: Double, ts: Long) {
        if (allowMotion) add(accel, maxSensor, sample(x, y, z, ts), 3, "accelerometer")
    }

    fun gyro(x: Double, y: Double, z: Double, ts: Long) {
        if (allowMotion) add(gyro, maxSensor, sample(x, y, z, ts), 3, "gyroscope")
    }

    /** Any other sensor, by its wire name (for example "magnetometer"). Has its own budget, slot 4. */
    fun sensor(name: String, x: Double, y: Double, z: Double, ts: Long) {
        if (!enabled || !allowSensors) return
        synchronized(this) {
            val list = extra.getOrPut(name) { ArrayList() }
            if (totals[4] >= maxExtraSensor) { dropped++; return }
            list.add(sample(x, y, z, ts))
            totals[4]++
            bump(name)
        }
    }

    private fun sample(x: Double, y: Double, z: Double, ts: Long) = mapOf(
        "x" to x.coerceIn(-999.0, 999.0), "y" to y.coerceIn(-999.0, 999.0), "z" to z.coerceIn(-999.0, 999.0), "ts" to ts,
    )

    class Drained(
        val touch: List<Map<String, Any?>>,
        val keys: List<Map<String, Any?>>,
        val ui: List<Map<String, Any?>>,
        val accel: List<Map<String, Any?>>,
        val gyro: List<Map<String, Any?>>,
        val extra: Map<String, List<Map<String, Any?>>> = emptyMap(),
    ) {
        val isEmpty get() = touch.isEmpty() && keys.isEmpty() && ui.isEmpty() && accel.isEmpty() &&
            gyro.isEmpty() && extra.values.all { it.isEmpty() }
    }

    fun drain(): Drained = synchronized(this) {
        val extraCopy = LinkedHashMap<String, List<Map<String, Any?>>>()
        for ((name, list) in extra) extraCopy[name] = ArrayList(list)
        Drained(ArrayList(touch), ArrayList(keys), ArrayList(ui), ArrayList(accel), ArrayList(gyro), extraCopy).also {
            touch.clear(); keys.clear(); ui.clear(); accel.clear(); gyro.clear(); extra.clear()
        }
    }

    fun clear() = synchronized(this) {
        touch.clear(); keys.clear(); ui.clear(); accel.clear(); gyro.clear(); extra.clear()
        totals = IntArray(5); dropped = 0
        seen.clear(); typedChars = 0L; correctedChars = 0L
    }

    fun counts(): Counts = synchronized(this) { Counts(totals[0], totals[1], totals[2], totals[3] + totals[4], dropped) }

    /** Lifetime number of samples or events seen per signal name, for the on-screen panel. */
    fun signals(): Map<String, Long> = synchronized(this) { LinkedHashMap(seen) }

    /** Lifetime characters typed and corrected (counts only). */
    fun typing(): Pair<Long, Long> = synchronized(this) { Pair(typedChars, correctedChars) }
}
