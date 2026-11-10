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
 * Privacy by construction: the methods take an event type, a time and a field, never text. There is
 * no way to put a typed character into a key event.
 */
class EventBuffer(
    private val maxTouch: Int = 4000,
    private val maxKeys: Int = 1500,
    private val maxUi: Int = 400,
    private val maxSensor: Int = 4000,
) {
    private val touch = ArrayList<Map<String, Any?>>()
    private val keys = ArrayList<Map<String, Any?>>()
    private val ui = ArrayList<Map<String, Any?>>()
    private val accel = ArrayList<Map<String, Any?>>()
    private val gyro = ArrayList<Map<String, Any?>>()
    private val extra = LinkedHashMap<String, ArrayList<Map<String, Any?>>>()
    private var totals = IntArray(4)
    private var dropped = 0

    @Volatile var enabled: Boolean = true

    private fun add(list: ArrayList<Map<String, Any?>>, cap: Int, item: Map<String, Any?>, slot: Int) {
        if (!enabled) return
        synchronized(this) {
            if (list.size >= cap) { dropped++; return }
            list.add(item)
            totals[slot]++
        }
    }

    fun touch(type: String, x: Double, y: Double, pressure: Double, size: Double, ts: Long) {
        require(type == "DOWN" || type == "MOVE" || type == "UP")
        add(touch, maxTouch, mapOf(
            "event_type" to type, "x" to x.coerceIn(-9999.0, 9999.0), "y" to y.coerceIn(-9999.0, 9999.0),
            "pressure" to pressure.coerceIn(0.0, 2.0), "size" to size.coerceIn(0.0, 1000.0), "timestamp_ms" to ts,
        ), 0)
    }

    fun key(type: String, field: Field, ts: Long) {
        require(type == "DOWN" || type == "UP")
        add(keys, maxKeys, mapOf("event_type" to type, "ts" to ts, "field" to field.wire), 1)
    }

    fun ui(type: String, field: Field, ts: Long) {
        require(type == "FOCUS" || type == "PASTE" || type == "SUBMIT")
        add(ui, maxUi, mapOf("event_type" to type, "field" to field.wire, "ts" to ts), 2)
    }

    fun accel(x: Double, y: Double, z: Double, ts: Long) = add(accel, maxSensor, sample(x, y, z, ts), 3)

    fun gyro(x: Double, y: Double, z: Double, ts: Long) = add(gyro, maxSensor, sample(x, y, z, ts), 3)

    /** Any other sensor, by its wire name (for example "magnetometer"). Shares the sensor cap. */
    fun sensor(name: String, x: Double, y: Double, z: Double, ts: Long) {
        if (!enabled) return
        synchronized(this) {
            val list = extra.getOrPut(name) { ArrayList() }
            if (totals[3] >= maxSensor) { dropped++; return }
            list.add(sample(x, y, z, ts))
            totals[3]++
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
        totals = IntArray(4); dropped = 0
    }

    fun counts(): Counts = synchronized(this) { Counts(totals[0], totals[1], totals[2], totals[3], dropped) }
}
