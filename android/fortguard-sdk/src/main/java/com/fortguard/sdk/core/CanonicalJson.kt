package com.fortguard.sdk.core

/**
 * Canonical JSON, byte for byte the same as the server's
 * `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)` after the server parses it.
 *
 * The SDK signs this text and also sends this exact text as the request body, so the server
 * re-creates the same bytes when it verifies.
 *
 * Numbers: doubles are rounded to 3 decimals and printed without an exponent, and whole numbers are
 * printed without ".0". Python then reads them back and prints them identically. Stay within
 * +/- 9e15 (timestamps are Long, so they are exact).
 */
object CanonicalJson {

    fun encode(value: Any?): String = StringBuilder().also { write(it, value) }.toString()

    private fun write(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (v) "true" else "false")
            is String -> writeString(sb, v)
            is Int -> sb.append(v.toLong())
            is Long -> sb.append(v)
            is Short -> sb.append(v.toLong())
            is Byte -> sb.append(v.toLong())
            is Double -> sb.append(number(v))
            is Float -> sb.append(number(v.toDouble()))
            is Map<*, *> -> {
                val keys = v.keys.map { k ->
                    require(k is String) { "map keys must be strings" }
                    k
                }.sorted()
                sb.append('{')
                keys.forEachIndexed { i, k ->
                    if (i > 0) sb.append(',')
                    writeString(sb, k)
                    sb.append(':')
                    write(sb, v[k])
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                v.forEachIndexed { i, item ->
                    if (i > 0) sb.append(',')
                    write(sb, item)
                }
                sb.append(']')
            }
            else -> throw IllegalArgumentException("unsupported JSON type: ${v::class.java.name}")
        }
    }

    /** Round to 3 decimals; no exponent; whole values without ".0"; never "-0". */
    fun number(d: Double): String {
        require(!d.isNaN() && !d.isInfinite()) { "numbers must be finite" }
        require(kotlin.math.abs(d) < 9.0e15) { "number out of range" }
        val m = Math.round(d * 1000.0)
        if (m == 0L) return "0"
        val negative = m < 0
        val a = if (negative) -m else m
        val whole = a / 1000
        val frac = a % 1000
        val sb = StringBuilder()
        if (negative) sb.append('-')
        sb.append(whole)
        if (frac != 0L) sb.append('.').append(frac.toString().padStart(3, '0').trimEnd('0'))
        return sb.toString()
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (c < ' ') {
                    sb.append("\\u").append(Integer.toHexString(c.code).padStart(4, '0'))
                } else {
                    sb.append(c)
                }
            }
        }
        sb.append('"')
    }
}
