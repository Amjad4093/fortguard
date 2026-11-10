package com.fortguard.sdk.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * JVM unit tests for the platform-neutral core. Run with ./gradlew :fortguard-sdk:test.
 * The cross-language check (Kotlin signs, Python verifies) lives in the server repo's tests.
 */
class CoreTest {

    // --- Canonical JSON: must equal Python's json.dumps(sort_keys=True, separators=(",", ":")) ---

    @Test fun numbersPrintLikePython() {
        val cases = mapOf(
            0.0 to "0", -0.0 to "0", 0.001 to "0.001", 0.1 to "0.1", 1.5 to "1.5", 100.0 to "100",
            12345.678 to "12345.678", -0.0004 to "0", 1e-7 to "0", 3.0 to "3", 9.81 to "9.81",
            -12.3456 to "-12.346", 2.0005 to "2.001", 0.0015 to "0.002",
        )
        cases.forEach { (v, want) -> assertEquals("for $v", want, CanonicalJson.number(v)) }
    }

    @Test fun keysAreSortedAndNoSpaces() {
        val s = CanonicalJson.encode(mapOf("b" to 1, "a" to listOf(true, null, "x"), "c" to mapOf("z" to 1L, "y" to 2.5)))
        assertEquals("""{"a":[true,null,"x"],"b":1,"c":{"y":2.5,"z":1}}""", s)
    }

    @Test fun stringsEscapeLikePython() {
        assertEquals("\"q\\\"b\\\\n\\nt\\tc\\u0001é\"", CanonicalJson.encode("q\"b\\n\nt\tc\u0001é"))
    }

    @Test fun longsStayExact() {
        assertEquals("1800000000123", CanonicalJson.encode(1_800_000_000_123L))
    }

    @Test fun badNumbersAreRefused() {
        assertTrue(runCatching { CanonicalJson.number(Double.NaN) }.isFailure)
        assertTrue(runCatching { CanonicalJson.number(1e20) }.isFailure)
    }

    // --- MiniJson ------------------------------------------------------------------------------------

    @Test fun parsesServerResponses() {
        val m = MiniJson.parse("""{"risk_score": 700, "x": -1.5e2, "ok": true, "n": null, "list": [1, "a\"b"], "u": "é"}""") as Map<*, *>
        assertEquals(700L, m["risk_score"])
        assertEquals(-150.0, m["x"])
        assertEquals(true, m["ok"])
        assertTrue(m.containsKey("n") && m["n"] == null)
        assertEquals(listOf(1L, "a\"b"), m["list"])
        assertEquals("é", m["u"])
    }

    @Test fun refusesBrokenJson() {
        listOf("{", "{\"a\":}", "[1,]", "tru", "{\"a\":1} x").forEach {
            assertTrue("should fail: $it", runCatching { MiniJson.parse(it) }.isFailure)
        }
    }

    @Test fun roundTripThroughCanonical() {
        val original = mapOf("a" to listOf(1L, 2.5, "x"), "b" to mapOf("c" to false))
        assertEquals(original, MiniJson.parse(CanonicalJson.encode(original)))
    }

    // --- Signing ---------------------------------------------------------------------------------------

    private fun softwareKey(): Pair<JcaDeviceKey, java.security.PublicKey> {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        return JcaDeviceKey(kp.private, kp.public) to kp.public
    }

    private fun verify(payload: Map<String, Any?>, pub: java.security.PublicKey): Boolean {
        val sig = java.util.Base64.getUrlDecoder().decode(payload["signature"] as String)
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(pub)
            update(TelemetrySigning.signingBytes(payload))
            verify(sig)
        }
    }

    @Test fun signatureCoversEverythingButItself() {
        val (key, pub) = softwareKey()
        val signed = TelemetrySigning.sign(mapOf("session_id" to "sess_abcdefgh", "seq" to 1, "x" to 1.25), key)
        assertTrue(verify(signed, pub))
        assertFalse(verify(signed + ("x" to 1.5), pub))
        assertTrue(String(TelemetrySigning.signingBytes(signed)).startsWith(TelemetrySigning.CONTEXT))
        assertFalse(String(TelemetrySigning.signingBytes(signed)).contains("signature"))
    }

    @Test fun idsMatchTheServerPattern() {
        repeat(200) { assertTrue(Ids.random("sess_", 16).matches(Regex("^[A-Za-z0-9_\\-]{8,64}$"))) }
    }

    // --- Event buffer --------------------------------------------------------------------------------------

    @Test fun keyEventsCarryOnlyTypeTimeAndField() {
        val b = EventBuffer()
        b.key("DOWN", Field.BENEFICIARY_ACCOUNT, 1000)
        b.ui("PASTE", Field.BENEFICIARY_ACCOUNT, 1001)
        val d = b.drain()
        assertEquals(setOf("event_type", "ts", "field"), d.keys.single().keys)
        assertEquals(setOf("event_type", "field", "ts"), d.ui.single().keys)
        assertTrue(b.drain().isEmpty)
    }

    @Test fun capsDropAndCount() {
        val b = EventBuffer(maxKeys = 3)
        repeat(5) { b.key("DOWN", Field.AMOUNT, 1000L + it) }
        assertEquals(3, b.drain().keys.size)
        assertEquals(2, b.counts().dropped)
    }

    @Test fun motionFloodDoesNotCrowdOutOtherSensors() {
        val b = EventBuffer(maxSensor = 5, maxExtraSensor = 5)
        repeat(50) { b.accel(0.0, 9.8, 0.0, 1000L + it) }
        b.sensor("magnetometer", 20.0, 0.0, 0.0, 2000)
        b.sensor("light", 300.0, 0.0, 0.0, 2001)
        val d = b.drain()
        assertEquals(setOf("magnetometer", "light"), d.extra.keys)
    }

    @Test fun noConsentMeansNothingIsKept() {
        val b = EventBuffer()
        b.enabled = false
        b.touch("DOWN", 1.0, 2.0, 0.5, 10.0, 1000)
        b.accel(0.0, 9.8, 0.0, 1000)
        assertTrue(b.drain().isEmpty)
    }

    @Test fun valuesAreClampedToServerLimits() {
        val b = EventBuffer()
        b.touch("DOWN", 50_000.0, -50_000.0, 7.0, 5_000.0, 1000)
        val t = b.drain().touch.single()
        assertEquals(9999.0, t["x"]); assertEquals(-9999.0, t["y"]); assertEquals(2.0, t["pressure"]); assertEquals(1000.0, t["size"])
    }
}
