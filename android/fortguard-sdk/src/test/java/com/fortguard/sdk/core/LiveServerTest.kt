package com.fortguard.sdk.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

/**
 * Runs the real protocol against a FortGuard server started with --dev. Skipped unless the address is set:
 *
 *   python -m fortguard.app --dev                          (in the server folder)
 *   FORTGUARD_TEST_SERVER=http://127.0.0.1:8080 ./gradlew :fortguard-sdk:test
 */
class LiveServerTest {
    private val server: String? = System.getenv("FORTGUARD_TEST_SERVER")

    private fun engine(env: MutableMap<String, Any?>): Pair<FortGuardEngine, ApiClient> {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val api = ApiClient(server!!)
        val e = FortGuardEngine(api, "com.example.mobilebank", Ids.random("dev_", 12), JcaDeviceKey(kp.private, kp.public),
            DevAttestationProvider(api), { env.toMap() })
        return e to api
    }

    private fun environment() = mutableMapOf<String, Any?>(
        "os" to "Android", "os_version" to "15", "is_rooted" to false, "is_emulator" to false,
        "has_hooking_framework" to false, "active_remote_software" to false, "screen_sharing" to false,
        "active_call" to false, "vpn" to false, "mock_location" to false,
    )

    private fun evaluate(api: ApiClient, sessionId: String): Map<String, Any?> {
        val r = api.postJson("/v1/risk/evaluate", mapOf(
            "session_id" to sessionId, "user_id" to "usr_jvmtest1", "event_type" to "FUNDS_TRANSFER",
            "transaction_details" to mapOf("amount" to 5000.0, "currency" to "PKR",
                "beneficiary_account" to "PK36EXMP00992201029381", "is_new_beneficiary" to false)),
            mapOf("X-API-Key" to (System.getenv("FORTGUARD_API_KEY") ?: "dev-only-api-key")))
        assertEquals(r.describe(), 200, r.status)
        return r.body
    }

    @Test fun enrollSignSendAndEvaluate() {
        assumeTrue("set FORTGUARD_TEST_SERVER to run", server != null)
        val env = environment()
        val (e, api) = engine(env)
        assertTrue(e.enroll().ok)
        val now = System.currentTimeMillis()
        for (i in 0 until 12) e.buffer.key("DOWN", Field.AMOUNT, now - 5000 + i * (120 + (i * 37) % 90))
        val f = e.flush()
        assertTrue(f.message, f.ok)
        val body = evaluate(api, e.sessionId)
        assertEquals("ALLOW", body["risk_level"])
    }

    @Test fun serverRejectsATamperedBatchAndAReplay() {
        assumeTrue("set FORTGUARD_TEST_SERVER to run", server != null)
        val env = environment().apply { put("active_call", true) }
        val (e, api) = engine(env)
        assertTrue(e.flush(force = true).ok)
        val sent = e.lastBatchJson!!
        assertEquals("bad_signature", api.post("/v1/telemetry/stream", sent.replace("\"active_call\":true", "\"active_call\":false")).errorCode)
        assertEquals("replay_detected", api.post("/v1/telemetry/stream", sent).errorCode)
    }

    private class Memory : ConfigMemory {
        val values = HashMap<String, String>()
        override fun get(name: String) = values[name]
        override fun put(name: String, value: String) { values[name] = value }
    }

    /** The server signs in Python, the SDK verifies with the JVM: the two must agree on every byte. */
    @Test fun signedConfigurationFromTheRealServerVerifies() {
        assumeTrue("set FORTGUARD_TEST_SERVER to run", server != null)
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val api = ApiClient(server!!)
        val memory = Memory()
        val trusting = FortGuardEngine(api, "com.example.mobilebank", Ids.random("dev_", 12), JcaDeviceKey(kp.private, kp.public),
            DevAttestationProvider(api), { environment().toMap() }, configMemory = memory)
        val first = trusting.refreshConfig()
        assertTrue(first.message, first.ok)
        assertTrue(trusting.policy.version >= 1)
        assertTrue("the first key seen is remembered", memory.values.containsKey("config_key"))
        // An app built with a different key refuses the same configuration and keeps collecting everything.
        val pinnedWrong = FortGuardEngine(api, "com.example.mobilebank", Ids.random("dev_", 12), JcaDeviceKey(kp.private, kp.public),
            DevAttestationProvider(api), { environment().toMap() }, configKey = kp.public.encoded)
        val refused = pinnedWrong.refreshConfig()
        assertTrue(refused.message, !refused.ok && refused.message.contains("signature does not verify"))
        assertEquals(CollectionPolicy(), pinnedWrong.policy)
        // A batch is accepted and tells the SDK which configuration version the server is on.
        val f = trusting.flush(force = true)
        assertTrue(f.message, f.ok)
        assertEquals(trusting.policy.version, f.response!!.body["config_version"])
    }
}
