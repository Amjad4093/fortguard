package com.fortguard.sdk.core

import java.net.HttpURLConnection
import java.net.URI

/** Plain HttpURLConnection client. Blocking: call it from a background thread. */
class ApiClient(baseUrl: String, private val timeoutMs: Int = 10_000) {
    private val base = baseUrl.trimEnd('/')

    data class Response(val status: Int, val body: Map<String, Any?>) {
        val ok get() = status in 200..299
        val errorCode: String? get() = (body["error"] as? Map<*, *>)?.get("code") as? String
        val errorMessage: String? get() = (body["error"] as? Map<*, *>)?.get("message") as? String
        fun describe(): String = if (ok) "HTTP $status" else "HTTP $status ${errorCode ?: ""} ${errorMessage ?: ""}".trim()
    }

    fun post(path: String, bodyText: String, headers: Map<String, String> = emptyMap()): Response {
        val conn = URI(base + path).toURL().openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
            conn.outputStream.use { it.write(bodyText.toByteArray(Charsets.UTF_8)) }
            return read(conn)
        } finally {
            conn.disconnect()
        }
    }

    fun get(path: String): Response {
        val conn = URI(base + path).toURL().openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "GET"
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            return read(conn)
        } finally {
            conn.disconnect()
        }
    }

    private fun read(conn: HttpURLConnection): Response {
        val status = conn.responseCode
        val stream = if (status >= 400) conn.errorStream else conn.inputStream
        val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
        @Suppress("UNCHECKED_CAST")
        val parsed = runCatching { MiniJson.parse(text) as? Map<String, Any?> }.getOrNull()
        return Response(status, parsed ?: emptyMap())
    }

    fun postJson(path: String, body: Map<String, Any?>, headers: Map<String, String> = emptyMap()) =
        post(path, CanonicalJson.encode(body), headers)
}
