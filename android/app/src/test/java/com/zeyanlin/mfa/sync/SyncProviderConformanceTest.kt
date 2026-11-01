package com.zeyanlin.mfa.sync

import java.io.File
import kotlinx.coroutines.runBlocking
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Drives every case in `conformance/vectors/sync-provider.json` against the
 * real [HttpProvider].
 *
 * The same decision table is written once per platform. What keeps the three
 * honest is not that they were written together — they were — but that each
 * is checked against the same file. This is the Android copy's check; the
 * Windows copy has `conformance/dotnet` and the Apple copy has a test target
 * of its own, both reading this same JSON.
 *
 * Robolectric, because [HttpProvider] uses `android.util.Base64` and
 * `org.json` for the GitHub and GitLab bodies, and a plain JVM unit test gets
 * the stubs that throw rather than the real implementations. No emulator is
 * needed: nothing here touches a device, a camera or the Keystore.
 */
@RunWith(RobolectricTestRunner::class)
class SyncProviderConformanceTest {

    @Test
    fun `every case matches the shared vectors`() {
        val vectors = loadVectors()
        val token = vectors.getString("token")
        val cases = vectors.getJSONArray("cases")
        assertTrue("the vectors are empty", cases.length() > 0)

        for (index in 0 until cases.length()) {
            runCase(cases.getJSONObject(index), token)
        }
    }

    @Test
    fun `every case describes a flavour and an outcome this suite understands`() {
        // An addition to the table must not pass by being ignored here.
        val cases = loadVectors().getJSONArray("cases")
        for (index in 0 until cases.length()) {
            val case = cases.getJSONObject(index)
            flavourOf(case.getString("flavour"))

            val operation = case.getString("operation")
            assertTrue(operation, operation == "fetch" || operation == "put")

            val outcome = case.getJSONObject("expect").getString("outcome")
            val allowed = if (operation == "fetch") {
                setOf("fetched", "absent", "error")
            } else {
                setOf("written", "lost_race", "error")
            }
            assertTrue("$operation/$outcome", outcome in allowed)
        }
    }

    private fun runCase(case: JSONObject, token: String) {
        val id = case.getString("id")
        val exchanges = case.getJSONArray("exchanges")
        val transport = ScriptedInterceptor(exchanges)
        val provider = HttpProvider(
            flavour = flavourOf(case.getString("flavour")),
            location = case.getString("location"),
            token = token,
            client = OkHttpClient.Builder().addInterceptor(transport).build(),
        )

        val name = case.getString("name")
        val expect = case.getJSONObject("expect")
        val outcome = expect.getString("outcome")
        val operation = case.getString("operation")

        runBlocking {
            when {
                outcome == "error" -> {
                    try {
                        if (operation == "fetch") {
                            provider.fetch(name)
                        } else {
                            provider.put(name, bodyOf(case), expectedOf(case))
                        }
                        fail("$id: expected a failure")
                    } catch (error: Exception) {
                        // Not the outcome under test, but worth asserting
                        // wherever a message is built from a response: the
                        // token travels in a header, and an error body can
                        // echo the request back.
                        assertFalse(
                            "$id: the failure message carries the token",
                            error.message.orEmpty().contains(token),
                        )
                    }
                }

                operation == "fetch" -> {
                    val fetched = provider.fetch(name)
                    if (outcome == "absent") {
                        assertNull(id, fetched)
                    } else {
                        assertNotNull(id, fetched)
                        assertEquals(id, expect.getString("revision"), fetched!!.revision)
                        assertArrayEquals(id, decode(expect.getString("body_base64")), fetched.bytes)
                    }
                }

                else -> {
                    val revision = provider.put(name, bodyOf(case), expectedOf(case))
                    if (outcome == "lost_race") {
                        assertNull(id, revision)
                    } else {
                        assertEquals(id, expect.getString("revision"), revision)
                    }
                }
            }
        }

        assertRequests(id, exchanges, transport)
    }

    /**
     * Checks that the implementation sent what the case says it should.
     *
     * Half the table is about the request rather than the response: whether a
     * write carried its guard, and which verb GitLab was given. A client that
     * reads responses correctly and builds requests wrongly fails in
     * production and nowhere else.
     */
    private fun assertRequests(id: String, exchanges: JSONArray, transport: ScriptedInterceptor) {
        assertEquals(
            "$id: number of requests",
            exchanges.length() - transport.unused,
            transport.seen.size,
        )

        transport.seen.forEachIndexed { index, actual ->
            val specification = exchanges.getJSONObject(index).getJSONObject("request")
            val where = "$id request $index"

            assertEquals(where, specification.getString("method"), actual.method)
            assertEquals(where, specification.getString("url"), actual.url)

            specification.optJSONObject("headers")?.let { required ->
                for (header in required.keys()) {
                    assertEquals(
                        "$where: $header",
                        required.getString(header),
                        actual.headers[header],
                    )
                }
            }

            specification.optJSONArray("headers_absent")?.let { absent ->
                for (position in 0 until absent.length()) {
                    val header = absent.getString(position)
                    assertNull(
                        "$where: $header should not have been sent",
                        actual.headers[header],
                    )
                }
            }

            specification.opt("body_base64")?.let { encoded ->
                assertArrayEquals(where, decode(encoded as String), actual.body)
            }

            specification.optJSONObject("body_json_has")?.let { fields ->
                val parsed = JSONObject(String(actual.body))
                for (field in fields.keys()) {
                    assertEquals("$where: $field", fields.getString(field), parsed.optString(field))
                }
            }

            specification.optJSONArray("body_json_lacks")?.let { fields ->
                val parsed = JSONObject(String(actual.body))
                for (position in 0 until fields.length()) {
                    val field = fields.getString(position)
                    assertFalse(
                        "$where: the body carries $field, which is the guard being tested",
                        parsed.has(field),
                    )
                }
            }
        }
    }

    private fun flavourOf(name: String): HttpProvider.Flavour = when (name) {
        "self_hosted" -> HttpProvider.Flavour.SELF_HOSTED
        "github" -> HttpProvider.Flavour.GITHUB
        "gitlab" -> HttpProvider.Flavour.GITLAB
        else -> throw IllegalArgumentException("unknown flavour $name")
    }

    private fun bodyOf(case: JSONObject): ByteArray = decode(case.getString("body_base64"))

    private fun expectedOf(case: JSONObject): String? =
        if (case.isNull("expected_revision")) null else case.getString("expected_revision")

    private fun decode(encoded: String): ByteArray =
        if (encoded.isEmpty()) ByteArray(0) else java.util.Base64.getDecoder().decode(encoded)

    /** Walks up from the working directory, so the suite runs from anywhere. */
    private fun loadVectors(): JSONObject {
        var directory: File? = File("").absoluteFile
        while (directory != null) {
            val candidate = File(directory, "conformance/vectors/sync-provider.json")
            if (candidate.isFile) return JSONObject(candidate.readText())
            directory = directory.parentFile
        }
        throw IllegalStateException(
            "conformance/vectors/sync-provider.json was not found above ${File("").absolutePath}",
        )
    }

    /**
     * Answers from a script and records what it was asked.
     *
     * An interceptor rather than a local server: the GitHub and GitLab URLs
     * are hard-coded in the implementation, which is right, and an
     * interceptor can still stand in for them.
     */
    private class ScriptedInterceptor(private val exchanges: JSONArray) : Interceptor {
        data class Recorded(
            val method: String,
            val url: String,
            val headers: Map<String, String>,
            val body: ByteArray,
        )

        val seen = mutableListOf<Recorded>()
        private var next = 0

        val unused: Int get() = exchanges.length() - next

        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request()

            val body = request.body?.let { body ->
                val buffer = okio.Buffer()
                body.writeTo(buffer)
                buffer.readByteArray()
            } ?: ByteArray(0)

            seen += Recorded(
                method = request.method,
                url = request.url.toString(),
                headers = request.headers.names().associateWith { request.header(it).orEmpty() },
                body = body,
            )

            if (next >= exchanges.length()) {
                throw IllegalStateException(
                    "the implementation made ${seen.size} requests; the case scripts ${exchanges.length()}",
                )
            }

            val scripted = exchanges.getJSONObject(next++).getJSONObject("response")
            val builder = Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(scripted.getInt("status"))
                .message("scripted")

            val json = scripted.optJSONObject("body_json")
            if (json != null) {
                builder.body(json.toString().toResponseBody("application/json".toMediaType()))
            } else {
                val encoded = scripted.optString("body_base64")
                builder.body(
                    decodeStatic(encoded)
                        .toResponseBody("application/octet-stream".toMediaType()),
                )
            }

            scripted.optJSONObject("headers")?.let { headers ->
                for (header in headers.keys()) {
                    builder.header(header, headers.getString(header))
                }
            }

            return builder.build()
        }

        private fun decodeStatic(encoded: String): ByteArray =
            if (encoded.isEmpty()) ByteArray(0) else java.util.Base64.getDecoder().decode(encoded)
    }
}
