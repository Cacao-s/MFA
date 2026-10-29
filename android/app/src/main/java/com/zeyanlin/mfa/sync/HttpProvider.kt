package com.zeyanlin.mfa.sync

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

/**
 * GitHub, GitLab and the self-hosted server.
 *
 * All three are "a file with a revision" over HTTP, differing only in the
 * shape of the request and in what they call the revision:
 *
 * | Target | Revision | Guarded write |
 * |---|---|---|
 * | self-hosted | ETag | `If-Match`, 412 when stale |
 * | GitHub | blob `sha` | `sha` in the body, 409 when stale |
 * | GitLab | `last_commit_id` | `last_commit_id` in the body, 400/409 |
 *
 * The token is passed in at construction and never stored in the vault,
 * because the vault's settings travel to the other devices.
 */
class HttpProvider(
    private val flavour: Flavour,
    private val location: String,
    private val token: String,
    private val client: OkHttpClient = shared,
) : SyncProvider {

    enum class Flavour {
        /** [location] is the server's base URL. */
        SELF_HOSTED,

        /** [location] is `owner/repo` or `owner/repo/branch`. */
        GITHUB,

        /** [location] is `project-id` or `project-id/branch`. */
        GITLAB,
    }

    override suspend fun fetch(name: String): SyncProvider.Fetched? = withContext(Dispatchers.IO) {
        when (flavour) {
            Flavour.SELF_HOSTED -> fetchSelfHosted(name)
            Flavour.GITHUB -> fetchGitHub(name)
            Flavour.GITLAB -> fetchGitLab(name)
        }
    }

    override suspend fun put(name: String, bytes: ByteArray, expected: String?): String? =
        withContext(Dispatchers.IO) {
            when (flavour) {
                Flavour.SELF_HOSTED -> putSelfHosted(name, bytes, expected)
                Flavour.GITHUB -> putGitHub(name, bytes, expected)
                Flavour.GITLAB -> putGitLab(name, bytes, expected)
            }
        }

    // --- self-hosted -----------------------------------------------------

    private fun fetchSelfHosted(name: String): SyncProvider.Fetched? {
        val request = Request.Builder()
            .url("${location.trimEnd('/')}/v1/files/$name")
            .header("Authorization", "Bearer $token")
            .build()

        client.newCall(request).execute().use { response ->
            if (response.code == 404) return null
            if (!response.isSuccessful) throw problem(response.code, response.body?.string())

            val etag = response.header("ETag")?.trim('"')
                ?: throw SyncProblem("the server's response had no ETag")
            val bytes = response.body?.bytes() ?: ByteArray(0)
            return SyncProvider.Fetched(bytes, etag)
        }
    }

    private fun putSelfHosted(name: String, bytes: ByteArray, expected: String?): String? {
        val builder = Request.Builder()
            .url("${location.trimEnd('/')}/v1/files/$name")
            .header("Authorization", "Bearer $token")
            .put(bytes.toRequestBody("application/octet-stream".toMediaType()))

        if (expected != null) builder.header("If-Match", "\"$expected\"")
        else builder.header("If-None-Match", "*")

        client.newCall(builder.build()).execute().use { response ->
            // 412 is the server saying somebody wrote first: a retry, not an
            // error to show the user.
            if (response.code == 412) return null
            if (!response.isSuccessful) throw problem(response.code, response.body?.string())
            return response.header("ETag")?.trim('"') ?: sha256(bytes)
        }
    }

    // --- GitHub ----------------------------------------------------------

    private fun fetchGitHub(name: String): SyncProvider.Fetched? {
        val (owner, repo, branch) = gitHubLocation()
        val request = Request.Builder()
            .url("https://api.github.com/repos/$owner/$repo/contents/$name?ref=$branch")
            .header("Authorization", "Bearer $token")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .build()

        client.newCall(request).execute().use { response ->
            if (response.code == 404) return null
            if (!response.isSuccessful) throw problem(response.code, response.body?.string())

            val json = JSONObject(response.body?.string().orEmpty())
            if (json.optString("encoding") != "base64") {
                throw SyncProblem("the file came back in an unexpected encoding")
            }
            val bytes = Base64.decode(json.getString("content"), Base64.DEFAULT)
            return SyncProvider.Fetched(bytes, json.getString("sha"))
        }
    }

    private fun putGitHub(name: String, bytes: ByteArray, expected: String?): String? {
        val (owner, repo, branch) = gitHubLocation()
        val body = JSONObject().apply {
            put("message", "MFA sync")
            put("content", Base64.encodeToString(bytes, Base64.NO_WRAP))
            put("branch", branch)
            // Without `sha` GitHub refuses to overwrite, which is the guard we
            // want on a first write.
            if (expected != null) put("sha", expected)
        }

        val request = Request.Builder()
            .url("https://api.github.com/repos/$owner/$repo/contents/$name")
            .header("Authorization", "Bearer $token")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .put(body.toString().toRequestBody("application/json".toMediaType()))
            .build()

        client.newCall(request).execute().use { response ->
            // 409 is a stale sha; 422 is "already exists" on a create.
            if (response.code == 409 || response.code == 422) return null
            if (!response.isSuccessful) throw problem(response.code, response.body?.string())

            return JSONObject(response.body?.string().orEmpty())
                .getJSONObject("content").getString("sha")
        }
    }

    private fun gitHubLocation(): Triple<String, String, String> {
        val parts = location.split('/').filter { it.isNotBlank() }
        if (parts.size < 2) throw SyncProblem("expected owner/repo or owner/repo/branch")
        return Triple(parts[0], parts[1], parts.getOrElse(2) { "main" })
    }

    // --- GitLab ----------------------------------------------------------

    private fun fetchGitLab(name: String): SyncProvider.Fetched? {
        val (project, branch) = gitLabLocation()
        val request = Request.Builder()
            .url("https://gitlab.com/api/v4/projects/${encode(project)}/repository/files/${encode(name)}?ref=$branch")
            .header("PRIVATE-TOKEN", token)
            .build()

        client.newCall(request).execute().use { response ->
            if (response.code == 404) return null
            if (!response.isSuccessful) throw problem(response.code, response.body?.string())

            val json = JSONObject(response.body?.string().orEmpty())
            if (json.optString("encoding") != "base64") {
                throw SyncProblem("the file came back in an unexpected encoding")
            }
            val bytes = Base64.decode(json.getString("content"), Base64.DEFAULT)
            return SyncProvider.Fetched(bytes, json.getString("last_commit_id"))
        }
    }

    private fun putGitLab(name: String, bytes: ByteArray, expected: String?): String? {
        val (project, branch) = gitLabLocation()
        val body = JSONObject().apply {
            put("branch", branch)
            put("content", Base64.encodeToString(bytes, Base64.NO_WRAP))
            put("encoding", "base64")
            put("commit_message", "MFA sync")
            if (expected != null) put("last_commit_id", expected)
        }

        val url = "https://gitlab.com/api/v4/projects/${encode(project)}/repository/files/${encode(name)}"
        val payload = body.toString().toRequestBody("application/json".toMediaType())
        // GitLab is strict: POST creates, PUT updates.
        val request = Request.Builder().url(url).header("PRIVATE-TOKEN", token)
            .apply { if (expected == null) post(payload) else put(payload) }
            .build()

        client.newCall(request).execute().use { response ->
            // 400 covers a stale last_commit_id and "already exists".
            if (response.code == 400 || response.code == 409) return null
            if (!response.isSuccessful) throw problem(response.code, response.body?.string())
        }
        // The write response has no commit id, so read it back.
        return fetchGitLab(name)?.revision
    }

    private fun gitLabLocation(): Pair<String, String> {
        val parts = location.split('/').filter { it.isNotBlank() }
        val project = parts.firstOrNull() ?: throw SyncProblem("expected a project id, optionally /branch")
        return project to parts.getOrElse(1) { "main" }
    }

    // --- shared ----------------------------------------------------------

    private fun encode(value: String): String =
        java.net.URLEncoder.encode(value, "UTF-8")

    private fun sha256(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    /**
     * Only the first line of the body, and never the request: an error body
     * can echo headers, and the token is in one of them.
     */
    private fun problem(code: Int, body: String?): SyncProblem {
        val detail = body?.take(200)?.lineSequence()?.firstOrNull().orEmpty()
        return SyncProblem(if (detail.isBlank()) "the server answered $code" else "$code: $detail")
    }

    companion object {
        private val shared = OkHttpClient.Builder().build()
    }
}
