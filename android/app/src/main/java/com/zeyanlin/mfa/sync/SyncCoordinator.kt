package com.zeyanlin.mfa.sync

import android.content.Context
import android.net.Uri
import com.zeyanlin.mfa.core.MergeSummary
import com.zeyanlin.mfa.core.MfaException
import com.zeyanlin.mfa.core.RemoteFile
import com.zeyanlin.mfa.core.SyncKind
import com.zeyanlin.mfa.core.SyncTargetView
import com.zeyanlin.mfa.core.VaultHandle
import com.zeyanlin.mfa.platform.FolderChoices
import com.zeyanlin.mfa.platform.KeystoreSecrets

/**
 * Runs one sync round over every enabled target.
 *
 * The core decides what the vault should become; this decides how the bytes
 * move. Read, merge, write — retrying a target whose revision moved while we
 * were merging, and never overwriting it, because the file is opaque
 * ciphertext that nothing can merge after the fact.
 */
class SyncCoordinator(
    private val context: Context,
    private val secrets: KeystoreSecrets,
    private val vault: VaultHandle,
    private val syncKey: ByteArray,
) {
    data class Result(
        val summary: MergeSummary,
        val written: List<String> = emptyList(),
        val problems: List<Pair<String, String>> = emptyList(),
    )

    /**
     * Syncs every enabled target.
     *
     * The caller seals the vault and writes it locally afterwards. This does
     * not touch the local file, so a failed sync cannot corrupt it.
     */
    suspend fun run(): Result {
        var summary = MergeSummary(0u, 0u, 0u, 0u, false)
        val written = mutableListOf<String>()
        val problems = mutableListOf<Pair<String, String>>()

        // Build the providers first, so a target with no token is reported
        // rather than silently skipped.
        var pending = vault.syncTargets().filter { it.enabled }.mapNotNull { target ->
            runCatching { target to provider(target) }
                .onFailure { problems += target.label to (it.message ?: "could not be set up") }
                .getOrNull()
        }
        if (pending.isEmpty()) return Result(summary, written, problems)

        var attempt = 0
        while (pending.isNotEmpty() && attempt < MAX_ATTEMPTS) {
            attempt++
            val retry = mutableListOf<Pair<SyncTargetView, SyncProvider>>()

            // 1. Read every target.
            val revisions = mutableMapOf<String, String?>()
            val remotes = mutableListOf<RemoteFile>()
            for ((target, provider) in pending) {
                try {
                    val fetched = provider.fetch(SyncFile.VAULT)
                    revisions[target.id] = fetched?.revision
                    remotes += RemoteFile(target.id, fetched?.bytes)
                } catch (error: Exception) {
                    problems += target.label to (error.message ?: "could not be reached")
                }
            }
            if (remotes.isEmpty()) break

            // 2. Merge them all at once: one round, one dedupe.
            val round = try {
                vault.sync(remotes, syncKey)
            } catch (error: MfaException.Failed) {
                problems += "sync" to error.displayMessage()
                break
            }
            summary = summary.plus(round.summary)

            round.failures.forEach { failure ->
                val label = pending.firstOrNull { it.first.id == failure.target }?.first?.label
                    ?: failure.target
                problems += label to failure.message
            }

            // 3. Write back to whichever targets are behind.
            for (upload in round.uploads) {
                val entry = pending.firstOrNull { it.first.id == upload.target } ?: continue
                try {
                    val result = entry.second.put(
                        SyncFile.VAULT,
                        upload.bytes,
                        revisions[upload.target],
                    )
                    if (result == null) {
                        // Somebody wrote first. Round again against what is
                        // there now rather than overwriting it.
                        retry += entry
                    } else {
                        written += entry.first.label
                    }
                } catch (error: Exception) {
                    problems += entry.first.label to (error.message ?: "could not be written")
                }
            }

            pending = retry
        }

        pending.forEach { (target, _) ->
            problems += target.label to
                "Another device kept writing first. It will try again on the next sync."
        }
        return Result(summary, written, problems)
    }

    /** Publishes the wrapped sync key so another device can join. */
    suspend fun publishKeyFile(wrapped: ByteArray) {
        vault.syncTargets().filter { it.enabled }.forEach { target ->
            val provider = provider(target)
            val existing = provider.fetch(SyncFile.KEY)
            provider.put(SyncFile.KEY, wrapped, existing?.revision)
        }
    }

    /** Looks for the key file, for a device joining an existing sync set. */
    suspend fun fetchKeyFile(): ByteArray? {
        vault.syncTargets().filter { it.enabled }.forEach { target ->
            runCatching { provider(target).fetch(SyncFile.KEY) }
                .getOrNull()
                ?.let { return it.bytes }
        }
        return null
    }

    private fun provider(target: SyncTargetView): SyncProvider = when (target.kind) {
        SyncKind.FOLDER -> {
            val uri = FolderChoices(context).uri(target.id)
                ?: throw SyncProblem("the folder is no longer reachable; choose it again")
            FolderProvider(context, Uri.parse(uri))
        }

        SyncKind.GIT_HUB, SyncKind.GIT_LAB, SyncKind.SERVER -> {
            val token = secrets.token(target.id)
            if (token.isNullOrEmpty()) {
                throw SyncProblem("no token is saved for “${target.label}”; add it again in Settings")
            }
            HttpProvider(
                flavour = when (target.kind) {
                    SyncKind.GIT_HUB -> HttpProvider.Flavour.GITHUB
                    SyncKind.GIT_LAB -> HttpProvider.Flavour.GITLAB
                    else -> HttpProvider.Flavour.SELF_HOSTED
                },
                location = target.location,
                token = token,
            )
        }
    }

    private fun MergeSummary.plus(other: MergeSummary) = MergeSummary(
        added = added + other.added,
        updated = updated + other.updated,
        deleted = deleted + other.deleted,
        deduped = deduped + other.deduped,
        changed = changed || other.changed,
    )

    private companion object {
        /**
         * How many times one target may lose the race before we leave it for
         * the next sync. Enough for a real collision, small enough that a
         * misbehaving server cannot spin here.
         */
        const val MAX_ATTEMPTS = 3
    }
}

/**
 * The text to show for a core failure.
 *
 * The generated `MfaException.Failed` overrides `message` with
 * `"kind=…, message=…"`, which is for a log and not for a person. The real
 * sentence is after the last `message=`.
 */
fun MfaException.Failed.displayMessage(): String {
    val raw = message ?: return "Something went wrong."
    return raw.substringAfterLast("message=").ifBlank { raw }
}
