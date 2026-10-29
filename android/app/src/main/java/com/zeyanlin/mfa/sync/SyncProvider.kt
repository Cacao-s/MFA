package com.zeyanlin.mfa.sync

/**
 * One place a copy of the vault is kept.
 *
 * This is `mfa_core::platform::SyncProvider`. The core never calls it — its
 * `sync` takes and returns bytes — so this is free to be a suspending
 * interface in the shape Android actually wants.
 *
 * [Fetched.revision] is whatever the target uses to detect a concurrent write:
 * an ETag, a blob SHA, a commit id. It matters because the sync file is opaque
 * ciphertext that no target can merge, so a write has to fail rather than
 * clobber a revision we have not merged.
 */
interface SyncProvider {

    data class Fetched(val bytes: ByteArray, val revision: String) {
        // ByteArray in a data class needs these, or two identical files
        // compare unequal.
        override fun equals(other: Any?): Boolean =
            other is Fetched && revision == other.revision && bytes.contentEquals(other.bytes)

        override fun hashCode(): Int = 31 * revision.hashCode() + bytes.contentHashCode()
    }

    /** Downloads the file, or null if it is not there yet. */
    suspend fun fetch(name: String): Fetched?

    /**
     * Uploads, only if the remote is still at [expected] (null meaning "only
     * if it does not exist yet").
     *
     * Returns the new revision, or null when the remote moved — which tells
     * the caller to fetch, merge and try again.
     */
    suspend fun put(name: String, bytes: ByteArray, expected: String?): String?
}

/** The two file names a sync set uses. */
object SyncFile {
    const val VAULT = "mfa-sync.vault"
    const val KEY = "mfa-sync.key"
}

class SyncProblem(message: String) : Exception(message)
