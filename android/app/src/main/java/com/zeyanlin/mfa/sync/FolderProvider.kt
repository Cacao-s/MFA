package com.zeyanlin.mfa.sync

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * A folder the user picked through the system document picker — Google Drive,
 * OneDrive, Dropbox, or local storage.
 *
 * There is no server here to hand out revisions, so the revision is the file's
 * own content hash. That answers the only question the sync round asks — "has
 * this changed since I read it?" — and gives the same answer on every device,
 * which a modification date does not.
 *
 * It cannot be atomic against another device writing at the same instant
 * through a syncing provider; nothing at this layer can. What it does
 * guarantee is that we never overwrite a revision we have not merged, which
 * turns a lost write into a retry rather than lost accounts.
 */
class FolderProvider(
    private val context: Context,
    private val treeUri: Uri,
) : SyncProvider {

    override suspend fun fetch(name: String): SyncProvider.Fetched? =
        withContext(Dispatchers.IO) {
            val file = find(name) ?: return@withContext null
            val bytes = context.contentResolver.openInputStream(file.uri)?.use { it.readBytes() }
                ?: return@withContext null
            SyncProvider.Fetched(bytes, hash(bytes))
        }

    override suspend fun put(name: String, bytes: ByteArray, expected: String?): String? =
        withContext(Dispatchers.IO) {
            val existing = find(name)
            val current = existing?.let { file ->
                context.contentResolver.openInputStream(file.uri)?.use { hash(it.readBytes()) }
            }
            if (current != expected) return@withContext null

            val tree = DocumentFile.fromTreeUri(context, treeUri)
                ?: throw SyncProblem("the folder is no longer reachable; choose it again")
            val file = existing
                ?: tree.createFile("application/octet-stream", name)
                ?: throw SyncProblem("could not create $name in that folder")

            // "wt" truncates; without it a shorter vault leaves the tail of
            // the previous one behind and the file no longer decrypts.
            context.contentResolver.openOutputStream(file.uri, "wt")?.use { it.write(bytes) }
                ?: throw SyncProblem("could not write to that folder")

            hash(bytes)
        }

    private fun find(name: String): DocumentFile? =
        DocumentFile.fromTreeUri(context, treeUri)?.findFile(name)?.takeIf { it.isFile }

    private fun hash(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
}
