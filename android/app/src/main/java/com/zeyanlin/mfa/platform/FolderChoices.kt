package com.zeyanlin.mfa.platform

import android.content.Context
import android.content.Intent
import android.net.Uri

/**
 * Remembers which folder a sync target points at.
 *
 * A document tree URI only stays usable across launches if the permission is
 * taken persistably, so choosing a folder is two steps: hold the grant, and
 * remember the URI. Neither is secret — it says where, not what — and the
 * vault inside the folder is encrypted regardless.
 */
class FolderChoices(private val context: Context) {

    private val preferences =
        context.getSharedPreferences("mfa-folders", Context.MODE_PRIVATE)

    /** Keeps the user's choice, taking a grant that survives a restart. */
    fun remember(targetId: String, uri: Uri) {
        context.contentResolver.takePersistableUriPermission(
            uri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
        )
        preferences.edit().putString(targetId, uri.toString()).apply()
    }

    /** The remembered URI, or null if it was never chosen or has gone. */
    fun uri(targetId: String): String? {
        val stored = preferences.getString(targetId, null) ?: return null
        // The grant can be revoked by the system or by the user clearing the
        // provider's data; a URI we can no longer read is as good as absent.
        val held = context.contentResolver.persistedUriPermissions.any {
            it.uri.toString() == stored && it.isReadPermission && it.isWritePermission
        }
        return if (held) stored else null
    }

    fun forget(targetId: String) {
        preferences.getString(targetId, null)?.let { stored ->
            runCatching {
                context.contentResolver.releasePersistableUriPermission(
                    Uri.parse(stored),
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                )
            }
        }
        preferences.edit().remove(targetId).apply()
    }
}
