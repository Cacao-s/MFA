package com.zeyanlin.mfa.platform

import android.content.Context
import java.io.File

/**
 * Where the encrypted vault file lives, and how it is written.
 *
 * This is `mfa_core::platform::VaultStorage` on Android. Internal storage, so
 * no permission and no other app can read it; and the write is atomic, because
 * a vault truncated half way through is a vault that no longer decrypts and
 * the accounts in it are not recoverable.
 */
class VaultStore(context: Context) {

    private val file = File(context.filesDir, "vault.mfa")

    val exists: Boolean get() = file.exists()

    fun read(): ByteArray? = if (exists) file.readBytes() else null

    /** Writes to a temporary file and renames, so a crash leaves the old one. */
    fun write(bytes: ByteArray) {
        val temporary = File(file.parentFile, "${file.name}.tmp")
        temporary.outputStream().use { stream ->
            stream.write(bytes)
            // Flush to the device before the rename: otherwise a power loss
            // can leave the new name pointing at an empty file.
            stream.fd.sync()
        }
        if (!temporary.renameTo(file)) {
            temporary.delete()
            error("could not replace the vault file")
        }
    }

    fun deleteFile() {
        file.delete()
    }
}
