package com.zeyanlin.mfa.platform

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The Android Keystore, holding the keys the core needs.
 *
 * This is `mfa_core::platform::SecureStore` on Android. The Keystore will not
 * store arbitrary bytes, only keys it generated, so the shape is: a
 * non-exportable AES key lives in the Keystore and wraps the core's 32-byte
 * keys, and the wrapped bytes sit in `SharedPreferences`. Hardware holds the
 * only thing that can unwrap them.
 *
 * The wrapping key is deliberately **not** `setUserAuthenticationRequired`.
 * That sounds stronger and is a trap: with `setInvalidatedByBiometricEnrollment`
 * (on by default) a user who adds a fingerprint destroys the key, and with it
 * every account in the vault. The unlock gate is [Biometrics] instead, which
 * already falls back to the device credential.
 */
class KeystoreSecrets(context: Context) {

    private val preferences =
        context.getSharedPreferences("mfa-secrets", Context.MODE_PRIVATE)

    fun dataKey(): ByteArray? = unwrap(KEY_VAULT)
    fun putDataKey(key: ByteArray) = wrap(KEY_VAULT, key)
    fun deleteDataKey() = preferences.edit().remove(KEY_VAULT).apply()

    fun syncKey(): ByteArray? = unwrap(KEY_SYNC)
    fun putSyncKey(key: ByteArray) = wrap(KEY_SYNC, key)
    fun deleteSyncKey() = preferences.edit().remove(KEY_SYNC).apply()

    /**
     * A sync target's token.
     *
     * Tokens live here and never in the vault: the vault's settings travel to
     * the other devices, and a GitHub token must not.
     */
    fun token(targetId: String): String? =
        unwrap("token-$targetId")?.toString(Charsets.UTF_8)

    fun putToken(targetId: String, token: String) =
        wrap("token-$targetId", token.toByteArray(Charsets.UTF_8))

    fun deleteToken(targetId: String) =
        preferences.edit().remove("token-$targetId").apply()

    /** Removes everything. This is what "reset the app" means. */
    fun deleteEverything() {
        preferences.edit().clear().apply()
        runCatching { keystore().deleteEntry(WRAPPING_ALIAS) }
    }

    // --- wrapping --------------------------------------------------------

    private fun wrap(name: String, value: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())

        val sealed = cipher.iv + cipher.doFinal(value)
        preferences.edit()
            .putString(name, Base64.encodeToString(sealed, Base64.NO_WRAP))
            .apply()
    }

    private fun unwrap(name: String): ByteArray? {
        val stored = preferences.getString(name, null) ?: return null
        val sealed = runCatching { Base64.decode(stored, Base64.NO_WRAP) }.getOrNull() ?: return null
        if (sealed.size <= IV_LENGTH) return null

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            wrappingKey(),
            GCMParameterSpec(TAG_BITS, sealed, 0, IV_LENGTH),
        )
        // A failure here means the Keystore entry has gone — a factory reset,
        // or a restore onto another device. There is nothing to recover, and
        // the caller has to say so rather than retry.
        return runCatching {
            cipher.doFinal(sealed, IV_LENGTH, sealed.size - IV_LENGTH)
        }.getOrNull()
    }

    private fun keystore(): KeyStore =
        KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun wrappingKey(): SecretKey {
        val existing = keystore().getEntry(WRAPPING_ALIAS, null) as? KeyStore.SecretKeyEntry
        existing?.secretKey?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(specification(strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P))
        return runCatching { generator.generateKey() }.getOrElse {
            // Not every device has a StrongBox, and asking for one it does not
            // have fails at generation time rather than reporting it up front.
            generator.init(specification(strongBox = false))
            generator.generateKey()
        }
    }

    private fun specification(strongBox: Boolean): KeyGenParameterSpec =
        KeyGenParameterSpec.Builder(
            WRAPPING_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // See the class documentation: binding this to authentication
            // would let a fingerprint enrolment destroy the vault.
            .setUserAuthenticationRequired(false)
            .apply {
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val WRAPPING_ALIAS = "mfa-wrapping-key"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val KEY_VAULT = "vault-data-key"
        const val KEY_SYNC = "sync-key"
        const val IV_LENGTH = 12
        const val TAG_BITS = 128
    }
}
