package com.zeyanlin.mfa.platform

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * The app-lock gate (spec §4).
 *
 * This is `mfa_core::platform::BiometricAuth` on Android. The authenticators
 * are `BIOMETRIC_STRONG or DEVICE_CREDENTIAL`, so a failed fingerprint falls
 * back to the device PIN, pattern or password without the app needing a PIN of
 * its own to be the fallback — the same reasoning as on Apple platforms, and
 * the same reason the vault's PIN is a re-authentication step here rather than
 * the unlock.
 */
object Biometrics {

    sealed interface Capability {
        /** Fingerprint or face is enrolled. */
        data object Biometric : Capability
        /** No biometrics, but there is a PIN, pattern or password. */
        data object CredentialOnly : Capability
        /** Nothing is set up, so the app cannot lock. */
        data object None : Capability
    }

    sealed interface Outcome {
        data object Succeeded : Outcome
        /** The user dismissed the prompt. Not a failure; do not nag. */
        data object Cancelled : Outcome
        data class Failed(val message: String) : Outcome
    }

    private const val AUTHENTICATORS =
        Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL

    fun capability(activity: FragmentActivity): Capability {
        val manager = BiometricManager.from(activity)
        return when {
            manager.canAuthenticate(Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS -> Capability.Biometric

            manager.canAuthenticate(Authenticators.DEVICE_CREDENTIAL) ==
                BiometricManager.BIOMETRIC_SUCCESS -> Capability.CredentialOnly

            else -> Capability.None
        }
    }

    /** Prompts the user. The strings are shown by the system. */
    suspend fun authenticate(activity: FragmentActivity): Outcome =
        suspendCancellableCoroutine { continuation ->
            val prompt = BiometricPrompt(
                activity,
                activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult,
                    ) {
                        if (continuation.isActive) continuation.resume(Outcome.Succeeded)
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        if (!continuation.isActive) return
                        val outcome = when (code) {
                            BiometricPrompt.ERROR_USER_CANCELED,
                            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                            BiometricPrompt.ERROR_CANCELED,
                            -> Outcome.Cancelled

                            else -> Outcome.Failed(message.toString())
                        }
                        continuation.resume(outcome)
                    }

                    // onAuthenticationFailed is a single rejected finger; the
                    // prompt stays up and tries again, so it is not an outcome.
                },
            )

            prompt.authenticate(
                BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Unlock MFA")
                    .setSubtitle("Your verification codes are locked")
                    .setAllowedAuthenticators(AUTHENTICATORS)
                    .setConfirmationRequired(false)
                    .build(),
            )

            continuation.invokeOnCancellation { prompt.cancelAuthentication() }
        }
}
