package com.zeyanlin.mfa.platform

import android.content.Context
import com.zeyanlin.mfa.core.LockConfig

/**
 * The handful of lock settings the app needs to know *before* the vault is
 * open.
 *
 * The real settings live in the vault, so they travel between devices. But the
 * vault cannot be read until the app is unlocked, and deciding whether to show
 * the lock screen is the thing that happens first. So the two values that
 * decision needs are mirrored here, outside the vault, and rewritten whenever
 * the vault's settings change.
 *
 * Neither is secret: whether the app locks, and after how long.
 */
class LockPreferences(context: Context) {

    private val preferences =
        context.getSharedPreferences("mfa-lock", Context.MODE_PRIVATE)

    /** Default on: a fresh install should lock, not be open. */
    var isLockEnabled: Boolean
        get() = preferences.getBoolean(KEY_ENABLED, true)
        set(value) = preferences.edit().putBoolean(KEY_ENABLED, value).apply()

    var backgroundTimeoutSeconds: Int
        get() = preferences.getInt(KEY_TIMEOUT, 30)
        set(value) = preferences.edit().putInt(KEY_TIMEOUT, value).apply()

    fun mirror(config: LockConfig) {
        isLockEnabled = config.biometricEnabled
        backgroundTimeoutSeconds = config.backgroundTimeoutSecs.toInt()
    }

    private companion object {
        const val KEY_ENABLED = "lock-enabled"
        const val KEY_TIMEOUT = "lock-background-timeout-secs"
    }
}
