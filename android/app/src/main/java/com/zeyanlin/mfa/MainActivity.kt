package com.zeyanlin.mfa

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.zeyanlin.mfa.ui.AppViewModel
import com.zeyanlin.mfa.ui.MfaApp
import com.zeyanlin.mfa.ui.theme.MfaTheme

/**
 * `FragmentActivity` because `BiometricPrompt` requires one.
 *
 * Two things here that are easy to miss and matter:
 *
 * - `FLAG_SECURE` keeps the codes out of the recent-apps thumbnail and out of
 *   screenshots and screen recordings (spec §4). It is set for the whole
 *   activity rather than toggled, because toggling it races the system's own
 *   snapshot.
 * - `singleTask` plus [onNewIntent]: an `otpauth://` link from a browser or a
 *   password manager should add an account to the running app, not start a
 *   second copy of it.
 */
class MainActivity : FragmentActivity() {

    private var pendingUri: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                        WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()

        pendingUri = otpauthUri(intent)

        setContent {
            MfaTheme {
                val model: AppViewModel = viewModel()
                MfaApp(
                    model = model,
                    activity = this,
                    takePendingUri = { pendingUri.also { pendingUri = null } },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        otpauthUri(intent)?.let { pendingUri = it }
    }

    private fun otpauthUri(intent: Intent?): String? =
        intent?.data?.takeIf { it.scheme.equals("otpauth", ignoreCase = true) }?.toString()
}
