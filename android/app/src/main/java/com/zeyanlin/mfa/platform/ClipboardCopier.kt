package com.zeyanlin.mfa.platform

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Copying a code, and clearing it again (spec §4).
 *
 * This is `mfa_core::platform::Clipboard` on Android. Two things it does that
 * are worth knowing:
 *
 * - From Android 13 the clip is marked sensitive, which stops the system
 *   showing the code in the copy confirmation toast.
 * - Clearing is ours to do, with a timer, and only if nothing else has been
 *   copied since — wiping something the user copied afterwards would be worse
 *   than leaving the code. The timer dies with the process, so [copy] reports
 *   whether the clearing can honestly be promised.
 */
class ClipboardCopier(
    private val context: Context,
    private val scope: CoroutineScope,
) {
    private val clipboard =
        context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    /** Returns whether the code will really be cleared. */
    fun copy(code: String, clearAfterSeconds: Int): Boolean {
        val clip = ClipData.newPlainText("Verification code", code).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
        }
        clipboard.setPrimaryClip(clip)

        scope.launch {
            delay(clearAfterSeconds * 1_000L)
            val current = clipboard.primaryClip
                ?.takeIf { it.itemCount > 0 }
                ?.getItemAt(0)?.text?.toString()
            if (current != code) return@launch

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                clipboard.clearPrimaryClip()
            } else {
                clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
            }
        }

        // Best effort: the timer does not survive the process being killed.
        return false
    }
}
