package com.zeyanlin.mfa.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.zeyanlin.mfa.core.AccountDraft
import com.zeyanlin.mfa.core.AccountView
import com.zeyanlin.mfa.core.LockConfig
import com.zeyanlin.mfa.core.MergeSummary
import com.zeyanlin.mfa.core.MfaException
import com.zeyanlin.mfa.core.Preferences
import com.zeyanlin.mfa.core.SyncTargetView
import com.zeyanlin.mfa.core.VaultHandle
import com.zeyanlin.mfa.core.generateDataKey
import com.zeyanlin.mfa.core.migrationProgress
import com.zeyanlin.mfa.core.newSyncKey
import com.zeyanlin.mfa.core.unwrapSyncKey
import com.zeyanlin.mfa.core.wrapSyncKey
import com.zeyanlin.mfa.platform.ClipboardCopier
import com.zeyanlin.mfa.platform.FolderChoices
import com.zeyanlin.mfa.platform.KeystoreSecrets
import com.zeyanlin.mfa.platform.LockPreferences
import com.zeyanlin.mfa.platform.VaultStore
import com.zeyanlin.mfa.sync.SyncCoordinator
import com.zeyanlin.mfa.sync.displayMessage
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * The one piece of state the whole app reads.
 *
 * It owns the open vault, and nothing else holds a [VaultHandle], so there is a
 * single place where "change something, then seal and write" happens. Every
 * mutation goes through [mutate], which means a change can never be left
 * unsaved by a code path that forgot.
 */
class AppViewModel(application: Application) : AndroidViewModel(application) {

    enum class Phase { LOADING, NEEDS_SETUP, LOCKED, UNLOCKED }

    data class Message(val title: String, val body: String)

    data class UiState(
        val phase: Phase = Phase.LOADING,
        val accounts: List<AccountView> = emptyList(),
        val query: String = "",
        val status: String? = null,
        val message: Message? = null,
        val isSyncing: Boolean = false,
        val hasSyncKey: Boolean = false,
    )

    private val secrets = KeystoreSecrets(application)
    private val store = VaultStore(application)
    private val lockPreferences = LockPreferences(application)
    private val folders = FolderChoices(application)
    private val clipboard = ClipboardCopier(application, viewModelScope)

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private var vault: VaultHandle? = null
    private var ticker: Job? = null
    private var statusReset: Job? = null
    private var leftForeground: Long? = null

    val isLockEnabled: Boolean get() = lockPreferences.isLockEnabled

    // --- lifecycle -------------------------------------------------------

    /** Works out whether this is a first run, and whether to lock. */
    fun start() {
        if (!store.exists) {
            _state.update { it.copy(phase = Phase.NEEDS_SETUP) }
            return
        }
        if (lockPreferences.isLockEnabled) {
            _state.update { it.copy(phase = Phase.LOCKED, hasSyncKey = secrets.syncKey() != null) }
        } else {
            openVault()
        }
    }

    /** First run: make a key, store it, and write an empty vault. */
    fun createVault() = report("Could not create your vault") {
        val key = generateDataKey()
        // Store the key before sealing anything with it: the other order
        // leaves a vault file nothing can read.
        secrets.putDataKey(key)

        val opened = VaultHandle.create(key)
        store.write(opened.seal())
        adopt(opened)
    }

    /** Called once the biometric prompt has succeeded. */
    fun onUnlocked() = openVault()

    fun lock() {
        ticker?.cancel()
        ticker = null
        vault = null
        _state.update { it.copy(phase = Phase.LOCKED, accounts = emptyList(), query = "") }
    }

    fun enteredBackground() {
        leftForeground = System.currentTimeMillis()
    }

    /** Re-locks if the app was away longer than the user asked for. */
    fun enteredForeground() {
        val left = leftForeground ?: return
        leftForeground = null
        if (_state.value.phase != Phase.UNLOCKED || !lockPreferences.isLockEnabled) return

        val away = (System.currentTimeMillis() - left) / 1_000
        if (away >= lockPreferences.backgroundTimeoutSeconds) lock()
    }

    private fun openVault() = report("Could not open your vault") {
        val key = secrets.dataKey()
        if (key == null) {
            // The file is here but the key is gone: a restore onto another
            // device, or the Keystore was cleared. The ciphertext is useless
            // now, and saying so is better than an unexplained failure.
            _state.update {
                it.copy(
                    phase = Phase.NEEDS_SETUP,
                    message = Message(
                        "This vault cannot be opened",
                        "Its key was stored only on the device it was created on, and it is " +
                            "no longer there. Restore from an encrypted backup or a sync " +
                            "target to get your accounts back.",
                    ),
                )
            }
            return@report
        }
        val file = store.read()
        if (file == null) {
            _state.update { it.copy(phase = Phase.NEEDS_SETUP) }
            return@report
        }
        adopt(VaultHandle.open(key, file))
    }

    private fun adopt(opened: VaultHandle) {
        vault = opened
        lockPreferences.mirror(opened.lockConfig())
        _state.update {
            it.copy(phase = Phase.UNLOCKED, hasSyncKey = secrets.syncKey() != null)
        }
        refresh()
        startTicking()
    }

    /**
     * Recomputes the list once a second, so the codes and the countdown rings
     * stay right without every row owning a timer.
     */
    private fun startTicking() {
        ticker?.cancel()
        ticker = viewModelScope.launch {
            while (true) {
                delay(1_000)
                refresh()
            }
        }
    }

    private fun refresh() {
        val vault = vault ?: return
        val now = System.currentTimeMillis() / 1_000
        val query = _state.value.query.trim()
        val accounts = runCatching {
            if (query.isEmpty()) vault.accounts(now.toULong())
            else vault.search(query, now.toULong())
        }.getOrElse { emptyList() }
        _state.update { it.copy(accounts = accounts) }
    }

    fun onQueryChange(query: String) {
        _state.update { it.copy(query = query) }
        refresh()
    }

    // --- mutations -------------------------------------------------------

    /**
     * Runs a change and saves, or reports why it could not.
     *
     * Everything that writes goes through here: that is what guarantees a
     * change is never left only in memory.
     */
    private fun mutate(title: String, change: (VaultHandle) -> Unit) {
        val vault = vault ?: return
        report(title) {
            change(vault)
            store.write(vault.seal())
            lockPreferences.mirror(vault.lockConfig())
            refresh()
        }
    }

    private fun nowMs() = System.currentTimeMillis()

    /** Adds a scanned or pasted URI. Returns whether it was new. */
    fun add(uri: String): Boolean {
        val vault = vault ?: return false
        val existing = runCatching { vault.duplicateOfUri(uri) }.getOrNull()
        var ok = false
        mutate("Could not add that account") {
            it.addUri(uri, nowMs())
            ok = true
        }
        if (ok) show(if (existing != null) "You already had that account" else "Added")
        return ok && existing == null
    }

    fun add(draft: AccountDraft) {
        mutate("Could not add that account") { it.addManual(draft, nowMs()) }
        show("Added")
    }

    fun delete(id: String) = mutate("Could not delete that account") { it.delete(id, nowMs()) }

    fun setNote(id: String, note: String?) =
        mutate("Could not save the note") { it.setNote(id, note, nowMs()) }

    fun rename(id: String, issuer: String?, account: String) =
        mutate("Could not rename that account") { it.rename(id, issuer, account, nowMs()) }

    fun reorder(ids: List<String>) = mutate("Could not reorder") { it.reorder(ids, nowMs()) }

    fun copy(account: AccountView) {
        val seconds = vault?.preferences()?.clipboardClearSecs?.toInt() ?: 30
        clipboard.copy(account.code, seconds)
        show("Copied")
    }

    /**
     * The `otpauth://` URI for a QR code to move the account elsewhere.
     *
     * This contains the secret, which is why it is a separate, deliberate call
     * and not part of the list.
     */
    fun exportUri(id: String): String? {
        val vault = vault ?: return null
        return runCatching { vault.accountUri(id) }.getOrNull()
    }

    // --- settings --------------------------------------------------------

    fun lockConfig(): LockConfig? = vault?.lockConfig()
    fun preferences(): Preferences? = vault?.preferences()
    fun syncTargets(): List<SyncTargetView> = vault?.syncTargets() ?: emptyList()

    fun setLockConfig(config: LockConfig) =
        mutate("Could not save the lock settings") { it.setLockConfig(config, nowMs()) }

    fun setPreferences(preferences: Preferences) =
        mutate("Could not save your settings") { it.setPreferences(preferences, nowMs()) }

    fun setPin(pin: String) {
        mutate("Could not set the PIN") { it.setPin(pin, nowMs()) }
        show("PIN set")
    }

    fun clearPin() = mutate("Could not remove the PIN") { it.clearPin(nowMs()) }

    fun verifyPin(pin: String): Boolean = vault?.verifyPin(pin) ?: false

    fun upsertSyncTarget(
        target: SyncTargetView,
        token: String?,
        folderUri: Uri?,
    ) {
        val vault = vault ?: return
        report("Could not save that sync target") {
            val id = vault.upsertSyncTarget(target, nowMs())
            store.write(vault.seal())
            if (!token.isNullOrEmpty()) secrets.putToken(id, token)
            if (folderUri != null) folders.remember(id, folderUri)
            refresh()
        }
    }

    fun removeSyncTarget(id: String) {
        mutate("Could not remove that sync target") { it.removeSyncTarget(id, nowMs()) }
        secrets.deleteToken(id)
        folders.forget(id)
    }

    // --- backup ----------------------------------------------------------

    fun exportBackup(password: String): ByteArray? {
        val vault = vault ?: return null
        return try {
            vault.exportBackup(password)
        } catch (error: MfaException.Failed) {
            present("Could not export", error)
            null
        }
    }

    fun importBackup(file: ByteArray, password: String) {
        val vault = vault ?: return
        try {
            val summary = vault.importBackup(file, password)
            // Only write once the import succeeded: the core leaves the vault
            // untouched on a wrong password, and so should the file.
            store.write(vault.seal())
            refresh()
            show(
                if (summary.added == 0u) "Nothing new in that backup"
                else "Restored ${summary.added} account${plural(summary.added)}",
            )
        } catch (error: MfaException.Failed) {
            present("Could not import", error)
        }
    }

    // --- migration -------------------------------------------------------

    /** How far through a Google Authenticator export the scanned codes get. */
    fun migrationProgressOf(uris: List<String>) = runCatching { migrationProgress(uris) }

    fun importMigration(uris: List<String>) {
        val vault = vault ?: return
        try {
            val result = vault.importMigration(uris, nowMs())
            store.write(vault.seal())
            refresh()

            if (result.skipped.isEmpty()) {
                show("Imported ${result.summary.added} account${plural(result.summary.added)}")
            } else {
                // Never silent: a user told nothing will assume everything came
                // across and find out when they cannot log in.
                _state.update {
                    it.copy(
                        message = Message(
                            "Imported ${result.summary.added}, skipped ${result.skipped.size}",
                            result.skipped.joinToString("\n") { skipped ->
                                "${skipped.displayName} — ${skipped.reason}"
                            },
                        ),
                    )
                }
            }
        } catch (error: MfaException.Failed) {
            present("Could not import", error)
        }
    }

    // --- sync ------------------------------------------------------------

    fun syncNow() {
        val vault = vault ?: return
        val key = secrets.syncKey()
        if (key == null) {
            _state.update {
                it.copy(message = Message("Sync is not set up", "Add a sync target in Settings first."))
            }
            return
        }
        if (_state.value.isSyncing) return

        viewModelScope.launch {
            _state.update { it.copy(isSyncing = true) }
            val result = SyncCoordinator(getApplication(), secrets, vault, key).run()

            try {
                store.write(vault.seal())
            } catch (error: Exception) {
                _state.update {
                    it.copy(
                        isSyncing = false,
                        message = Message("Synced, but could not save locally", error.message.orEmpty()),
                    )
                }
                return@launch
            }
            refresh()
            _state.update { it.copy(isSyncing = false) }

            if (result.problems.isNotEmpty()) {
                _state.update {
                    it.copy(
                        message = Message(
                            "Sync had a problem",
                            result.problems.joinToString("\n") { (label, text) -> "$label: $text" },
                        ),
                    )
                }
            } else {
                show(summaryLine(result.summary))
            }
        }
    }

    /** Starts a new sync set on this device. */
    fun createSyncSet() = report("Could not set up sync") {
        secrets.putSyncKey(newSyncKey())
        _state.update { it.copy(hasSyncKey = true) }
        show("Sync set up on this device")
    }

    /** Publishes the wrapped key so another device can join. */
    fun publishKeyFile(password: String, onDone: (String?) -> Unit) {
        val vault = vault ?: return onDone("The vault is not open.")
        val key = secrets.syncKey() ?: return onDone("Sync is not set up on this device yet.")

        viewModelScope.launch {
            try {
                val wrapped = wrapSyncKey(key, password)
                SyncCoordinator(getApplication(), secrets, vault, key).publishKeyFile(wrapped)
                show("Key file published")
                onDone(null)
            } catch (error: MfaException.Failed) {
                onDone(error.displayMessage())
            } catch (error: Exception) {
                onDone(error.message ?: "Could not publish the key file.")
            }
        }
    }

    /** Joins an existing sync set using the key file on one of the targets. */
    fun joinSyncSet(password: String, onDone: (String?) -> Unit) {
        val vault = vault ?: return onDone("The vault is not open.")

        viewModelScope.launch {
            try {
                // Any key will do to build the providers; only the targets and
                // their tokens matter for reading the key file.
                val placeholder = secrets.syncKey() ?: ByteArray(32)
                val keyFile = SyncCoordinator(getApplication(), secrets, vault, placeholder)
                    .fetchKeyFile()
                if (keyFile == null) {
                    onDone("No key file was found. Publish one from the device that already syncs.")
                    return@launch
                }
                secrets.putSyncKey(unwrapSyncKey(keyFile, password))
                _state.update { it.copy(hasSyncKey = true) }
                show("This device has joined")
                onDone(null)
            } catch (error: MfaException.Failed) {
                onDone(error.displayMessage())
            } catch (error: Exception) {
                onDone(error.message ?: "Could not join.")
            }
        }
    }

    private fun summaryLine(summary: MergeSummary): String {
        if (!summary.changed) return "Already up to date"
        val parts = buildList {
            if (summary.added > 0u) add("${summary.added} added")
            if (summary.updated > 0u) add("${summary.updated} updated")
            if (summary.deleted > 0u) add("${summary.deleted} removed")
            if (summary.deduped > 0u) add("${summary.deduped} duplicate${plural(summary.deduped)} merged")
        }
        return if (parts.isEmpty()) "Synced" else "Synced: ${parts.joinToString(", ")}"
    }

    // --- reset -----------------------------------------------------------

    /**
     * Deletes everything on this device.
     *
     * Takes the keys out of the Keystore as well as the file: leaving them
     * behind would mean a recovered file could still be read.
     */
    fun resetEverything() {
        lock()
        store.deleteFile()
        secrets.deleteEverything()
        _state.update { it.copy(phase = Phase.NEEDS_SETUP, hasSyncKey = false) }
    }

    // --- reporting -------------------------------------------------------

    fun dismissMessage() = _state.update { it.copy(message = null) }

    private fun plural(count: UInt) = if (count == 1u) "" else "s"

    private fun show(text: String) {
        _state.update { it.copy(status = text) }
        statusReset?.cancel()
        statusReset = viewModelScope.launch {
            delay(3_000)
            _state.update { it.copy(status = null) }
        }
    }

    private fun present(title: String, error: MfaException.Failed) {
        _state.update { it.copy(message = Message(title, error.displayMessage())) }
    }

    /** Runs a block, turning any failure into something the user can read. */
    private inline fun report(title: String, block: () -> Unit) {
        try {
            block()
        } catch (error: MfaException.Failed) {
            present(title, error)
        } catch (error: Exception) {
            _state.update {
                it.copy(message = Message(title, error.message ?: "Something went wrong."))
            }
        }
    }
}
