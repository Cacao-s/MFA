package com.zeyanlin.mfa.ui

import android.graphics.Bitmap
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.zeyanlin.mfa.core.LockConfig
import com.zeyanlin.mfa.core.Preferences
import com.zeyanlin.mfa.core.SortMode
import com.zeyanlin.mfa.core.SyncKind
import com.zeyanlin.mfa.core.SyncTargetView
import com.zeyanlin.mfa.core.libraryVersion

/** Settings. Everything here lives in the vault, so it travels to the other devices. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    model: AppViewModel,
    onBack: () -> Unit,
    onSync: () -> Unit,
    onBackup: () -> Unit,
) {
    var lock by remember { mutableStateOf(model.lockConfig()) }
    var preferences by remember { mutableStateOf(model.preferences()) }
    var isSettingPin by remember { mutableStateOf(false) }
    var isConfirmingReset by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        lock = model.lockConfig()
        preferences = model.preferences()
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Settings") }, navigationIcon = { BackButton(onBack) }) }) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()),
        ) {
            lock?.let { current ->
                ListItem(
                    headlineContent = { Text("Lock MFA") },
                    supportingContent = {
                        Text("Your fingerprint or face, falling back to your device PIN.")
                    },
                    trailingContent = {
                        Switch(
                            checked = current.biometricEnabled,
                            onCheckedChange = {
                                val updated = current.copy(biometricEnabled = it)
                                lock = updated
                                model.setLockConfig(updated)
                            },
                        )
                    },
                )

                if (current.biometricEnabled) {
                    SecondsChoice(
                        label = "Lock after",
                        options = listOf(0, 30, 60, 300),
                        selected = current.backgroundTimeoutSecs.toInt(),
                    ) { seconds ->
                        val updated = current.copy(backgroundTimeoutSecs = seconds.toUInt())
                        lock = updated
                        model.setLockConfig(updated)
                    }
                }

                HorizontalDivider()
                ListItem(
                    headlineContent = { Text(if (current.hasPin) "Change PIN…" else "Set a PIN…") },
                    supportingContent = {
                        Text(
                            "Asked for before revealing a secret key or exporting a backup. " +
                                "It is not what unlocks the app.",
                        )
                    },
                    modifier = Modifier.clickableRow { isSettingPin = true },
                )
                if (current.hasPin) {
                    ListItem(
                        headlineContent = { Text("Remove PIN") },
                        modifier = Modifier.clickableRow {
                            model.clearPin()
                            lock = model.lockConfig()
                        },
                    )
                }
            }

            HorizontalDivider()

            preferences?.let { current ->
                SecondsChoice(
                    label = "Clear the clipboard after",
                    options = listOf(15, 30, 60),
                    selected = current.clipboardClearSecs.toInt(),
                ) { seconds ->
                    val updated = current.copy(clipboardClearSecs = seconds.toUInt())
                    preferences = updated
                    model.setPreferences(updated)
                }
                ListItem(
                    headlineContent = { Text("Order") },
                    supportingContent = {
                        Text(if (current.sort == SortMode.MANUAL) "As I arranged them"
                             else "By service name")
                    },
                    modifier = Modifier.clickableRow {
                        val updated = current.copy(
                            sort = if (current.sort == SortMode.MANUAL) SortMode.ISSUER_ASC
                                   else SortMode.MANUAL,
                        )
                        preferences = updated
                        model.setPreferences(updated)
                    },
                )
            }

            HorizontalDivider()
            ListItem(headlineContent = { Text("Sync") }, modifier = Modifier.clickableRow(onSync))
            ListItem(headlineContent = { Text("Backup") }, modifier = Modifier.clickableRow(onBackup))

            HorizontalDivider()
            ListItem(
                headlineContent = { Text("Delete everything on this device…") },
                supportingContent = { Text("MFA ${libraryVersion()}") },
                modifier = Modifier.clickableRow { isConfirmingReset = true },
            )
        }
    }

    if (isSettingPin) {
        PinDialog(
            onDismiss = { isSettingPin = false },
            onSet = { pin ->
                model.setPin(pin)
                lock = model.lockConfig()
                isSettingPin = false
            },
        )
    }

    if (isConfirmingReset) {
        AlertDialog(
            onDismissRequest = { isConfirmingReset = false },
            title = { Text("Delete everything on this device?") },
            text = {
                Text(
                    "Your accounts will be gone from this device and cannot be recovered " +
                        "from it. Make sure you have a backup, or that another device has them.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    model.resetEverything()
                    isConfirmingReset = false
                }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { isConfirmingReset = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun SecondsChoice(
    label: String,
    options: List<Int>,
    selected: Int,
    onSelect: (Int) -> Unit,
) {
    ListItem(
        headlineContent = { Text(label) },
        supportingContent = {
            androidx.compose.foundation.layout.Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                options.forEach { seconds ->
                    TextButton(onClick = { onSelect(seconds) }) {
                        Text(
                            if (seconds == 0) "Immediately" else "${seconds}s",
                            color = if (seconds == selected) MaterialTheme.colorScheme.primary
                                    else MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        },
    )
}

@Composable
private fun PinDialog(onDismiss: () -> Unit, onSet: (String) -> Unit) {
    var pin by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    val problem = when {
        pin.length < 4 -> "At least 4 digits."
        again.isNotEmpty() && pin != again -> "The two do not match."
        else -> null
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Set a PIN") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(pin, { pin = it }, label = { Text("PIN") },
                                  visualTransformation = PasswordVisualTransformation())
                OutlinedTextField(again, { again = it }, label = { Text("PIN again") },
                                  visualTransformation = PasswordVisualTransformation())
                problem?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(onClick = { onSet(pin) }, enabled = problem == null && pin == again) {
                Text("Save")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Sync targets (spec §3). Several can be on at once. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncSettingsScreen(model: AppViewModel, onBack: () -> Unit) {
    val state by model.state.collectAsState()
    var targets by remember { mutableStateOf(model.syncTargets()) }
    var editing by remember { mutableStateOf<SyncTargetView?>(null) }
    var isAdding by remember { mutableStateOf(false) }
    var passwordPrompt by remember { mutableStateOf<PasswordPurpose?>(null) }

    Scaffold(topBar = { TopAppBar(title = { Text("Sync") }, navigationIcon = { BackButton(onBack) }) }) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()),
        ) {
            if (!state.hasSyncKey) {
                ListItem(
                    headlineContent = { Text("Start syncing from this device") },
                    supportingContent = {
                        Text(
                            "One of your devices starts the sync set; the others join it with " +
                                "your backup password.",
                        )
                    },
                    modifier = Modifier.clickableRow(model::createSyncSet),
                )
                ListItem(
                    headlineContent = { Text("Join a sync set already running") },
                    modifier = Modifier.clickableRow { passwordPrompt = PasswordPurpose.JOIN },
                )
                HorizontalDivider()
            }

            targets.forEach { target ->
                ListItem(
                    headlineContent = { Text(target.label) },
                    supportingContent = { Text("${describe(target.kind)} — ${target.location}") },
                    trailingContent = { if (!target.enabled) Text("Off") },
                    modifier = Modifier.clickableRow { editing = target },
                )
            }
            ListItem(
                headlineContent = { Text("Add a target…") },
                modifier = Modifier.clickableRow { isAdding = true },
            )

            Text(
                "Your accounts are encrypted before they leave this device, so none of these " +
                    "can read them. Tokens and folder choices stay on this device and are not " +
                    "synced.",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(16.dp),
            )

            if (state.hasSyncKey && targets.isNotEmpty()) {
                HorizontalDivider()
                ListItem(
                    headlineContent = { Text("Sync now") },
                    modifier = Modifier.clickableRow(model::syncNow),
                )
                ListItem(
                    headlineContent = { Text("Publish the key file for a new device…") },
                    supportingContent = {
                        Text("Encrypted with your backup password, so publishing it is safe.")
                    },
                    modifier = Modifier.clickableRow { passwordPrompt = PasswordPurpose.PUBLISH },
                )
            }
        }
    }

    if (isAdding || editing != null) {
        SyncTargetDialog(
            model = model,
            target = editing,
            onDismiss = {
                isAdding = false
                editing = null
                targets = model.syncTargets()
            },
        )
    }

    passwordPrompt?.let { purpose ->
        SyncPasswordDialog(
            purpose = purpose,
            model = model,
            onDismiss = { passwordPrompt = null },
        )
    }
}

private enum class PasswordPurpose { JOIN, PUBLISH }

private fun describe(kind: SyncKind) = when (kind) {
    SyncKind.FOLDER -> "Folder"
    SyncKind.GIT_HUB -> "GitHub"
    SyncKind.GIT_LAB -> "GitLab"
    SyncKind.SERVER -> "Server"
}

@Composable
private fun SyncTargetDialog(
    model: AppViewModel,
    target: SyncTargetView?,
    onDismiss: () -> Unit,
) {
    var kind by remember { mutableStateOf(target?.kind ?: SyncKind.SERVER) }
    var label by remember { mutableStateOf(target?.label.orEmpty()) }
    var location by remember { mutableStateOf(target?.location.orEmpty()) }
    var token by remember { mutableStateOf("") }
    var enabled by remember { mutableStateOf(target?.enabled ?: true) }
    var folderUri by remember { mutableStateOf<Uri?>(null) }

    val pickFolder = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree(),
    ) { uri ->
        if (uri != null) {
            folderUri = uri
            location = uri.lastPathSegment ?: "folder"
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (target == null) "Add a target" else target.label) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (target == null) {
                    androidx.compose.foundation.layout.Row(
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        SyncKind.entries.forEach { option ->
                            TextButton(onClick = { kind = option }) {
                                Text(
                                    describe(option),
                                    color = if (option == kind) MaterialTheme.colorScheme.primary
                                            else MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }

                OutlinedTextField(label, { label = it }, label = { Text("Name") })

                when (kind) {
                    SyncKind.FOLDER -> Button(onClick = { pickFolder.launch(null) }) {
                        Text(folderUri?.lastPathSegment ?: "Choose a folder…")
                    }
                    SyncKind.GIT_HUB -> {
                        OutlinedTextField(location, { location = it },
                                          label = { Text("Repository") },
                                          placeholder = { Text("owner/repo/branch") })
                        OutlinedTextField(token, { token = it }, label = { Text("Token") },
                                          visualTransformation = PasswordVisualTransformation(),
                                          supportingText = { Text("Needs contents: write.") })
                    }
                    SyncKind.GIT_LAB -> {
                        OutlinedTextField(location, { location = it },
                                          label = { Text("Project id") },
                                          placeholder = { Text("12345678/main") })
                        OutlinedTextField(token, { token = it }, label = { Text("Token") },
                                          visualTransformation = PasswordVisualTransformation(),
                                          supportingText = { Text("Needs the api scope.") })
                    }
                    SyncKind.SERVER -> {
                        OutlinedTextField(location, { location = it },
                                          label = { Text("Address") },
                                          placeholder = { Text("https://mfa.example.com") })
                        OutlinedTextField(token, { token = it }, label = { Text("Token") },
                                          visualTransformation = PasswordVisualTransformation(),
                                          supportingText = { Text("The MFA_SYNC_TOKEN the server uses.") })
                    }
                }

                androidx.compose.foundation.layout.Row(
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                ) {
                    Switch(checked = enabled, onCheckedChange = { enabled = it })
                    Text("Use this target", modifier = Modifier.padding(start = 8.dp))
                }

                Text(
                    "Tokens are kept in this device's keystore, not in the vault.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                model.upsertSyncTarget(
                    SyncTargetView(
                        id = target?.id.orEmpty(),
                        kind = kind,
                        label = label.ifBlank { describe(kind) },
                        location = location,
                        enabled = enabled,
                    ),
                    token = token.ifBlank { null },
                    folderUri = folderUri,
                )
                onDismiss()
            }) { Text("Save") }
        },
        dismissButton = {
            androidx.compose.foundation.layout.Row {
                if (target != null) {
                    TextButton(onClick = {
                        model.removeSyncTarget(target.id)
                        onDismiss()
                    }) { Text("Remove") }
                }
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        },
    )
}

@Composable
private fun SyncPasswordDialog(
    purpose: PasswordPurpose,
    model: AppViewModel,
    onDismiss: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<String?>(null) }
    var isWorking by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(if (purpose == PasswordPurpose.JOIN) "Join a sync set" else "Publish the key file")
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(password, { password = it },
                                  label = { Text("Backup password") },
                                  visualTransformation = PasswordVisualTransformation())
                Text(
                    if (purpose == PasswordPurpose.JOIN)
                        "The same password you use for encrypted backups."
                    else
                        "Choose a long one: this single password protects your backups and " +
                            "the key file on every sync target.",
                    style = MaterialTheme.typography.bodySmall,
                )
                problem?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(
                enabled = password.length >= 8 && !isWorking,
                onClick = {
                    isWorking = true
                    val done = { failure: String? ->
                        isWorking = false
                        if (failure == null) onDismiss() else problem = failure
                    }
                    if (purpose == PasswordPurpose.JOIN) model.joinSyncSet(password, done)
                    else model.publishKeyFile(password, done)
                },
            ) { Text(if (purpose == PasswordPurpose.JOIN) "Join" else "Publish") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Encrypted backup export and import (spec §1, §5). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupScreen(model: AppViewModel, onBack: () -> Unit) {
    val context = LocalContext.current
    var exportPassword by remember { mutableStateOf("") }
    var exportAgain by remember { mutableStateOf("") }
    var importPassword by remember { mutableStateOf("") }
    var picked by remember { mutableStateOf<ByteArray?>(null) }
    var pending by remember { mutableStateOf<ByteArray?>(null) }

    val save = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        val bytes = pending
        pending = null
        if (uri != null && bytes != null) {
            context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
        }
    }

    val open = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            picked = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Backup") }, navigationIcon = { BackButton(onBack) }) }) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Export", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(exportPassword, { exportPassword = it },
                              label = { Text("Backup password") },
                              visualTransformation = PasswordVisualTransformation(),
                              modifier = Modifier.fillMaxWidth())
            OutlinedTextField(exportAgain, { exportAgain = it },
                              label = { Text("Password again") },
                              visualTransformation = PasswordVisualTransformation(),
                              modifier = Modifier.fillMaxWidth())
            Text(
                "At least 8 characters, and worth making longer: this one password protects " +
                    "the backup file wherever it ends up, and the key file on every sync " +
                    "target. MFA cannot recover it for you.",
                style = MaterialTheme.typography.bodySmall,
            )
            Button(
                enabled = exportPassword.length >= 8 && exportPassword == exportAgain,
                onClick = {
                    model.exportBackup(exportPassword)?.let { bytes ->
                        pending = bytes
                        save.launch("mfa-backup.mfabackup")
                    }
                },
            ) { Text("Export…") }

            HorizontalDivider()

            Text("Import", style = MaterialTheme.typography.titleMedium)
            Button(onClick = { open.launch(arrayOf("*/*")) }) {
                Text(if (picked == null) "Choose a backup file…" else "Choose a different file…")
            }
            if (picked != null) {
                OutlinedTextField(importPassword, { importPassword = it },
                                  label = { Text("Backup password") },
                                  visualTransformation = PasswordVisualTransformation(),
                                  modifier = Modifier.fillMaxWidth())
                Button(
                    enabled = importPassword.isNotEmpty(),
                    onClick = {
                        picked?.let { model.importBackup(it, importPassword) }
                        onBack()
                    },
                ) { Text("Import") }
            }
            Text(
                "Importing merges: accounts already on this device are kept, and a wrong " +
                    "password changes nothing.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

/**
 * Shows an account as a QR code, for moving it to another authenticator.
 *
 * **This puts the secret on screen**, so it is behind a deliberate tap and it
 * says so.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShowQrScreen(model: AppViewModel, id: String, onBack: () -> Unit) {
    var bitmap by remember { mutableStateOf<Bitmap?>(null) }

    Scaffold(topBar = { TopAppBar(title = { Text("Move this account") }, navigationIcon = { BackButton(onBack) }) }) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally,
        ) {
            bitmap?.let { image ->
                Image(
                    bitmap = image.asImageBitmap(),
                    contentDescription = "QR code for this account",
                    modifier = Modifier.fillMaxWidth().aspectRatio(1f),
                    // Nearest-neighbour: a blurred QR code is an unreadable one.
                    filterQuality = androidx.compose.ui.graphics.FilterQuality.None,
                )
            }

            Text(
                "This QR code contains the secret key for this account. Anyone who " +
                    "photographs it can generate your codes. Make sure nobody is looking.",
                style = MaterialTheme.typography.bodySmall,
            )

            Button(onClick = {
                bitmap = if (bitmap != null) null
                         else model.exportUri(id)?.let(::encodeQr)
            }) {
                Text(if (bitmap == null) "Show the code" else "Hide")
            }
        }
    }
}

/** Renders a payload as a QR bitmap, with ZXing. */
private fun encodeQr(payload: String): Bitmap {
    val size = 512
    val matrix = QRCodeWriter().encode(
        payload,
        BarcodeFormat.QR_CODE,
        size,
        size,
        mapOf(
            // Medium: enough redundancy for a camera to read off a screen
            // without making the modules too small to resolve.
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to 1,
        ),
    )

    return Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888).apply {
        for (x in 0 until size) {
            for (y in 0 until size) {
                setPixel(x, y, if (matrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
            }
        }
    }
}
