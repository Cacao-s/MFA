package com.zeyanlin.mfa.ui

import android.Manifest
import android.content.pm.PackageManager
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.zeyanlin.mfa.core.AccountDraft
import com.zeyanlin.mfa.core.AccountView
import com.zeyanlin.mfa.core.MigrationProgress
import com.zeyanlin.mfa.platform.QrAnalyzer
import java.util.concurrent.Executors

/** The ways an account can get in (spec §1). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddAccountScreen(
    model: AppViewModel,
    onBack: () -> Unit,
    onScan: () -> Unit,
    onManual: () -> Unit,
    onMigration: () -> Unit,
) {
    var pasted by remember { mutableStateOf("") }

    Scaffold(topBar = { TopAppBar(title = { Text("Add account") }, navigationIcon = { BackButton(onBack) }) }) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            ListItem(
                headlineContent = { Text("Scan a QR code") },
                modifier = Modifier.clickableRow(onScan),
            )
            ListItem(
                headlineContent = { Text("Enter a key by hand") },
                modifier = Modifier.clickableRow(onManual),
            )
            ListItem(
                headlineContent = { Text("Import from Google Authenticator") },
                supportingContent = {
                    Text("Authy cannot be imported: it has no export.")
                },
                modifier = Modifier.clickableRow(onMigration),
            )

            OutlinedTextField(
                value = pasted,
                onValueChange = { pasted = it },
                label = { Text("Or paste a setup link") },
                placeholder = { Text("otpauth://totp/…") },
                modifier = Modifier.fillMaxWidth().padding(16.dp),
            )
            Button(
                onClick = { if (model.add(pasted.trim())) onBack() },
                enabled = pasted.isNotBlank(),
                modifier = Modifier.padding(horizontal = 16.dp),
            ) { Text("Add from link") }
        }
    }
}

/** The camera scanner. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScannerScreen(onBack: () -> Unit, onFound: (String) -> Unit) {
    val context = LocalContext.current
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val request = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> hasPermission = granted }

    LaunchedEffect(Unit) {
        if (!hasPermission) request.launch(Manifest.permission.CAMERA)
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Scan") }, navigationIcon = { BackButton(onBack) }) }) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (hasPermission) {
                CameraPreview(onFound = onFound, modifier = Modifier.fillMaxSize())
            } else {
                Text(
                    "MFA needs the camera to read a QR code. Allow it, or paste the setup " +
                        "link instead.",
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(32.dp),
                )
            }
        }
    }
}

/**
 * CameraX preview with the QR analyser attached.
 *
 * `STRATEGY_KEEP_ONLY_LATEST` on purpose: a backlog of frames would make the
 * decode lag behind what the user is pointing at.
 */
@Composable
private fun CameraPreview(onFound: (String) -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    var lastFound by remember { mutableStateOf<String?>(null) }

    DisposableEffect(Unit) { onDispose { executor.shutdown() } }

    AndroidView(
        modifier = modifier,
        factory = { viewContext ->
            val previewView = PreviewView(viewContext)
            val providerFuture = ProcessCameraProvider.getInstance(viewContext)

            providerFuture.addListener({
                val provider = providerFuture.get()

                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }
                val analysis = ImageAnalysis.Builder()
                    .setTargetResolution(Size(1280, 720))
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                    .also { it.setAnalyzer(executor, QrAnalyzer { payload ->
                        // The camera reports the same code many times a
                        // second; act on it once.
                        if (payload != lastFound) {
                            lastFound = payload
                            onFound(payload)
                        }
                    }) }

                provider.unbindAll()
                provider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
            }, ContextCompat.getMainExecutor(viewContext))

            previewView
        },
    )
}

/** Typing a key in by hand, for sites that print the secret. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ManualEntryScreen(model: AppViewModel, onAdded: () -> Unit) {
    var issuer by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var algorithm by remember { mutableStateOf("SHA1") }
    var digits by remember { mutableStateOf(6) }
    var period by remember { mutableStateOf(30) }

    Scaffold(topBar = { TopAppBar(title = { Text("Enter a key") }, navigationIcon = { BackButton(onAdded) }) }) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(issuer, { issuer = it }, label = { Text("Service") },
                              placeholder = { Text("GitHub") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(account, { account = it }, label = { Text("Account") },
                              placeholder = { Text("you@example.com") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(secret, { secret = it }, label = { Text("Setup key") },
                              placeholder = { Text("JBSW Y3DP EHPK 3PXP") },
                              supportingText = { Text("Spaces and capitals do not matter.") },
                              modifier = Modifier.fillMaxWidth())

            Text("Advanced", style = MaterialTheme.typography.labelLarge)
            Text(
                "Almost every site uses SHA1, 6 digits and 30 seconds. Only change these " +
                    "if the site told you to.",
                style = MaterialTheme.typography.bodySmall,
            )
            Choice("Algorithm", listOf("SHA1", "SHA256", "SHA512"), algorithm) { algorithm = it }
            Choice("Digits", listOf(6, 7, 8), digits) { digits = it }
            Choice("Changes every", listOf(30, 60), period) { period = it }

            Button(
                onClick = {
                    model.add(
                        AccountDraft(
                            issuer = issuer.ifBlank { null },
                            account = account,
                            secret = secret,
                            algorithm = algorithm,
                            digits = digits.toUByte(),
                            period = period.toUInt(),
                        ),
                    )
                    onAdded()
                },
                enabled = secret.isNotBlank() && (issuer.isNotBlank() || account.isNotBlank()),
            ) { Text("Add") }
        }
    }
}

/** A row of options, which is less machinery than a dropdown for three items. */
@Composable
private fun <T> Choice(label: String, options: List<T>, selected: T, onSelect: (T) -> Unit) {
    Column {
        Text(label, style = MaterialTheme.typography.bodySmall)
        androidx.compose.foundation.layout.Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            options.forEach { option ->
                TextButton(onClick = { onSelect(option) }) {
                    Text(
                        option.toString(),
                        color = if (option == selected) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

/**
 * Importing a Google Authenticator export.
 *
 * A large export is split over several QR codes, and the whole set has to be
 * scanned before anything is imported — a partial import that looks finished
 * is the failure worth designing against here.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MigrationImportScreen(model: AppViewModel, onFinished: () -> Unit) {
    var scanned by remember { mutableStateOf(listOf<String>()) }
    var progress by remember { mutableStateOf<MigrationProgress?>(null) }
    var problem by remember { mutableStateOf<String?>(null) }

    fun add(uri: String) {
        if (!uri.lowercase().startsWith("otpauth-migration://")) {
            problem = "That is a normal QR code, not an export. Add it from the previous screen."
            return
        }
        if (uri in scanned) return

        val candidate = scanned + uri
        // Ask the core: it rejects codes from a different export, which would
        // otherwise silently lose accounts.
        model.migrationProgressOf(candidate)
            .onSuccess {
                progress = it
                scanned = candidate
                problem = null
            }
            .onFailure { problem = it.message }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Import") },
                navigationIcon = { BackButton(onFinished) },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            CameraPreview(onFound = ::add, modifier = Modifier.fillMaxWidth().height(360.dp))

            Column(modifier = Modifier.padding(horizontal = 16.dp)) {
                val current = progress
                if (current == null) {
                    Text("In Google Authenticator, choose Transfer accounts → Export.")
                } else {
                    Text(
                        "Scanned ${current.scanned} of ${current.expected}",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    if (!current.complete) {
                        val next = current.missing.firstOrNull()?.plus(1)
                        Text(next?.let { "Scan code $it next." } ?: "Keep scanning.")
                    }
                }
                problem?.let {
                    Text(it, color = MaterialTheme.colorScheme.error,
                         style = MaterialTheme.typography.bodySmall)
                }

                Button(
                    onClick = {
                        model.importMigration(scanned)
                        onFinished()
                    },
                    enabled = progress?.complete == true,
                    modifier = Modifier.padding(top = 12.dp),
                ) { Text("Import") }
            }
        }
    }
}

/**
 * Renaming an account and giving it a note.
 *
 * The secret is deliberately not editable: a typo there turns a working account
 * into one that produces plausible-looking wrong codes, which is far harder to
 * diagnose than a missing account. Re-add it instead.
 */
@Composable
fun EditAccountDialog(
    account: AccountView,
    onDismiss: () -> Unit,
    onSave: (issuer: String?, account: String, note: String?) -> Unit,
) {
    var issuer by remember { mutableStateOf(account.issuer.orEmpty()) }
    var name by remember { mutableStateOf(account.account) }
    var note by remember { mutableStateOf(account.note.orEmpty()) }

    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Edit") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(issuer, { issuer = it }, label = { Text("Service") })
                OutlinedTextField(name, { name = it }, label = { Text("Account") })
                OutlinedTextField(note, { note = it }, label = { Text("Note") },
                                  supportingText = { Text("Notes are searchable.") })
                Text(
                    "${account.algorithm}, ${account.digits} digits, every ${account.period}s — " +
                        "these came from the site and cannot be changed.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onSave(issuer.ifBlank { null }, name, note.ifBlank { null })
            }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
internal fun BackButton(onBack: () -> Unit) {
    IconButton(onClick = onBack) {
        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
    }
}

internal fun Modifier.clickableRow(onClick: () -> Unit): Modifier =
    this.clickable(onClick = onClick)
