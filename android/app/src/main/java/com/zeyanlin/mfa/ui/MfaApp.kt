package com.zeyanlin.mfa.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Fingerprint
import com.zeyanlin.mfa.platform.Biometrics

/** Where the app is. Simple enough not to need a navigation library. */
sealed interface Route {
    data object List : Route
    data object Add : Route
    data object Scan : Route
    data object Manual : Route
    data object Migration : Route
    data object Settings : Route
    data object Sync : Route
    data object Backup : Route
    data class ShowQr(val id: String) : Route
}

@Composable
fun MfaApp(
    model: AppViewModel,
    activity: FragmentActivity,
    takePendingUri: () -> String?,
) {
    val state by model.state.collectAsStateWithLifecycle()
    var route by remember { mutableStateOf<Route>(Route.List) }

    LaunchedEffect(Unit) { model.start() }

    // An otpauth:// link that arrived while locked waits until the vault is
    // open, rather than being dropped.
    LaunchedEffect(state.phase) {
        if (state.phase == AppViewModel.Phase.UNLOCKED) {
            takePendingUri()?.let { model.add(it) }
        }
    }

    state.message?.let { message ->
        AlertDialog(
            onDismissRequest = model::dismissMessage,
            title = { Text(message.title) },
            text = { Text(message.body) },
            confirmButton = { TextButton(onClick = model::dismissMessage) { Text("OK") } },
        )
    }

    when (state.phase) {
        AppViewModel.Phase.LOADING -> Centred { CircularProgressIndicator() }

        AppViewModel.Phase.NEEDS_SETUP -> SetupScreen(
            onStartFresh = model::createVault,
            onRestore = {
                model.createVault()
                route = Route.Backup
            },
        )

        AppViewModel.Phase.LOCKED -> LockScreen(model, activity)

        AppViewModel.Phase.UNLOCKED -> when (val current = route) {
            Route.List -> AccountListScreen(
                model = model,
                state = state,
                onAdd = { route = Route.Add },
                onSettings = { route = Route.Settings },
                onShowQr = { route = Route.ShowQr(it) },
            )

            Route.Add -> AddAccountScreen(
                model = model,
                onBack = { route = Route.List },
                onScan = { route = Route.Scan },
                onManual = { route = Route.Manual },
                onMigration = { route = Route.Migration },
            )

            Route.Scan -> ScannerScreen(
                onBack = { route = Route.Add },
                onFound = { uri ->
                    if (model.add(uri)) route = Route.List
                },
            )

            Route.Manual -> ManualEntryScreen(model) { route = Route.List }

            Route.Migration -> MigrationImportScreen(model) { route = Route.List }

            Route.Settings -> SettingsScreen(
                model = model,
                onBack = { route = Route.List },
                onSync = { route = Route.Sync },
                onBackup = { route = Route.Backup },
            )

            Route.Sync -> SyncSettingsScreen(model) { route = Route.Settings }

            Route.Backup -> BackupScreen(model) { route = Route.List }

            is Route.ShowQr -> ShowQrScreen(model, current.id) { route = Route.List }
        }
    }
}

@Composable
private fun Centred(content: @Composable () -> Unit) {
    Scaffold { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) { content() }
    }
}

/** First run, and the way back in after a reset. */
@Composable
fun SetupScreen(onStartFresh: () -> Unit, onRestore: () -> Unit) {
    Centred {
        Icon(
            painter = rememberVectorPainter(Icons.Default.Lock),
            contentDescription = null,
            modifier = Modifier.size(64.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Text("MFA", style = MaterialTheme.typography.headlineLarge,
             modifier = Modifier.padding(top = 16.dp))
        Text(
            "Your verification codes, encrypted on this device.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 32.dp, vertical = 8.dp),
        )
        Button(onClick = onStartFresh, modifier = Modifier.padding(top = 24.dp)) {
            Text("Start fresh")
        }
        OutlinedButton(onClick = onRestore, modifier = Modifier.padding(top = 8.dp)) {
            Text("Restore from a backup")
        }
    }
}

/**
 * The lock screen.
 *
 * The gate is the system's: fingerprint or face, falling back to the device
 * PIN, pattern or password. The vault's own PIN is not offered here — see
 * [Biometrics] for why.
 */
@Composable
fun LockScreen(model: AppViewModel, activity: FragmentActivity) {
    // Bumping this re-runs the prompt, which is how "try again" works without
    // a second code path.
    var attempt by remember { mutableIntStateOf(0) }
    var isWorking by remember { mutableStateOf(false) }
    var problem by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(attempt) {
        isWorking = true
        problem = null
        when (val outcome = Biometrics.authenticate(activity)) {
            Biometrics.Outcome.Succeeded -> model.onUnlocked()
            Biometrics.Outcome.Cancelled -> Unit
            is Biometrics.Outcome.Failed -> problem = outcome.message
        }
        isWorking = false
    }

    Centred {
        Icon(
            painter = rememberVectorPainter(Icons.Default.Fingerprint),
            contentDescription = null,
            modifier = Modifier.size(56.dp),
            tint = MaterialTheme.colorScheme.primary,
        )
        Text(
            "MFA is locked",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(vertical = 16.dp),
        )

        problem?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(horizontal = 32.dp, vertical = 8.dp),
            )
        }

        if (isWorking) {
            CircularProgressIndicator()
        } else {
            Button(onClick = { attempt++ }) { Text("Unlock") }
        }
    }
}
