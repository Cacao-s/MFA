package com.zeyanlin.mfa.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.zeyanlin.mfa.core.AccountView

/** The main screen: every account, its code, and how long that code has left. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountListScreen(
    model: AppViewModel,
    state: AppViewModel.UiState,
    onAdd: () -> Unit,
    onSettings: () -> Unit,
    onShowQr: (String) -> Unit,
) {
    var pendingDeletion by remember { mutableStateOf<AccountView?>(null) }
    var editing by remember { mutableStateOf<AccountView?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("MFA") },
                actions = {
                    IconButton(onClick = model::syncNow, enabled = state.hasSyncKey && !state.isSyncing) {
                        Icon(Icons.Default.Sync, contentDescription = "Sync")
                    }
                    IconButton(onClick = onSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                    IconButton(onClick = model::lock) {
                        Icon(Icons.Default.Lock, contentDescription = "Lock")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAdd) {
                Icon(Icons.Default.Add, contentDescription = "Add account")
            }
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            OutlinedTextField(
                value = state.query,
                onValueChange = model::onQueryChange,
                placeholder = { Text("Search") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            )

            if (state.accounts.isEmpty()) {
                EmptyState(hasQuery = state.query.isNotBlank(), onAdd = onAdd)
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(state.accounts, key = { it.id }) { account ->
                        AccountRow(
                            account = account,
                            onCopy = { model.copy(account) },
                            onEdit = { editing = account },
                            onShowQr = { onShowQr(account.id) },
                            onDelete = { pendingDeletion = account },
                        )
                        HorizontalDivider()
                    }
                }
            }

            AnimatedVisibility(visible = state.status != null || state.isSyncing) {
                Surface(tonalElevation = 2.dp, modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(12.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        if (state.isSyncing) {
                            CircularProgressIndicator(modifier = Modifier.size(14.dp))
                        }
                        Text(
                            state.status ?: "Syncing…",
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(start = if (state.isSyncing) 8.dp else 0.dp),
                        )
                    }
                }
            }
        }
    }

    pendingDeletion?.let { account ->
        AlertDialog(
            onDismissRequest = { pendingDeletion = null },
            title = { Text("Delete “${account.displayName}”?") },
            text = {
                Text(
                    "You will not be able to sign in to this account with MFA again unless " +
                        "you add it back. Check you can still get in another way first.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    model.delete(account.id)
                    pendingDeletion = null
                }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { pendingDeletion = null }) { Text("Cancel") }
            },
        )
    }

    editing?.let { account ->
        EditAccountDialog(
            account = account,
            onDismiss = { editing = null },
            onSave = { issuer, name, note ->
                model.rename(account.id, issuer, name)
                model.setNote(account.id, note)
                editing = null
            },
        )
    }
}

@Composable
private fun EmptyState(hasQuery: Boolean, onAdd: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            if (hasQuery) "Nothing matches" else "No accounts yet",
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            if (hasQuery) "Try a different search."
            else "Add your first account by scanning the QR code a website shows you.",
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = 8.dp),
        )
        if (!hasQuery) {
            TextButton(onClick = onAdd, modifier = Modifier.padding(top = 16.dp)) {
                Text("Add account")
            }
        }
    }
}

/** One account. Tapping the row copies, because that is what it is for. */
@Composable
private fun AccountRow(
    account: AccountView,
    onCopy: () -> Unit,
    onEdit: () -> Unit,
    onShowQr: () -> Unit,
    onDelete: () -> Unit,
) {
    var isMenuOpen by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onCopy)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                account.issuer ?: account.account,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
            )
            if (account.issuer != null && account.account.isNotEmpty()) {
                Text(
                    account.account,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                )
            }
            Text(
                grouped(account.code),
                style = MaterialTheme.typography.headlineSmall.copy(fontFamily = FontFamily.Monospace),
            )
        }

        CountdownRing(
            remaining = account.remainingSecs.toInt(),
            period = account.period.toInt(),
        )

        Box {
            IconButton(onClick = { isMenuOpen = true }) {
                Icon(Icons.Default.MoreVert, contentDescription = "More")
            }
            DropdownMenu(expanded = isMenuOpen, onDismissRequest = { isMenuOpen = false }) {
                DropdownMenuItem(text = { Text("Copy code") },
                                 onClick = { isMenuOpen = false; onCopy() })
                DropdownMenuItem(text = { Text("Edit…") },
                                 onClick = { isMenuOpen = false; onEdit() })
                DropdownMenuItem(text = { Text("Show QR code…") },
                                 onClick = { isMenuOpen = false; onShowQr() })
                DropdownMenuItem(text = { Text("Delete…") },
                                 onClick = { isMenuOpen = false; onDelete() })
            }
        }
    }
}

/**
 * The ring that empties as the code expires.
 *
 * Driven by the seconds the core reports rather than by its own clock, so it
 * cannot drift away from the code it is describing. It turns amber near the
 * end, because the useful question is "do I have time to type this?" and a
 * colour answers it faster than a number.
 */
@Composable
private fun CountdownRing(remaining: Int, period: Int) {
    val fraction = if (period > 0) remaining.toFloat() / period else 0f
    val isRunningOut = remaining <= 5
    val colour = if (isRunningOut) MaterialTheme.colorScheme.error
                 else MaterialTheme.colorScheme.primary
    val track = MaterialTheme.colorScheme.surfaceVariant

    Box(
        modifier = Modifier.size(34.dp).drawBehind {
            val stroke = 3.dp.toPx()
            val inset = stroke / 2
            val box = Size(size.width - stroke, size.height - stroke)

            drawArc(
                color = track,
                startAngle = 0f, sweepAngle = 360f, useCenter = false,
                topLeft = androidx.compose.ui.geometry.Offset(inset, inset),
                size = box,
                style = Stroke(width = stroke),
            )
            drawArc(
                color = colour,
                startAngle = -90f, sweepAngle = 360f * fraction, useCenter = false,
                topLeft = androidx.compose.ui.geometry.Offset(inset, inset),
                size = box,
                style = Stroke(width = stroke, cap = StrokeCap.Round),
            )
        },
        contentAlignment = Alignment.Center,
    ) {
        Text(
            "$remaining",
            style = MaterialTheme.typography.labelSmall,
            color = colour,
        )
    }
}

/** `123 456`, which is how people read a code aloud while typing it. */
private fun grouped(code: String): String =
    if (code.length % 2 != 0) code
    else "${code.take(code.length / 2)} ${code.drop(code.length / 2)}"
