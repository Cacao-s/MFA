import SwiftUI

/// Sync targets (spec §3). Several can be on at once.
struct SyncSettingsView: View {
    @EnvironmentObject private var model: AppModel

    @State private var targets: [SyncTargetView] = []
    @State private var editing: SyncTargetView?
    @State private var isAdding = false
    @State private var isJoining = false
    @State private var isPublishing = false

    var body: some View {
        Form {
            if !model.hasSyncKey {
                Section {
                    Button("Start syncing from this device") { model.createSyncSet() }
                    Button("Join a sync set already running") { isJoining = true }
                } header: {
                    Text("Set up")
                } footer: {
                    Text("""
                    One of your devices starts the sync set; the others join it with \
                    your backup password. Every target shares one key, so you can move \
                    between them or use several at once without setting it up again.
                    """)
                }
            }

            Section {
                ForEach(targets, id: \.id) { target in
                    Button {
                        editing = target
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(target.label)
                                Text(describe(target))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            if !target.enabled {
                                Text("Off").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                }
                Button("Add a target…") { isAdding = true }
            } header: {
                Text("Targets")
            } footer: {
                Text("""
                Your accounts are encrypted before they leave this device, so none of \
                these can read them. Tokens and folder choices stay on this device and \
                are not synced.
                """)
            }

            if model.hasSyncKey, !targets.isEmpty {
                Section {
                    Button("Sync now") { Task { await model.syncNow() } }
                        .disabled(model.isSyncing)
                    Button("Publish the key file for a new device…") { isPublishing = true }
                } footer: {
                    Text("""
                    The key file lets another device join. It is encrypted with your \
                    backup password, so publishing it is safe as long as that password is.
                    """)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Sync")
        .onAppear { targets = model.syncTargets() }
        .sheet(isPresented: $isAdding) {
            SyncTargetEditor(target: nil) { targets = model.syncTargets() }
        }
        .sheet(item: $editing) { target in
            SyncTargetEditor(target: target) { targets = model.syncTargets() }
        }
        .sheet(isPresented: $isJoining) { JoinSyncSetView() }
        .sheet(isPresented: $isPublishing) { PublishKeyFileView() }
    }

    private func describe(_ target: SyncTargetView) -> String {
        switch target.kind {
        case .folder: "Folder — \(target.location)"
        case .gitHub: "GitHub — \(target.location)"
        case .gitLab: "GitLab — \(target.location)"
        case .server: "Server — \(target.location)"
        }
    }
}

extension SyncTargetView: Identifiable {}

/// Adding or changing one target.
struct SyncTargetEditor: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let target: SyncTargetView?
    let onChange: () -> Void

    @State private var kind: SyncKind = .server
    @State private var label = ""
    @State private var location = ""
    @State private var token = ""
    @State private var enabled = true
    @State private var folderURL: URL?
    @State private var isPickingFolder = false

    var body: some View {
        NavigationStack {
            Form {
                Picker("Kind", selection: $kind) {
                    Text("Folder (iCloud Drive, Google Drive, OneDrive)").tag(SyncKind.folder)
                    Text("GitHub").tag(SyncKind.gitHub)
                    Text("GitLab").tag(SyncKind.gitLab)
                    Text("Self-hosted server").tag(SyncKind.server)
                }
                .disabled(target != nil)

                TextField("Name", text: $label, prompt: Text(defaultLabel))

                switch kind {
                case .folder:
                    Button(folderURL?.lastPathComponent ?? "Choose a folder…") {
                        isPickingFolder = true
                    }
                case .gitHub:
                    field("Repository", $location, "owner/repo/branch")
                    secret("Personal access token", help: "Needs the `repo` scope, or `contents: write` on a fine-grained token.")
                case .gitLab:
                    field("Project id", $location, "12345678/main")
                    secret("Personal access token", help: "Needs the `api` scope.")
                case .server:
                    field("Address", $location, "https://mfa.example.com")
                    secret("Token", help: "The MFA_SYNC_TOKEN the server was started with.")
                }

                Toggle("Use this target", isOn: $enabled)

                if target != nil {
                    Section {
                        Button("Remove this target", role: .destructive) {
                            if let target { model.removeSyncTarget(id: target.id) }
                            onChange()
                            dismiss()
                        }
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(target == nil ? "Add a target" : "Target")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save).disabled(!canSave)
                }
            }
            .onAppear(perform: load)
            .fileImporter(isPresented: $isPickingFolder,
                          allowedContentTypes: [.folder]) { result in
                if case let .success(url) = result {
                    folderURL = url
                    location = url.lastPathComponent
                }
            }
        }
    }

    private var defaultLabel: String {
        switch kind {
        case .folder: "iCloud Drive"
        case .gitHub: "GitHub"
        case .gitLab: "GitLab"
        case .server: "My server"
        }
    }

    private var canSave: Bool {
        switch kind {
        case .folder: folderURL != nil || target != nil
        default: !location.trimmingCharacters(in: .whitespaces).isEmpty
            && (!token.isEmpty || target != nil)
        }
    }

    private func field(_ title: String, _ value: Binding<String>, _ prompt: String) -> some View {
        TextField(title, text: value, prompt: Text(prompt))
            #if os(iOS)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            #endif
    }

    private func secret(_ title: String, help: String) -> some View {
        Section {
            SecureField(title, text: $token)
        } footer: {
            Text("\(help) It is kept in this device's keychain, not in the vault.")
        }
    }

    private func load() {
        guard let target else { return }
        kind = target.kind
        label = target.label
        location = target.location
        enabled = target.enabled
        if target.kind == .folder { folderURL = FolderBookmarks.resolve(targetID: target.id) }
    }

    private func save() {
        let resolved = SyncTargetView(
            id: target?.id ?? "",
            kind: kind,
            label: label.isEmpty ? defaultLabel : label,
            location: location,
            enabled: enabled
        )
        guard let id = model.upsertSyncTarget(resolved) else { return }

        if kind == .folder, let folderURL {
            try? FolderBookmarks.remember(targetID: id, url: folderURL)
        }
        if !token.isEmpty {
            try? KeychainStore.storeToken(targetID: id, token)
        }
        onChange()
        dismiss()
    }
}

/// Joining a sync set from the key file on one of its targets.
private struct JoinSyncSetView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var password = ""
    @State private var isWorking = false
    @State private var problem: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Backup password", text: $password)
                } footer: {
                    if let problem {
                        Text(problem).foregroundStyle(.red)
                    } else {
                        Text("""
                        The same password you use for encrypted backups. MFA will look \
                        for the key file on the targets you have set up.
                        """)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Join a sync set")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Join") { Task { await join() } }
                        .disabled(password.isEmpty || isWorking)
                }
            }
        }
    }

    private func join() async {
        isWorking = true
        defer { isWorking = false }
        do {
            guard let keyFile = try await SyncCoordinator.fetchKeyFile(targets: model.syncTargets())
            else {
                problem = "No key file was found. Publish one from the device that already syncs."
                return
            }
            model.joinSyncSet(keyFile: keyFile, password: password)
            dismiss()
        } catch {
            problem = error.localizedDescription
        }
    }
}

/// Publishing the wrapped key so another device can join.
private struct PublishKeyFileView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var password = ""
    @State private var isWorking = false
    @State private var problem: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("Backup password", text: $password)
                } footer: {
                    if let problem {
                        Text(problem).foregroundStyle(.red)
                    } else {
                        Text("""
                        Choose a long one. This single password protects your backups \
                        and the key file on every sync target.
                        """)
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Publish the key file")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Publish") { Task { await publish() } }
                        .disabled(password.count < 8 || isWorking)
                }
            }
        }
    }

    private func publish() async {
        isWorking = true
        defer { isWorking = false }

        if let failure = await model.publishKeyFile(password: password) {
            problem = failure
        } else {
            dismiss()
        }
    }
}
