import SwiftUI

/// The main screen: every account, its code, and how long that code has left.
struct AccountListView: View {
    @EnvironmentObject private var model: AppModel
    @State private var isAdding = false
    @State private var isShowingSettings = false
    @State private var editing: AccountView?
    @State private var sharing: AccountView?
    @State private var pendingDeletion: AccountView?

    var body: some View {
        NavigationStack {
            Group {
                if model.accounts.isEmpty {
                    emptyState
                } else {
                    list
                }
            }
            .navigationTitle("MFA")
            .searchable(text: $model.query, prompt: "Search")
            .onChange(of: model.query) { _, _ in model.queryChanged() }
            .toolbar { toolbar }
            .safeAreaInset(edge: .bottom) { statusBar }
        }
        .sheet(isPresented: $isAdding) { AddAccountView() }
        .sheet(isPresented: $isShowingSettings) {
            #if os(iOS)
            NavigationStack { SettingsView() }
            #else
            SettingsView().frame(width: 460)
            #endif
        }
        .sheet(item: $editing) { EditAccountView(account: $0) }
        .sheet(item: $sharing) { ShowQRView(account: $0) }
        .confirmationDialog(
            "Delete “\(pendingDeletion?.displayName ?? "")”?",
            isPresented: Binding(get: { pendingDeletion != nil },
                                 set: { if !$0 { pendingDeletion = nil } }),
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                if let account = pendingDeletion { model.delete(id: account.id) }
                pendingDeletion = nil
            }
        } message: {
            Text("""
            You will not be able to sign in to this account with MFA again \
            unless you add it back. Check you can still get in another way first.
            """)
        }
    }

    private var list: some View {
        List {
            ForEach(model.accounts, id: \.id) { account in
                AccountRow(account: account) { model.copy(account) }
                    .contextMenu {
                        Button("Copy code") { model.copy(account) }
                        Button("Edit…") { editing = account }
                        Button("Show QR code…") { sharing = account }
                        Divider()
                        Button("Delete…", role: .destructive) { pendingDeletion = account }
                    }
                    .swipeActions(edge: .trailing) {
                        Button("Delete", role: .destructive) { pendingDeletion = account }
                    }
            }
            .onMove(perform: reorder)
        }
        #if os(iOS)
        .listStyle(.insetGrouped)
        #endif
    }

    /// Dragging only makes sense while the list is unfiltered and in manual
    /// order; otherwise the drop position means nothing, so `onMove` gets nil
    /// and the rows stop offering a grab handle.
    ///
    /// Passing `model.move` straight in does not compile: the model is
    /// `@MainActor`, so the method reference carries that isolation in its type
    /// and will not convert to the plain closure `onMove` wants. SwiftUI only
    /// ever calls this from the main thread, which is what makes assuming the
    /// isolation here true rather than merely convenient.
    private var reorder: ((IndexSet, Int) -> Void)? {
        guard isReorderable else { return nil }
        return { source, destination in
            MainActor.assumeIsolated { model.move(from: source, to: destination) }
        }
    }

    private var isReorderable: Bool {
        model.query.trimmingCharacters(in: .whitespaces).isEmpty
            && model.preferences()?.sort == .manual
    }

    private var emptyState: some View {
        ContentUnavailableView {
            Label(model.query.isEmpty ? "No accounts yet" : "Nothing matches",
                  systemImage: model.query.isEmpty ? "person.badge.key" : "magnifyingglass")
        } description: {
            Text(model.query.isEmpty
                 ? "Add your first account by scanning the QR code a website shows you."
                 : "Try a different search.")
        } actions: {
            if model.query.isEmpty {
                Button("Add account") { isAdding = true }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .primaryAction) {
            Button { isAdding = true } label: { Label("Add", systemImage: "plus") }
        }
        ToolbarItem(placement: .secondaryAction) {
            Button { Task { await model.syncNow() } } label: {
                Label("Sync", systemImage: "arrow.triangle.2.circlepath")
            }
            .disabled(model.isSyncing || !model.hasSyncKey)
        }
        ToolbarItem(placement: .secondaryAction) {
            Button { isShowingSettings = true } label: { Label("Settings", systemImage: "gear") }
        }
        ToolbarItem(placement: .cancellationAction) {
            Button { model.lock() } label: { Label("Lock", systemImage: "lock") }
        }
    }

    /// A one-line report that gets out of the way by itself.
    @ViewBuilder
    private var statusBar: some View {
        if let status = model.status {
            Text(status)
                .font(.footnote)
                .padding(.vertical, 8)
                .frame(maxWidth: .infinity)
                .background(.thinMaterial)
                .transition(.move(edge: .bottom).combined(with: .opacity))
        } else if model.isSyncing {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Syncing…").font(.footnote)
            }
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity)
            .background(.thinMaterial)
        }
    }
}

/// `sheet(item:)` for anything identifiable, which `AccountView` is not by
/// itself — it comes from the bindings.
extension AccountView: Identifiable {}

extension View {
    func sheet<Item: Identifiable, Content: View>(
        item: Binding<Item?>,
        @ViewBuilder content: @escaping (Item) -> Content
    ) -> some View {
        sheet(isPresented: Binding(get: { item.wrappedValue != nil },
                                   set: { if !$0 { item.wrappedValue = nil } })) {
            if let value = item.wrappedValue { content(value) }
        }
    }
}
