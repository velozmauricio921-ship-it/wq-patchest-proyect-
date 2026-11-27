import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct AppTheme {
    static let accent = Color.accentColor
    static let emptyIconSize: CGFloat = 30
    static let pageInset: CGFloat = 16
}

struct AppLanguage {
    private static let fallbackStrings = [
        "common.cancel": "Cancel",
        "common.done": "Done",
        "common.failed": "Failed",
        "common.ok": "OK",
        "patch.add": "Add project",
        "patch.edit": "Edit project",
        "patch.empty_message": "Create a project or import a .3105 package.",
        "patch.empty_title": "No projects yet",
        "patch.import": "Import project",
        "patch.new": "New project",
        "patch.title": "External"
    ]

    func text(_ key: String) -> String {
        let localized = Bundle.main.localizedString(forKey: key, value: nil, table: "PatchLocalizable")
        if localized != key { return localized }
        if let fallback = Self.fallbackStrings[key] { return fallback }
        return (key.components(separatedBy: ".").last ?? key)
            .replacingOccurrences(of: "_", with: " ")
            .capitalized
    }

    func text(_ key: String, _ argument: Int64) -> String {
        String(format: text(key), locale: Locale.current, argument)
    }

    func text(_ key: String, _ argument: String) -> String {
        String(format: text(key), locale: Locale.current, argument)
    }
}

private struct AppLanguageEnvironmentKey: EnvironmentKey {
    static let defaultValue = AppLanguage()
}

extension EnvironmentValues {
    var appLanguage: AppLanguage {
        get { self[AppLanguageEnvironmentKey.self] }
        set { self[AppLanguageEnvironmentKey.self] = newValue }
    }
}

struct PatchProjectDraft {
    let name: String
    let bundleIdentifiers: [String]
    let directories: [PatchDirectory]
    let rules: [PatchRule]

    init(
        name: String,
        bundleIdentifiers: [String] = [],
        directories: [PatchDirectory] = [],
        rules: [PatchRule] = []
    ) {
        self.name = name
        self.bundleIdentifiers = bundleIdentifiers
        self.directories = directories
        self.rules = rules
    }
}

struct FileDocumentPicker: UIViewControllerRepresentable {
    let allowedContentTypes: [UTType]
    let copiesSelectedDocument: Bool
    let allowsMultipleSelection: Bool
    let onSelection: (Result<[URL], Error>) -> Void
    let onCancel: () -> Void

    init(
        allowedContentTypes: [UTType] = [.item],
        copiesSelectedDocument: Bool = false,
        allowsMultipleSelection: Bool = true,
        onSelection: @escaping (Result<[URL], Error>) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.allowedContentTypes = allowedContentTypes
        self.copiesSelectedDocument = copiesSelectedDocument
        self.allowsMultipleSelection = allowsMultipleSelection
        self.onSelection = onSelection
        self.onCancel = onCancel
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(onSelection: onSelection, onCancel: onCancel)
    }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: allowedContentTypes,
            asCopy: copiesSelectedDocument
        )
        picker.allowsMultipleSelection = allowsMultipleSelection
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(_ controller: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        private let onSelection: (Result<[URL], Error>) -> Void
        private let onCancel: () -> Void

        init(
            onSelection: @escaping (Result<[URL], Error>) -> Void,
            onCancel: @escaping () -> Void
        ) {
            self.onSelection = onSelection
            self.onCancel = onCancel
        }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            onSelection(.success(urls))
        }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            onCancel()
        }
    }
}

extension FileManager {
    func recursiveFiles(in root: URL, matchingExtension fileExtension: String) throws -> [URL] {
        var isDirectory: ObjCBool = false
        guard fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue,
              let enumerator = enumerator(
                  at: root,
                  includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
                  options: [.skipsHiddenFiles]
              ) else {
            return []
        }

        var files: [URL] = []
        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true,
                  values.isSymbolicLink != true,
                  url.pathExtension.caseInsensitiveCompare(fileExtension) == .orderedSame else {
                continue
            }
            files.append(url)
        }
        return files
    }
}

@MainActor
@objc(WQExternalPatchViewFactory)
final class WQExternalPatchViewFactory: NSObject {
    @objc static func makeViewController() -> UIViewController {
        let coordinator = PatchDraftCoordinator()
        let view = PatchProjectsView().environmentObject(coordinator)
        return UIHostingController(rootView: view)
    }
}

private enum PatchPackagePickerPolicy {
    static let packageType = UTType(filenameExtension: "3105") ?? .data
    static let allowedContentTypes: [UTType] = [packageType, .data]
    static let copiesSelectedDocument = true
}

struct PatchProjectsView: View {
    @Environment(\.appLanguage) private var language
    @EnvironmentObject private var draftCoordinator: PatchDraftCoordinator
    @StateObject private var store = PatchProjectStore()
    @State private var showCreate = false
    @State private var showImporter = false
    @State private var searchText = ""
    @State private var selectedGroup: String? = nil
    @State private var selectedSubgroup: String? = nil

    private var filteredItems: [PatchLibraryItem] {
        // Start from full list and apply category/subcategory filtering first
        var items = store.items
        if let group = selectedGroup {
            items = items.filter { $0.categories.first == group }
        }
        if let subgroup = selectedSubgroup {
            items = items.filter { $0.categories.count > 1 && $0.categories[1] == subgroup }
        }

        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return items }

        return items.filter { item in
            if item.packageURL.lastPathComponent.localizedCaseInsensitiveContains(query) {
                return true
            }
            guard let project = item.project else { return false }
            return project.name.localizedCaseInsensitiveContains(query)
                || project.allBundleIdentifiers.contains {
                    $0.localizedCaseInsensitiveContains(query)
                }
                || project.directories.contains {
                    $0.relativePath.localizedCaseInsensitiveContains(query)
                }
                || project.rules.contains {
                    $0.relativePath.localizedCaseInsensitiveContains(query)
                        || $0.replacementFilename.localizedCaseInsensitiveContains(query)
                }
        }
    }

    private var availableGroups: [String] {
        let groups = Set(store.items.compactMap { $0.categories.first })
        return Array(groups).sorted()
    }

    private func availableSubgroups(for group: String) -> [String] {
        let subs = Set(store.items.compactMap { item -> String? in
            let cats = item.categories
            guard cats.first == group, cats.count > 1 else { return nil }
            return cats[1]
        })
        return Array(subs).sorted()
    }

    init() {
#if targetEnvironment(simulator)
        _showCreate = State(
            initialValue: ProcessInfo.processInfo.arguments.contains("--simulate-patch-editor")
        )
#endif
    }

    var body: some View {
        NavigationStack {
            ZStack {
                LinearGradient(
                    colors: [Color(red: 0.05, green: 0.10, blue: 0.18), Color(red: 0.12, green: 0.16, blue: 0.24)],
                    startPoint: .top,
                    endPoint: .bottom
                )
                .ignoresSafeArea()

                VStack(spacing: 12) {
                    ZStack(alignment: .trailing) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("GIAN XIT")
                                .font(.system(size: 30, weight: .heavy, design: .rounded))
                                .foregroundStyle(Color(red: 0.83, green: 0.96, blue: 1.00))
                                .tracking(-1.2)
                                .textCase(.uppercase)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 18)
                        .padding(.vertical, 22)
                        .background(
                            RoundedRectangle(cornerRadius: 24, style: .continuous)
                                .fill(Color(red: 0.12, green: 0.22, blue: 0.34))
                                .overlay(
                                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                                        .stroke(AppTheme.accent.opacity(0.9), lineWidth: 2)
                                )
                        )

                        Circle()
                            .fill(AppTheme.accent)
                            .frame(width: 42, height: 42)
                            .padding(.trailing, 18)
                            .overlay(
                                Text("B")
                                    .font(.system(size: 21, weight: .heavy))
                                    .foregroundStyle(Color(red: 0.04, green: 0.12, blue: 0.20))
                            )
                    }
                    .padding(.horizontal, 14)

                    if !availableGroups.isEmpty {
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                ForEach(availableGroups, id: \.self) { g in
                                    Button(action: {
                                        if selectedGroup == g {
                                            selectedGroup = nil
                                            selectedSubgroup = nil
                                        } else {
                                            selectedGroup = g
                                            selectedSubgroup = nil
                                        }
                                    }) {
                                        Text(g)
                                            .font(.system(size: 15, weight: .semibold, design: .rounded))
                                            .padding(.vertical, 9)
                                            .padding(.horizontal, 14)
                                            .background(
                                                RoundedRectangle(cornerRadius: 10)
                                                    .fill(selectedGroup == g ? AppTheme.accent : Color(white: 0.18))
                                            )
                                            .foregroundStyle(selectedGroup == g ? .black : .white)
                                    }
                                    .buttonStyle(.plain)
                                }
                            }
                            .padding(.horizontal, AppTheme.pageInset)
                            .padding(.vertical, 8)
                        }
                        if let group = selectedGroup {
                            let subs = availableSubgroups(for: group)
                            if !subs.isEmpty {
                                ScrollView(.horizontal, showsIndicators: false) {
                                    HStack(spacing: 8) {
                                        ForEach(subs, id: \.self) { s in
                                            Button(action: {
                                                if selectedSubgroup == s { selectedSubgroup = nil } else { selectedSubgroup = s }
                                            }) {
                                                Text(s)
                                                    .font(.system(size: 14, weight: .medium, design: .rounded))
                                                    .padding(.vertical, 7)
                                                    .padding(.horizontal, 12)
                                                    .background(
                                                        RoundedRectangle(cornerRadius: 8)
                                                            .fill(selectedSubgroup == s ? AppTheme.accent : Color(white: 0.18))
                                                    )
                                                    .foregroundStyle(selectedSubgroup == s ? .black : .white)
                                            }
                                            .buttonStyle(.plain)
                                        }
                                    }
                                    .padding(.horizontal, AppTheme.pageInset)
                                    .padding(.bottom, 6)
                                }
                            }
                        }
                    }

                    List {
                        if store.items.isEmpty && !store.isBusy {
                            emptyState
                                .listRowSeparator(.hidden)
                        } else if filteredItems.isEmpty && !store.isBusy {
                            searchEmptyState
                                .listRowSeparator(.hidden)
                        } else {
                            ForEach(filteredItems) { item in
                                itemRow(item)
                            }
                            .onDelete { offsets in
                                offsets.map { filteredItems[$0] }.forEach(store.delete)
                            }
                        }
                    }
                    .listStyle(.insetGrouped)
                    .scrollContentBackground(.hidden)
                    .background(Color.clear)
                }
            }
        } // NavigationStack end
        .navigationTitle(language.text("patch.title"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Menu {
                    Button {
                        showCreate = true
                    } label: {
                        Label(language.text("patch.new"), systemImage: "doc.badge.plus")
                    }
                    Button {
                        showImporter = true
                    } label: {
                        Label(language.text("patch.import"), systemImage: "square.and.arrow.down")
                    }
                } label: {
                    if store.isBusy {
                        ProgressView()
                    } else {
                        Image(systemName: "plus")
                    }
                }
                .disabled(store.isBusy)
                .accessibilityLabel(language.text("patch.add"))
            }
        }
        .sheet(isPresented: $showImporter) {
            FileDocumentPicker(
                allowedContentTypes: PatchPackagePickerPolicy.allowedContentTypes,
                copiesSelectedDocument: PatchPackagePickerPolicy.copiesSelectedDocument,
                allowsMultipleSelection: false,
                onSelection: { result in
                    showImporter = false
                    if case .success(let urls) = result, let url = urls.first {
                        store.importPackage(at: url)
                    }
                },
                onCancel: {
                    showImporter = false
                }
            )
            .ignoresSafeArea()
        }
        .sheet(isPresented: $showCreate) {
            PatchProjectEditorView(
                existingProject: nil,
                passwordIsProtected: false
            ) { project, password in
                store.create(project: project, password: password)
            }
        }
        .sheet(item: $draftCoordinator.request) { request in
            PatchProjectEditorView(
                existingProject: nil,
                passwordIsProtected: false,
                initialDraft: request.draft
            ) { project, password in
                store.create(project: project, password: password)
                draftCoordinator.clear()
            }
        }
        .sheet(item: $store.passwordRequest, onDismiss: store.cancelUnlock) { _ in
            PatchUnlockView(store: store)
        }
        .alert(item: $store.alert) { alert in
            Alert(
                title: Text(language.text(alert.titleKey)),
                message: Text(alert.message(language: language)),
                dismissButton: .default(Text(language.text("common.ok")))
            )
        }
        .onAppear(perform: consumeExternalImport)
        .onChange(of: draftCoordinator.importRequest?.id) { _ in
            consumeExternalImport()
        }
    }

    private func consumeExternalImport() {
        guard let request = draftCoordinator.importRequest else { return }
        draftCoordinator.clearImport()
        store.importPackage(from: request.source)
    }

    @ViewBuilder
    private func itemRow(_ item: PatchLibraryItem) -> some View {
        if item.isLocked {
            Button { store.requestUnlock(for: item) } label: {
                PatchProjectRow(item: item, language: language)
            }
            .buttonStyle(.plain)
        } else {
            NavigationLink {
                PatchProjectDetailView(store: store, projectID: item.id)
            } label: {
                PatchProjectRow(item: item, language: language)
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "shippingbox")
                .font(.system(size: AppTheme.emptyIconSize, weight: .light))
                .foregroundStyle(AppTheme.accent)
            Text(language.text("patch.empty_title"))
                .font(.headline)
            Text(language.text("patch.empty_message"))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button(language.text("patch.new")) { showCreate = true }
                .buttonStyle(.bordered)
                .controlSize(.large)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 64)
    }

    private var searchEmptyState: some View {
        VStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: AppTheme.emptyIconSize, weight: .light))
                .foregroundStyle(.secondary)
            Text(language.text("patch.search_empty"))
                .font(.headline)
            Text(language.text("patch.search_empty_message"))
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 64)
    }
}

private struct PatchProjectRow: View {
    let item: PatchLibraryItem
    let language: AppLanguage

    var body: some View {
        HStack(spacing: 12) {
            PatchCubeIcon(isLocked: item.isLocked)

            VStack(alignment: .leading, spacing: 4) {
                let fileTitle = item.packageURL.deletingPathExtension().lastPathComponent
                Text((fileTitle.isEmpty ? (item.project?.name ?? language.text("patch.locked_project")) : fileTitle).uppercased())
                    .font(.system(size: 16, weight: .semibold, design: .rounded))
                    .foregroundStyle(.white)
                    .lineLimit(2)

                Text(item.isLocked
                     ? language.text("patch.tap_to_unlock").uppercased()
                     : language.text(
                        item.summary.schemaVersion >= 2 ? "patch.workspace_items_count" : "patch.rules_count",
                        Int64((item.project?.rules.count ?? 0) + (item.project?.directories.count ?? 0))
                     ).uppercased())
                    .font(.caption)
                    .foregroundStyle(Color(white: 0.8))
            }

            Spacer()

            if item.summary.isPasswordProtected {
                Image(systemName: "key.fill")
                    .font(.caption)
                    .foregroundStyle(AppTheme.accent)
                    .accessibilityLabel(language.text("patch.password_protected"))
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Color(red: 0.10, green: 0.18, blue: 0.26))
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .stroke(AppTheme.accent.opacity(0.3), lineWidth: 1.2)
                )
        )
        .shadow(color: Color.black.opacity(0.18), radius: 10, x: 0, y: 4)
        .padding(.horizontal, AppTheme.pageInset)
        .padding(.vertical, 6)
    }
}

private struct PatchCubeIcon: View {
    let isLocked: Bool

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(LinearGradient(
                    colors: [Color(red: 0.12, green: 0.22, blue: 0.34), Color(red: 0.07, green: 0.16, blue: 0.26)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .stroke(Color.white.opacity(0.12), lineWidth: 1)
                )

            ZStack {
                Circle()
                    .fill(LinearGradient(
                        colors: [Color(red: 0.78, green: 0.95, blue: 1.0), Color(red: 0.44, green: 0.77, blue: 0.98)],
                        startPoint: .top,
                        endPoint: .bottom
                    ))
                    .frame(width: 24, height: 24)

                Circle()
                    .stroke(Color(red: 0.12, green: 0.24, blue: 0.36), lineWidth: 2)
                    .frame(width: 18, height: 18)

                Rectangle()
                    .fill(Color(red: 0.12, green: 0.24, blue: 0.36))
                    .frame(width: 2, height: 22)

                Rectangle()
                    .fill(Color(red: 0.12, green: 0.24, blue: 0.36))
                    .frame(width: 22, height: 2)

                Circle()
                    .fill(AppTheme.accent)
                    .frame(width: 5, height: 5)
            }
            .frame(width: 28, height: 28)

            if isLocked {
                Image(systemName: "lock.fill")
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(.white.opacity(0.9))
                    .padding(4)
                    .background(
                        Circle()
                            .fill(Color(red: 0.08, green: 0.15, blue: 0.24))
                    )
                    .offset(x: 10, y: 10)
            }
        }
        .frame(width: 34, height: 34)
        .cornerRadius(10)
    }
}

private struct PatchUnlockView: View {
    @Environment(\.appLanguage) private var language
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: PatchProjectStore
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField(language.text("patch.password"), text: $password)
                        .textContentType(.password)
                        .submitLabel(.done)
                        .onSubmit(unlock)
                        .onChange(of: password) { _ in
                            store.clearUnlockError()
                        }
                    if let errorKey = store.unlockErrorKey {
                        Text(language.text(errorKey))
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                } footer: {
                    Text(language.text("patch.password_once_message"))
                }
            }
            .navigationTitle(language.text("patch.unlock"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(language.text("common.cancel")) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(language.text("patch.unlock"), action: unlock)
                        .disabled(password.isEmpty || store.isBusy)
                }
            }
        }
    }

    private func unlock() {
        guard !password.isEmpty else { return }
        store.unlock(password: password)
    }
}

private struct PatchProjectDetailView: View {
    @Environment(\.appLanguage) private var language
    @ObservedObject var store: PatchProjectStore
    let projectID: UUID
    @State private var showEditor = false
    @State private var editingRule: PatchRule?

    private var item: PatchLibraryItem? {
        store.items.first(where: { $0.id == projectID })
    }

    private var isWorkspaceProject: Bool {
        (item?.summary.schemaVersion ?? 1) >= 2
    }

    var body: some View {
        List {
            if let item, let project = item.project {
                if isWorkspaceProject {
                    Section {
                        ForEach(project.allBundleIdentifiers, id: \.self) { bundleID in
                            Label {
                                Text(bundleID)
                                    .font(.subheadline.monospaced())
                            } icon: {
                                Image(systemName: "app.dashed")
                                    .foregroundStyle(AppTheme.accent)
                            }
                        }
                        LabeledContent(language.text("patch.files")) {
                            Text("\(project.rules.count)")
                        }
                        LabeledContent(language.text("patch.folders")) {
                            Text("\(project.directories.count)")
                        }
                        if let workspaceURL = item.workspaceURL {
                            NavigationLink {
                                FileBrowserView(
                                    containerPath: workspaceURL.path,
                                    title: project.name,
                                    bundleID: nil
                                )
                            } label: {
                                Label(
                                    language.text("patch.open_workspace"),
                                    systemImage: "folder"
                                )
                            }
                        }
                    } header: {
                        Text(language.text("patch.workspace"))
                    } footer: {
                        Text(language.text("patch.workspace_detail_footer"))
                    }
                } else {
                    Section {
                        ForEach(project.rules) { rule in
                            Button {
                                editingRule = rule
                            } label: {
                                HStack(spacing: 10) {
                                    ruleSummary(rule)
                                    Spacer(minLength: 8)
                                    Image(systemName: "chevron.right")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.tertiary)
                                }
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .accessibilityHint(language.text("patch.edit_rule_hint"))
                        }
                    } header: {
                        Text(language.text("patch.rules"))
                    } footer: {
                        Text(language.text("patch.legacy_footer"))
                    }
                }

                Section(language.text("patch.password")) {
                    HStack(spacing: 12) {
                        Image(systemName: item.summary.isPasswordProtected ? "lock.fill" : "lock.open")
                            .foregroundStyle(AppTheme.accent)
                            .frame(width: 24)
                        Text(language.text(item.summary.isPasswordProtected
                            ? "patch.password_locked"
                            : "patch.no_password"))
                            .font(.subheadline)
                    }
                }

            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle(item?.project?.name ?? language.text("patch.title"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if !isWorkspaceProject {
                    Button(language.text("patch.edit")) { showEditor = true }
                        .disabled(item?.project == nil)
                }
            }
        }
        .sheet(isPresented: $showEditor) {
            if let item, let project = item.project {
                PatchProjectEditorView(
                    existingProject: project,
                    passwordIsProtected: item.summary.isPasswordProtected
                ) { updatedProject, _ in
                    store.update(project: updatedProject)
                }
            }
        }
        .sheet(item: $editingRule) { rule in
            PatchRuleEditorView(rule: rule) { updatedRule in
                updateRule(updatedRule)
            }
        }
    }

    private func ruleSummary(_ rule: PatchRule) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(rule.bundleID)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.primary)
            Text(rule.relativePath)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(2)
            Label(rule.replacementFilename, systemImage: "arrow.triangle.2.circlepath")
                .font(.caption)
                .foregroundStyle(AppTheme.accent)
        }
        .padding(.vertical, 3)
    }

    private func updateRule(_ updatedRule: PatchRule) {
        guard var project = item?.project,
              let index = project.rules.firstIndex(where: { $0.id == updatedRule.id }) else {
            return
        }
        project.rules[index] = updatedRule
        project.updatedAt = Date()
        do {
            try PatchPackageCodec.validate(project)
            store.update(project: project)
        } catch let error as PatchPackageError {
            actionAlert = PatchStoreAlert(
                titleKey: "common.failed",
                messageKey: error.localizationKey,
                messageArgument: error.localizationArgument
            )
        } catch {
            actionAlert = PatchStoreAlert(
                titleKey: "common.failed",
                messageKey: "patch.error.invalid_project"
            )
        }
    }

    // Export functionality removed to avoid accidental leaking of .3105 packages.
}

private struct PatchShareRequest: Identifiable {
    let id = UUID()
    let url: URL
}

private struct PatchActivityView: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(
        _ uiViewController: UIActivityViewController,
        context: Context
    ) {}
}
