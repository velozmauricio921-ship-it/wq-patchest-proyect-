import Foundation

struct PatchLibraryItem: Identifiable {
    let summary: PatchPackageSummary
    var project: PatchProject?
    var contentKey: Data?
    var categories: [String] = []
    var packageURL: URL

    var id: UUID { summary.packageID }
    var isLocked: Bool { project == nil }
    var workspaceURL: URL? {
        PatchWorkspaceService.workspaceURL(projectID: id)
    }
}

struct PatchPasswordRequest: Identifiable {
    let summary: PatchPackageSummary
    var id: UUID { summary.packageID }
}

private enum SecureZIPArchive {
    static func extract(archiveURL: URL, destinationURL: URL) throws {
        var errorText: NSString?
        guard wq_zip_extract(
            archiveURL.path,
            destinationURL.path,
            wq_archive_posix_io(),
            512 * 1024 * 1024,
            nil,
            nil,
            nil,
            nil,
            &errorText
        ) else {
            throw NSError(
                domain: "SecureZIPArchive",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: errorText.map { $0 as String } ?? "ZIP extraction failed"]
            )
        }
    }
}

enum PatchProjectLibrary {
    private static let installNamespaceKey = "PatchProjectLibrary.installNamespace"

    private static func appNamespace() -> String {
        if let stored = UserDefaults.standard.string(forKey: installNamespaceKey), !stored.isEmpty {
            return stored
        }

        let generated = UUID().uuidString
        UserDefaults.standard.set(generated, forKey: installNamespaceKey)
        return generated
    }

    static func legacyPackageRootURL(fileManager: FileManager = .default) throws -> URL {
        let base = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        return base.appendingPathComponent("PatchProjects", isDirectory: true)
    }

    static func packageRootURL(fileManager: FileManager = .default) throws -> URL {
        let base = try fileManager.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let root = base
            .appendingPathComponent(appNamespace(), isDirectory: true)
            .appendingPathComponent("PatchProjects", isDirectory: true)

        let legacyRoot = try legacyPackageRootURL(fileManager: fileManager)
        if fileManager.fileExists(atPath: legacyRoot.path),
           legacyRoot.path != root.path {
            do {
                try? fileManager.removeItem(at: legacyRoot)
            }
        }

        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    static func backupRootURL(fileManager: FileManager = .default) throws -> URL {
        let root = try packageRootURL(fileManager: fileManager)
            .appendingPathComponent("Backups", isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    static func preloadedRootURL(fileManager: FileManager = .default) throws -> URL {
        let root = try packageRootURL(fileManager: fileManager)
            .appendingPathComponent("Preloaded", isDirectory: true)
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    static func load(fileManager: FileManager = .default) -> [PatchLibraryItem] {
        ensurePreloadedPackagesInstalled(fileManager: fileManager)

        guard let root = try? packageRootURL(fileManager: fileManager) else { return [] }

        let rootURLs = (try? fileManager.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
            options: [.skipsHiddenFiles, .skipsSubdirectoryDescendants]
        )) ?? []

        let preloadedURLs: [URL]
        if let recursive = try? fileManager.recursiveFiles(in: try preloadedRootURL(fileManager: fileManager), matchingExtension: "3105") {
            preloadedURLs = recursive
        } else {
            preloadedURLs = (try? fileManager.contentsOfDirectory(
                at: try preloadedRootURL(fileManager: fileManager),
                includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
                options: [.skipsHiddenFiles, .skipsSubdirectoryDescendants]
            )) ?? []
        }

        let preloadedNames = Set(preloadedURLs.map { $0.lastPathComponent })
        let filteredRootURLs = rootURLs.filter { url in
            guard url.pathExtension.lowercased() == "3105" else { return false }
            guard !isPreloadedResource(url) else { return false }
            return !preloadedNames.contains(url.lastPathComponent)
        }

        let urls = filteredRootURLs + preloadedURLs

        var items: [PatchLibraryItem] = []
        var seenPaths = Set<String>()

        for url in urls where url.pathExtension.lowercased() == "3105" {
            do {
                let data = try readPackage(at: url)
                let summary = try PatchPackageCodec.inspect(data)

                // Keep every bundled package file distinct. Some release bundles can contain
                // several .3105 files that legitimately share the same package metadata, but
                // they must still appear as separate entries in the UI and cache.
                let pathKey = url.standardizedFileURL.path
                if !seenPaths.insert(pathKey).inserted {
                    continue
                }

                // Require contentKey in secure keychain for non-password-protected packages.
                let decoded: DecodedPatchPackage?
                if let contentKey = try? PatchKeyStore.load(for: summary) {
                    decoded = try PatchPackageCodec.decode(data, contentKey: contentKey)
                } else if summary.isPasswordProtected {
                    // If password-protected and no key available, keep locked
                    decoded = nil
                } else {
                    // For public packages, still attempt decode without contentKey
                    decoded = try PatchPackageCodec.decode(data, password: nil)
                }
                var categories: [String] = []
                if let preloadIndex = url.pathComponents.firstIndex(where: isPreloadedDirectoryName) {
                    let comps = url.pathComponents
                    if preloadIndex + 1 < comps.count - 1 {
                        categories = Array(comps[(preloadIndex + 1)..<(comps.count - 1)])
                    }
                }

                let item = PatchLibraryItem(
                    summary: summary,
                    project: decoded?.project,
                    contentKey: decoded?.contentKey,
                    categories: categories,
                    packageURL: url
                )
                if summary.schemaVersion >= 2, let project = decoded?.project {
                    do {
                        _ = try PatchWorkspaceService.ensureWorkspace(for: project)
                    } catch {
                        wq_log_message("patch: workspace unavailable for \(project.id.uuidString)")
                    }
                }
                items.append(item)
            } catch {
                wq_log_message("patch: skipped invalid local package \(url.lastPathComponent)")
            }
        }
        return items.sorted {
            ($0.project?.updatedAt ?? .distantPast) > ($1.project?.updatedAt ?? .distantPast)
        }
    }

    static func readPackage(at url: URL) throws -> Data {
        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
        guard values.isDirectory != true,
              values.isSymbolicLink != true,
              values.isRegularFile == true else {
            throw PatchPackageError.invalidProject
        }
        return try Data(contentsOf: url, options: .mappedIfSafe)
    }

    static func save(
        data: Data,
        projectName: String,
        existingURL: URL? = nil,
        fileManager: FileManager = .default
    ) throws -> URL {
        let destination: URL
        if let existingURL {
            destination = existingURL
        } else {
            let root = try packageRootURL(fileManager: fileManager)
            let baseName = sanitizedFilename(projectName)
            var candidate = root.appendingPathComponent(baseName).appendingPathExtension("3105")
            var suffix = 2
            while fileManager.fileExists(atPath: candidate.path) {
                candidate = root.appendingPathComponent("\(baseName)-\(suffix)").appendingPathExtension("3105")
                suffix += 1
            }
            destination = candidate
        }
        try data.write(to: destination, options: [.atomic, .completeFileProtection])
        return destination
    }

    static func installImportedPackage(
        data: Data,
        decoded: DecodedPatchPackage,
        summary: PatchPackageSummary,
        existingURL: URL?,
        fileManager: FileManager = .default
    ) throws {
        let previousData = try existingURL.map { try readPackage(at: $0) }
        var savedURL: URL?
        do {
            savedURL = try save(
                data: data,
                projectName: decoded.project.name,
                existingURL: existingURL,
                fileManager: fileManager
            )
            if summary.schemaVersion >= 2 {
                _ = try PatchWorkspaceService.replaceWorkspace(
                    with: decoded.project,
                    fileManager: fileManager
                )
            } else {
                try? PatchWorkspaceService.deleteWorkspace(
                    projectID: decoded.project.id,
                    fileManager: fileManager
                )
            }
        } catch {
            if let previousData, let existingURL {
                try? previousData.write(
                    to: existingURL,
                    options: [.atomic, .completeFileProtection]
                )
            } else if let savedURL, fileManager.fileExists(atPath: savedURL.path) {
                try? fileManager.removeItem(at: savedURL)
            }
            throw error
        }
    }

    static func delete(_ item: PatchLibraryItem, fileManager: FileManager = .default) throws {
        if fileManager.fileExists(atPath: item.packageURL.path) {
            try fileManager.removeItem(at: item.packageURL)
        }
        try? PatchWorkspaceService.deleteWorkspace(projectID: item.id, fileManager: fileManager)
        try? PatchKeyStore.delete(for: item.summary)
    }

    static func synchronizeWorkspace(
        item: PatchLibraryItem,
        fileManager: FileManager = .default
    ) throws -> PatchProject {
        guard item.summary.schemaVersion >= 2,
              let baseProject = item.project,
              let contentKey = item.contentKey else {
            throw PatchPackageError.invalidProject
        }
        let workspace = try PatchWorkspaceService.ensureWorkspace(
            for: baseProject,
            fileManager: fileManager
        )
        let project = try PatchWorkspaceService.snapshot(
            baseProject: baseProject,
            workspaceURL: workspace,
            fileManager: fileManager
        )
        let original = try readPackage(at: item.packageURL)
        let updated = try PatchPackageCodec.update(
            original,
            project: project,
            contentKey: contentKey,
            schemaVersion: PatchPackageCodec.latestSchemaVersion
        )
        _ = try save(
            data: updated,
            projectName: project.name,
            existingURL: item.packageURL,
            fileManager: fileManager
        )
        return project
    }

    static func ensurePreloadedPackagesInstalled(fileManager: FileManager = .default) {
        guard (try? packageRootURL(fileManager: fileManager)) != nil else { return }

        let preloadedRoot: URL
        do {
            preloadedRoot = try preloadedRootURL(fileManager: fileManager)
        } catch {
            wq_log_message("preload: failed to prepare preloaded cache — \(error.localizedDescription)")
            return
        }

        do {
            if fileManager.fileExists(atPath: preloadedRoot.path) {
                try fileManager.removeItem(at: preloadedRoot)
            }
            try fileManager.createDirectory(at: preloadedRoot, withIntermediateDirectories: true)
        } catch {
            wq_log_message("preload: failed to clear stale preloaded cache — \(error.localizedDescription)")
        }

        var bundleURLs: [URL] = []

        // Prefer a single packaged archive named `Preloaded.tendies` in the app bundle.
        // This allows shipping preloaded packages inside a single compressed file so the
        // `Preloaded` folder is not openly visible when the IPA is unpacked.
        if let archiveURL = Bundle.main.url(forResource: "Preloaded", withExtension: "tendies") {
            do {
                try SecureZIPArchive.extract(archiveURL: archiveURL, destinationURL: preloadedRoot)
                if let recursive = try? fileManager.recursiveFiles(in: preloadedRoot, matchingExtension: "3105") {
                    bundleURLs += recursive.filter(isPreloadedResource)
                }
                wq_log_message("preload: extracted bundled Preloaded.tendies archive into cache")
            } catch {
                wq_log_message("preload: failed to extract bundled archive — \(error.localizedDescription)")
            }
        }

        // Fallback: if no packaged archive, look for a Preloaded directory inside bundle resources.
        // Important: nested folders such as `Preloaded/Free Fire/Visuals` must be traversed recursively,
        // otherwise the app only sees top-level entries and misses the actual .3105 files.
        if bundleURLs.isEmpty, let resourceRoot = Bundle.main.resourceURL {
            if let directPreloaded = preloadedResourceDirectory(in: resourceRoot, fileManager: fileManager),
               let recursive = try? fileManager.recursiveFiles(in: directPreloaded, matchingExtension: "3105") {
                bundleURLs += recursive.filter(isPreloadedResource)
            }

            if bundleURLs.isEmpty,
               let recursive = try? fileManager.recursiveFiles(in: resourceRoot, matchingExtension: "3105") {
                bundleURLs += recursive.filter(isPreloadedResource)
            }
        }

        for subdirectory in ["preloaded", "Preloaded"] where bundleURLs.isEmpty {
            if let nestedResourceURLs = Bundle.main.urls(
                forResourcesWithExtension: "3105",
                subdirectory: subdirectory
            ) {
                bundleURLs += nestedResourceURLs
            }
        }

        for directory in ["preloaded", "Preloaded"] where bundleURLs.isEmpty {
            if let paths = Bundle.main.paths(forResourcesOfType: "3105", inDirectory: directory) as [String]? {
                bundleURLs += paths.map { URL(fileURLWithPath: $0) }
            }
        }

        guard !bundleURLs.isEmpty else {
            wq_log_message("preload: no bundled .3105 files found in app resources")
            return
        }

        // Preserve folder structure inside the Preloaded resource directory when copying into cache.
        let uniqueBundleURLs = Dictionary(uniqueKeysWithValues: bundleURLs.map { ($0.path, $0) }).values

        for sourceURL in uniqueBundleURLs.sorted(by: { $0.path < $1.path }) {
            // Compute relative path components after the "Preloaded" segment so we can recreate subfolders
            let comps = sourceURL.pathComponents
            var destinationURL: URL
            if let preloadIndex = comps.firstIndex(where: isPreloadedDirectoryName), preloadIndex + 1 < comps.count {
                let relative = comps[(preloadIndex + 1)...].joined(separator: "/")
                destinationURL = preloadedRoot.appendingPathComponent(relative)
            } else {
                destinationURL = preloadedRoot.appendingPathComponent(sourceURL.lastPathComponent)
            }

            do {
                // Ensure parent folder exists to preserve structure
                try fileManager.createDirectory(at: destinationURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                if fileManager.fileExists(atPath: destinationURL.path) {
                    try fileManager.removeItem(at: destinationURL)
                }
                try fileManager.copyItem(at: sourceURL, to: destinationURL)
                wq_log_message("preload: copied bundled package \(sourceURL.lastPathComponent) to cache as \(destinationURL.path)")
            } catch {
                wq_log_message("preload: failed to copy \(sourceURL.lastPathComponent) — \(error.localizedDescription)")
            }
        }

        // Intentionally left harmless: we do not delete user-facing patch files here.
        // Only the canonical `Preloaded` cache is installed so that existing patches remain intact.
    }

    private static func isPreloadedDirectoryName(_ component: String) -> Bool {
        component.caseInsensitiveCompare("Preloaded") == .orderedSame
    }

    private static func isPreloadedResource(_ url: URL) -> Bool {
        url.pathComponents.contains(where: isPreloadedDirectoryName)
    }

    private static func preloadedResourceDirectory(
        in resourceRoot: URL,
        fileManager: FileManager
    ) -> URL? {
        for name in ["preloaded", "Preloaded"] {
            let directory = resourceRoot.appendingPathComponent(name, isDirectory: true)
            var isDirectory: ObjCBool = false
            if fileManager.fileExists(atPath: directory.path, isDirectory: &isDirectory), isDirectory.boolValue {
                return directory
            }
        }
        return nil
    }

    private static func sanitizedFilename(_ rawName: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_ "))
        let scalars = rawName.unicodeScalars.map { allowed.contains($0) ? Character(String($0)) : "-" }
        let result = String(scalars)
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .prefix(80)
        return result.isEmpty ? "Patch" : String(result)
    }
}

extension FileManager {
    func recursiveFiles(in directory: URL, matchingExtension fileExtension: String) throws -> [URL] {
        let keys: [URLResourceKey] = [.isRegularFileKey, .isSymbolicLinkKey]
        guard let enumerator = enumerator(
            at: directory,
            includingPropertiesForKeys: keys,
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else {
            return []
        }

        var files: [URL] = []
        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: Set(keys))
            guard values.isRegularFile == true,
                  values.isSymbolicLink != true,
                  url.pathExtension.localizedCaseInsensitiveCompare(fileExtension) == .orderedSame else {
                continue
            }
            files.append(url)
        }
        return files
    }
}
