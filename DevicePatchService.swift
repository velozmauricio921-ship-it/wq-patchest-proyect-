import Foundation
import Darwin

enum DevicePatchService {
    static func apply(project: PatchProject) async throws -> PatchTransactionReceipt {
        guard wq_auth_has_valid_session() else { throw PatchPackageError.licenseRevoked }

        let bundleIDs = orderedBundleIdentifiers(in: project)
        return try withResolvedContainers(bundleIDs: bundleIDs) { roots in
            try PatchTransaction.apply(
                project: project,
                backupRoot: try PatchProjectLibrary.backupRootURL(),
                containerResolver: { bundleID in
                    guard let root = roots[bundleID] else {
                        throw PatchPackageError.targetAppUnavailable(bundleID)
                    }
                    return root
                },
                requestAccess: { _ = wq_grant($0.path) }
            )
        }
    }

    static func restore(receipt: PatchTransactionReceipt) throws {
        // Restoring original files should be allowed even when the license is not valid,
        // so do not require LicenseGateStore.isValid() here.
        let bundleIDs = try PatchTransaction.requiredBundleIdentifiers(for: receipt)
        try withResolvedContainers(bundleIDs: bundleIDs) { roots in
            try PatchTransaction.restore(
                receipt: receipt,
                containerResolver: { bundleID in
                    guard let root = roots[bundleID] else {
                        throw PatchPackageError.targetAppUnavailable(bundleID)
                    }
                    return root
                },
                requestAccess: { _ = wq_grant($0.path) }
            )
        }
    }

    static func latestReceipt(projectID: UUID) -> PatchTransactionReceipt? {
        guard let backupRoot = try? PatchProjectLibrary.backupRootURL() else { return nil }
        return PatchTransaction.latestReceipt(projectID: projectID, backupRoot: backupRoot)
    }

    private static func orderedBundleIdentifiers(in project: PatchProject) -> [String] {
        project.allBundleIdentifiers
    }

    private static func withResolvedContainers<T>(
        bundleIDs: [String],
        operation: ([String: URL]) throws -> T
    ) throws -> T {
        var roots: [String: URL] = [:]
        let launchServicesPaths = wq_ls_container_paths(nil) ?? []
        var fallbackPaths: [String]?

        for bundleID in bundleIDs {
            var root = resolveAppContainer(
                bundleID: bundleID,
                paths: launchServicesPaths
            )
            if root == nil {
                if fallbackPaths == nil {
                    fallbackPaths = appDataContainerPaths()
                }
                root = resolveAppContainer(
                    bundleID: bundleID,
                    paths: fallbackPaths ?? []
                )
            }
            guard let root else {
                throw PatchPackageError.targetAppUnavailable(bundleID)
            }
            roots[bundleID] = root
        }
        return try operation(roots)
    }

    private static func appDataContainerPaths() -> [String] {
        let applicationDataRoot = "/private/var/mobile/Containers/Data/Application"
        let listedNames = wq_list(applicationDataRoot, nil) ?? []
        if !listedNames.isEmpty {
            return listedNames.map { name in
                name.hasPrefix("/")
                    ? name
                    : (applicationDataRoot as NSString).appendingPathComponent(name)
            }
        }
        return wq_enumerate(applicationDataRoot, 0, nil, nil) ?? []
    }

    private static func resolveAppContainer(bundleID: String, paths: [String]) -> URL? {
        guard (try? PatchPathValidator.canonicalBundleIdentifier(bundleID)) == bundleID else {
            return nil
        }

        let applicationDataRoot = "/private/var/mobile/Containers/Data/Application"
        for path in paths {
            let root = PatchPathValidator.canonicalFileURL(
                URL(fileURLWithPath: path, isDirectory: true)
            )
            guard root.deletingLastPathComponent().path == applicationDataRoot,
                                    UUID(uuidString: root.lastPathComponent) != nil else {
                continue
            }

            _ = wq_grant(root.path)
            var fileStatus = stat()
            guard wq_stat(root.path, &fileStatus),
                                    fileStatus.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) else {
                continue
            }

            if let containerLabel = wq_container_label(root.path) {
                guard containerLabel == bundleID else { continue }
                return root
            }
            guard wq_bundle_id_for_container(root.path) == bundleID else { continue }
            return root
        }
        return nil
    }

    // Deactivate (restore) all applied patches found in the backups directory.
    static func deactivateAllActivePatches() async {
        guard let backupRoot = try? PatchProjectLibrary.backupRootURL() else { return }
        let fileManager = FileManager.default
        guard let projectDirs = try? fileManager.contentsOfDirectory(at: backupRoot, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else { return }

        for dir in projectDirs {
            let idString = dir.lastPathComponent
            guard let projectID = UUID(uuidString: idString) else { continue }
            if let receipt = latestReceipt(projectID: projectID) {
                do {
                    try restore(receipt: receipt)
                    print("[Patch] auto-restore succeeded for project: \(projectID)")
                } catch {
                    print("[Patch] auto-restore failed for project: \(projectID) -> \(error)")
                }
            }
        }
    }
}
