import Foundation

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
                }
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
                }
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

        for bundleID in bundleIDs {
            guard let path = ContainerStore.resolveAppContainerPath(bundleID: bundleID),
                  ContainerStore.isApplicationContainerPath(path) else {
                throw PatchPackageError.targetAppUnavailable(bundleID)
            }
            roots[bundleID] = PatchPathValidator.canonicalFileURL(URL(fileURLWithPath: path, isDirectory: true))
        }
        return try operation(roots)
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
