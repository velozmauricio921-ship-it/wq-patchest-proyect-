import CommonCrypto
import CryptoKit
import Foundation
import UIKit

private struct WQ3105Envelope: Decodable {
    let schemaVersion: Int
    let keyAADVersion: Int?
    let packageID: UUID
    let isPasswordProtected: Bool
    let kdfSalt: Data?
    let kdfIterations: Int?
    let wrappedContentKey: Data?
    let publicContentKey: Data?
    let keyFingerprint: Data
    let encryptedPayload: Data
}

private struct WQ3105Payload: Decodable {
    let project: WQ3105Project
    let replacementDigests: [String: Data]
}

private struct WQ3105Project: Decodable {
    let id: UUID
    let name: String
    let author: String
    let isPrivate: Bool
    let createdAt: Date
    let updatedAt: Date
    let bundleIdentifiers: [String]
    let directories: [WQ3105Directory]
    let rules: [WQ3105Rule]

    var allBundleIdentifiers: [String] {
        var seen = Set<String>()
        return (bundleIdentifiers + directories.map(\.bundleID) + rules.map(\.bundleID))
            .filter { seen.insert($0).inserted }
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, author, isPrivate, createdAt, updatedAt, bundleIdentifiers, directories, rules
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        author = try container.decodeIfPresent(String.self, forKey: .author) ?? ""
        isPrivate = try container.decodeIfPresent(Bool.self, forKey: .isPrivate) ?? false
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        updatedAt = try container.decode(Date.self, forKey: .updatedAt)
        bundleIdentifiers = try container.decodeIfPresent([String].self, forKey: .bundleIdentifiers) ?? []
        directories = try container.decodeIfPresent([WQ3105Directory].self, forKey: .directories) ?? []
        rules = try container.decode([WQ3105Rule].self, forKey: .rules)
    }
}

private struct WQ3105Directory: Decodable {
    let id: UUID
    let bundleID: String
    let relativePath: String
}

private struct WQ3105Rule: Decodable {
    let id: UUID
    let bundleID: String
    let relativePath: String
    let replacementFilename: String
    let replacementData: Data
}

private enum WQ3105ReaderError: LocalizedError {
    case unsupportedFormat
    case unsupportedVersion
    case invalidPackage
    case passwordRequired
    case invalidPassword

    var errorDescription: String? {
        switch self {
        case .unsupportedFormat: return "This is not a 3105 patch package."
        case .unsupportedVersion: return "This 3105 package version is not supported."
        case .invalidPackage: return "The 3105 package is invalid or corrupted."
        case .passwordRequired: return "This package requires a password."
        case .invalidPassword: return "The password is incorrect or the package is corrupted."
        }
    }
}

private struct WQ3105DecodedPackage {
    let envelope: WQ3105Envelope
    let project: WQ3105Project
}

private enum WQ3105PackageReader {
    private static let magic = Data("3105PATCH\0".utf8)
    private static let minimumVersion = 1
    private static let maximumVersion = 3
    private static let minimumKDFIterations = 100_000
    private static let maximumKDFIterations = 1_000_000
    private static let maximumPasswordBytes = 1_024

    static func inspect(_ data: Data) throws -> WQ3105Envelope {
        guard data.count > magic.count, data.prefix(magic.count) == magic else {
            throw WQ3105ReaderError.unsupportedFormat
        }
        let encodedEnvelope = Data(data.dropFirst(magic.count))
        let envelope: WQ3105Envelope
        do {
            envelope = try PropertyListDecoder().decode(WQ3105Envelope.self, from: encodedEnvelope)
        } catch {
            throw WQ3105ReaderError.invalidPackage
        }

        guard (minimumVersion...maximumVersion).contains(envelope.schemaVersion) else {
            throw WQ3105ReaderError.unsupportedVersion
        }
        guard envelope.keyFingerprint.count == 32, envelope.encryptedPayload.count >= 28 else {
            throw WQ3105ReaderError.invalidPackage
        }
        if envelope.isPasswordProtected {
            guard envelope.publicContentKey == nil,
                  (minimumVersion...maximumVersion).contains(envelope.keyAADVersion ?? envelope.schemaVersion),
                  envelope.kdfSalt?.count == 16,
                  let iterations = envelope.kdfIterations,
                  (minimumKDFIterations...maximumKDFIterations).contains(iterations),
                  envelope.wrappedContentKey != nil else {
                throw WQ3105ReaderError.invalidPackage
            }
        } else {
            guard envelope.kdfSalt == nil,
                  envelope.kdfIterations == nil,
                  envelope.wrappedContentKey == nil,
                  envelope.publicContentKey?.count == 32 else {
                throw WQ3105ReaderError.invalidPackage
            }
        }
        return envelope
    }

    static func decode(_ data: Data, password: String?) throws -> WQ3105DecodedPackage {
        let envelope = try inspect(data)
        let contentKey: Data
        if envelope.isPasswordProtected {
            guard let password, !password.isEmpty,
                  password.utf8.count <= maximumPasswordBytes,
                  let salt = envelope.kdfSalt,
                  let iterations = envelope.kdfIterations,
                  let wrappedKey = envelope.wrappedContentKey else {
                throw WQ3105ReaderError.passwordRequired
            }
            let wrappingKey = try deriveKey(password: password, salt: salt, iterations: iterations)
            do {
                contentKey = try open(
                    wrappedKey,
                    key: wrappingKey,
                    aad: keyAAD(for: envelope.packageID, version: envelope.keyAADVersion ?? envelope.schemaVersion)
                )
            } catch {
                throw WQ3105ReaderError.invalidPassword
            }
        } else if let publicKey = envelope.publicContentKey {
            contentKey = publicKey
        } else {
            throw WQ3105ReaderError.invalidPackage
        }

        guard Data(SHA256.hash(data: contentKey)) == envelope.keyFingerprint else {
            throw WQ3105ReaderError.invalidPassword
        }
        let plaintext: Data
        do {
            plaintext = try open(
                envelope.encryptedPayload,
                key: contentKey,
                aad: payloadAAD(for: envelope.packageID, version: envelope.schemaVersion)
            )
        } catch {
            throw WQ3105ReaderError.invalidPassword
        }

        let payload: WQ3105Payload
        do {
            payload = try PropertyListDecoder().decode(WQ3105Payload.self, from: plaintext)
        } catch {
            throw WQ3105ReaderError.invalidPackage
        }
        guard payload.project.id == envelope.packageID,
              !payload.project.isPrivate || (envelope.schemaVersion >= 3 && envelope.isPasswordProtected),
              payload.replacementDigests.count == payload.project.rules.count else {
            throw WQ3105ReaderError.invalidPackage
        }
        for rule in payload.project.rules {
            guard payload.replacementDigests[rule.id.uuidString] == Data(SHA256.hash(data: rule.replacementData)) else {
                throw WQ3105ReaderError.invalidPackage
            }
        }
        return WQ3105DecodedPackage(envelope: envelope, project: payload.project)
    }

    private static func deriveKey(password: String, salt: Data, iterations: Int) throws -> Data {
        let passwordData = Data(password.utf8)
        let outputLength = 32
        var output = Data(count: outputLength)
        let status = output.withUnsafeMutableBytes { outputBuffer in
            passwordData.withUnsafeBytes { passwordBuffer in
                salt.withUnsafeBytes { saltBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.bindMemory(to: Int8.self).baseAddress,
                        passwordData.count,
                        saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        outputBuffer.bindMemory(to: UInt8.self).baseAddress,
                        outputLength
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw WQ3105ReaderError.invalidPackage }
        return output
    }

    private static func open(_ ciphertext: Data, key: Data, aad: Data) throws -> Data {
        guard key.count == 32 else { throw WQ3105ReaderError.invalidPackage }
        let box = try AES.GCM.SealedBox(combined: ciphertext)
        return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }

    private static func keyAAD(for packageID: UUID, version: Int) -> Data {
        Data("3105PATCH/v\(version)/key/\(packageID.uuidString)".utf8)
    }

    private static func payloadAAD(for packageID: UUID, version: Int) -> Data {
        Data("3105PATCH/v\(version)/payload/\(packageID.uuidString)".utf8)
    }
}

private final class WQ3105PackageViewController: UITableViewController {
    private struct Row {
        let title: String
        let detail: String
    }

    private let path: String
    private var package: WQ3105DecodedPackage?
    private var status = "Reading package…"

    init(path: String) {
        self.path = path
        super.init(style: .insetGrouped)
        title = URL(fileURLWithPath: path).lastPathComponent
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        loadPackage(password: nil)
    }

    private func loadPackage(password: String?) {
        status = "Reading package…"
        tableView.reloadData()
        let packagePath = path
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let data = try Data(contentsOf: URL(fileURLWithPath: packagePath), options: .mappedIfSafe)
                let envelope = try WQ3105PackageReader.inspect(data)
                if envelope.isPasswordProtected && password == nil {
                    DispatchQueue.main.async { self?.askForPassword() }
                    return
                }
                let decoded = try WQ3105PackageReader.decode(data, password: password)
                DispatchQueue.main.async {
                    self?.package = decoded
                    self?.status = ""
                    self?.tableView.reloadData()
                }
            } catch let error as WQ3105ReaderError {
                DispatchQueue.main.async {
                    if case .invalidPassword = error {
                        self?.askForPassword(message: error.localizedDescription)
                    } else {
                        self?.status = error.localizedDescription
                        self?.tableView.reloadData()
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self?.status = error.localizedDescription
                    self?.tableView.reloadData()
                }
            }
        }
    }

    private func askForPassword(message: String? = nil) {
        let alert = UIAlertController(title: "Password Required", message: message ?? "Enter the package password.", preferredStyle: .alert)
        alert.addTextField { field in
            field.isSecureTextEntry = true
            field.autocapitalizationType = .none
            field.autocorrectionType = .no
        }
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { [weak self] _ in
            self?.status = "Password required to read this package."
            self?.tableView.reloadData()
        })
        alert.addAction(UIAlertAction(title: "Open", style: .default) { [weak self, weak alert] _ in
            guard let password = alert?.textFields?.first?.text, !password.isEmpty else {
                self?.askForPassword(message: "Enter a password to continue.")
                return
            }
            self?.loadPackage(password: password)
        })
        present(alert, animated: true)
    }

    private var sections: [(String, [Row])] {
        guard let package else { return [("", [Row(title: status, detail: "")])] }
        let project = package.project
        let formatter = DateFormatter.localizedString(from: project.createdAt, dateStyle: .medium, timeStyle: .short)
        let metadata = [
            Row(title: "Package", detail: project.name),
            Row(title: "Author", detail: project.author.isEmpty ? "-" : project.author),
            Row(title: "Package ID", detail: project.id.uuidString),
            Row(title: "Format Version", detail: "\(package.envelope.schemaVersion)"),
            Row(title: "Privacy", detail: project.isPrivate ? "Private" : "Public"),
            Row(title: "Created", detail: formatter),
            Row(title: "Password", detail: package.envelope.isPasswordProtected ? "Protected" : "Not protected")
        ]
        let bundles = project.allBundleIdentifiers.map { Row(title: $0, detail: "Application identifier") }
        let directories = project.directories.map {
            Row(title: $0.relativePath, detail: $0.bundleID)
        }
        let files = project.rules.map {
            Row(title: $0.replacementFilename,
                detail: "\($0.bundleID)/\($0.relativePath) · \(ByteCountFormatter.string(fromByteCount: Int64($0.replacementData.count), countStyle: .file))")
        }
        return [
            ("Package", metadata),
            ("Targets", bundles),
            ("Directories", directories),
            ("Files", files)
        ]
    }

    override func numberOfSections(in tableView: UITableView) -> Int { sections.count }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        sections[section].0
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        sections[section].1.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "3105-row")
            ?? UITableViewCell(style: .subtitle, reuseIdentifier: "3105-row")
        let row = sections[indexPath.section].1[indexPath.row]
        var content = UIListContentConfiguration.subtitleCell()
        content.text = row.title
        content.secondaryText = row.detail
        content.secondaryTextProperties.numberOfLines = 0
        cell.contentConfiguration = content
        cell.accessoryType = indexPath.section == 3 && package != nil ? .disclosureIndicator : .none
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard indexPath.section == 3,
              let rule = package?.project.rules[indexPath.row] else { return }
        navigationController?.pushViewController(
            WQ3105PayloadViewController(name: rule.replacementFilename, data: rule.replacementData),
            animated: true
        )
    }
}

private final class WQ3105PayloadViewController: UIViewController {
    private let name: String
    private let data: Data

    init(name: String, data: Data) {
        self.name = name
        self.data = data
        super.init(nibName: nil, bundle: nil)
        title = name
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        let textView = UITextView()
        textView.translatesAutoresizingMaskIntoConstraints = false
        textView.isEditable = false
        textView.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.text = displayText()
        view.addSubview(textView)
        NSLayoutConstraint.activate([
            textView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            textView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            textView.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            textView.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor)
        ])
    }

    private func displayText() -> String {
        if let text = String(data: data, encoding: .utf8), !text.contains("\0") { return text }
        var lines: [String] = []
        lines.reserveCapacity((data.count + 15) / 16)
        for start in stride(from: 0, to: data.count, by: 16) {
            let end = min(start + 16, data.count)
            let bytes = data[start..<end]
            let hex = bytes.map { String(format: "%02x", $0) }.joined(separator: " ")
            lines.append(String(format: "%08x  %@", start, hex))
        }
        return lines.joined(separator: "\n")
    }
}

@_cdecl("WQ3105MakePackageViewController")
public func WQ3105MakePackageViewController(_ path: UnsafePointer<CChar>) -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(WQ3105PackageViewController(path: String(cString: path))).toOpaque()
}