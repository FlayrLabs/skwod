import SwiftUI
import UniformTypeIdentifiers

/// Attachments sent through the core's streamed, resumable uploads (build 44b).
///
/// Nothing is read into memory whole: the picked file is encrypted file-to-file
/// (`prepareUpload`), the message that carries it is QUEUED naming the attachment by a
/// placeholder, and the outbox uploads the ciphertext in chunks, resuming from the server's
/// offset — after a lost connection, and after the app was killed (`resumeUploads` at launch and
/// on reconnect). The one exception is a photo: its metadata is stripped by re-encoding the
/// pixels, which needs the picture decoded (pictures are small next to what the cap allows).
enum StreamedUpload {
    enum Source {
        case file(URL)
        case image(Data)
    }

    enum Target {
        case channel(channelId: String)
        case dm(conversationId: String, peers: [String])
    }

    private static var root: URL { SharedContainer.privateURL.appendingPathComponent("skwod-uploads", isDirectory: true) }

    /// Where a workspace's CIPHERTEXT waits to be uploaded: its own directory under the app's
    /// Application Support, in no backup, removed with the workspace (`removeWork`). (Not
    /// `completeFileProtection`: an upload must be able to finish while the device is locked;
    /// what is in here is ciphertext under a key only the message carries.)
    static func workDirectory(forWorkspace id: String) -> URL {
        prepared(root.appendingPathComponent(safeComponent(id), isDirectory: true), protection: nil)
    }

    /// Where PLAINTEXT is staged for the moments between picking a file and encrypting it (a
    /// cleaned photo, a copy of a security-scoped file): a separate directory with complete
    /// file protection — unreadable while the device is locked — emptied as each file is
    /// encrypted, swept at every launch, and removed with the workspace.
    static func stagingDirectory(forWorkspace id: String) -> URL {
        #if os(iOS)
        let protection: FileProtectionType? = .complete
        #else
        let protection: FileProtectionType? = nil   // macOS: owner-only; at rest it is FileVault's
        #endif
        return prepared(workDirectory(forWorkspace: id).appendingPathComponent("staging", isDirectory: true), protection: protection)
    }

    private static func prepared(_ url: URL, protection: FileProtectionType?) -> URL {
        var dir = url
        var attributes: [FileAttributeKey: Any] = [.posixPermissions: 0o700]
        if let protection { attributes[.protectionKey] = protection }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: attributes)
        try? FileManager.default.setAttributes(attributes, ofItemAtPath: dir.path)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
        return dir
    }

    private static func safeComponent(_ id: String) -> String {
        let cleaned = String(id.unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) || $0 == "-" })
        return cleaned.isEmpty ? "default" : String(cleaned.prefix(80))
    }

    /// At launch: no staged plaintext survives a relaunch (a crash or a kill between staging
    /// and encrypting would otherwise leave one behind), in any workspace — nor the `src-*`
    /// copies an earlier build kept beside the ciphertext.
    static func sweepStaged() {
        let fm = FileManager.default
        guard let workspaces = try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) else { return }
        for dir in workspaces {
            if dir.lastPathComponent.hasPrefix("src-") { try? fm.removeItem(at: dir); continue }
            try? fm.removeItem(at: dir.appendingPathComponent("staging", isDirectory: true))
            for file in (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] where file.lastPathComponent.hasPrefix("src-") {
                try? fm.removeItem(at: file)
            }
        }
    }

    /// Everything upload-related a workspace left on disk (erase, forget, factory reset).
    static func removeWork(forWorkspace id: String) {
        try? FileManager.default.removeItem(at: root.appendingPathComponent(safeComponent(id), isDirectory: true))
    }

    static func removeAllWork() { try? FileManager.default.removeItem(at: root) }

    /// Encrypt `source` to a file, build its descriptor and queue the message. Returns once
    /// the message is queued (it shows at once as "Sending…" with upload progress).
    /// `client` has the cache of `workspace` open: both were taken when the user sent it, and
    /// everything after goes through them alone.
    @MainActor
    static func queue(_ source: Source, to target: Target, through client: SkwodClient, workspace: String, app: AppState) async throws {
        let forDm: Bool = { if case .dm = target { return true } else { return false } }()
        // The host's per-file limit, as fresh as a minute: checked before anything is encrypted.
        await UploadLimitSync.refresh(app)
        let staged = try await stage(source, in: stagingDirectory(forWorkspace: workspace))
        defer { if staged.temporary { try? FileManager.default.removeItem(at: staged.url) } }
        let prepared: PreparedUpload
        do {
            prepared = try await client.prepareUpload(sourcePath: staged.url.path, workDir: workDirectory(forWorkspace: workspace).path, forDm: forDm)
        } catch {
            throw error
        }
        let descriptor = ChatAttachment(name: staged.name, mime: staged.mime, size: Int64(prepared.plaintextLen), kind: staged.kind,
                                        blobId: prepared.placeholderBlobId,
                                        keyB64: prepared.key.base64EncodedString(), digestB64: prepared.digest.base64EncodedString(),
                                        thumbB64: staged.thumb?.base64EncodedString(), caption: nil, token: prepared.downloadToken)
        guard let json = String(data: try JSONEncoder().encode(descriptor), encoding: .utf8) else {
            await client.releaseUpload(uploadId: prepared.uploadId, deleteBlob: true)
            throw AttachmentError.upload
        }
        do {
            switch target {
            case .channel(let channelId):
                _ = try await client.queueChannelMessage(channelId: channelId, text: ChatTags.attach + json, replyToId: nil,
                                                         blobIds: [], uploadIds: [prepared.uploadId])
            case .dm(let conversationId, let peers):
                _ = try await client.queueDm(conversationId: conversationId, peerUserIds: peers, text: ChatTags.attach + json,
                                             replyToId: nil, uploadIds: [prepared.uploadId])
            }
        } catch {
            // The message never made it into the queue: its ciphertext has no owner.
            await client.releaseUpload(uploadId: prepared.uploadId, deleteBlob: true)
            throw error
        }
        UploadProgressStore.shared.watch(app)
        Outbox.kick(app)
    }

    private struct Staged {
        var url: URL
        /// A copy this code made (a cleaned photo): removed once it has been encrypted.
        var temporary: Bool
        var name: String
        var mime: String
        var kind: ChatAttachment.Kind
        var thumb: Data?
    }

    /// The file to encrypt, and what the descriptor says about it. A file is used where it
    /// is; only a photo is rewritten (pixels only — no GPS position, camera model or time).
    private static func stage(_ source: Source, in staging: URL) async throws -> Staged {
        switch source {
        case .image(let picked):
            guard picked.count <= AttachmentService.maxBytes else { throw AttachmentError.tooLarge }
            guard let clean = SafeImage.stripped(picked) else { throw AttachmentError.unreadable }
            let ext = clean.type.preferredFilenameExtension ?? "jpg"
            let url = try writeTemporary(clean.data, ext: ext, in: staging)
            return Staged(url: url, temporary: true, name: "photo-\(Int(Date().timeIntervalSince1970)).\(ext)",
                          mime: clean.type.preferredMIMEType ?? "image/jpeg", kind: .image,
                          thumb: FeedMedia.downscaledJPEG(clean.data, maxDimension: 480, quality: 0.4))
        case .file(let url):
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize else { throw AttachmentError.unreadable }
            guard size <= AttachmentService.maxBytes else { throw AttachmentError.tooLarge }
            var type = UTType(filenameExtension: url.pathExtension)
            var name = url.lastPathComponent
            let kind = AttachmentService.kind(for: type)
            if kind == .image {
                guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { throw AttachmentError.unreadable }
                if let clean = SafeImage.stripped(data) {
                    if clean.type != type {
                        type = clean.type
                        name = (name as NSString).deletingPathExtension + "." + (clean.type.preferredFilenameExtension ?? "jpg")
                    }
                    let copy = try writeTemporary(clean.data, ext: clean.type.preferredFilenameExtension ?? "jpg", in: staging)
                    return Staged(url: copy, temporary: true, name: name, mime: type?.preferredMIMEType ?? "image/jpeg", kind: .image,
                                  thumb: FeedMedia.downscaledJPEG(clean.data, maxDimension: 480, quality: 0.4))
                } else if SafeImage.hasPrivateMetadata(data) {
                    // Not re-encodable AND carrying location/camera data: refuse rather than leak it.
                    throw AttachmentError.unreadable
                }
            }
            // The security scope ends when this function returns, and the encryption runs
            // after it: a scoped file (a document picker's) is copied — streamed, by the
            // system — into the work directory first. A plain path is used where it is.
            var staged = url
            var temporary = false
            if scoped {
                let copy = staging.appendingPathComponent("src-\(UUID().uuidString).\(url.pathExtension)")
                do { try FileManager.default.copyItem(at: url, to: copy) } catch { throw AttachmentError.unreadable }
                protect(copy)
                staged = copy
                temporary = true
            }
            var thumb: Data?
            switch kind {
            case .video: thumb = await AttachmentService.videoThumb(staged)
            case .audio: thumb = await AttachmentService.audioArtwork(staged)
            default: break
            }
            return Staged(url: staged, temporary: temporary, name: name, mime: type?.preferredMIMEType ?? "application/octet-stream",
                          kind: kind, thumb: thumb)
        }
    }

    private static func writeTemporary(_ data: Data, ext: String, in staging: URL) throws -> URL {
        let url = staging.appendingPathComponent("src-\(UUID().uuidString).\(ext)")
        do {
            #if os(iOS)
            try data.write(to: url, options: [.atomic, .completeFileProtection])
            #else
            try data.write(to: url, options: .atomic)
            #endif
        } catch { throw AttachmentError.unreadable }
        protect(url)
        return url
    }

    /// Owner-only, and (iOS) unreadable while the device is locked.
    private static func protect(_ url: URL) {
        var attributes: [FileAttributeKey: Any] = [.posixPermissions: 0o600]
        #if os(iOS)
        attributes[.protectionKey] = FileProtectionType.complete
        #endif
        try? FileManager.default.setAttributes(attributes, ofItemAtPath: url.path)
    }

    /// The upload a descriptor's blob id stands for while it has not been uploaded, if it is
    /// such a placeholder (`upload:<id>`, the core's format).
    static func uploadId(forPlaceholder blobId: String) -> String? {
        let prefix = "upload:"
        guard blobId.hasPrefix(prefix) else { return nil }
        let id = String(blobId.dropFirst(prefix.count))
        return id.isEmpty ? nil : id
    }

    /// "12.4 MB of 50 MB".
    static func progressText(sent: UInt64, total: UInt64) -> String {
        "\(AttachmentService.formattedSize(Int64(sent))) of \(AttachmentService.formattedSize(Int64(total)))"
    }
}

/// Upload progress for the bubbles: `pendingUploads()` polled about once a second while
/// anything is uploading, and not at all otherwise.
@MainActor
final class UploadProgressStore: ObservableObject {
    static let shared = UploadProgressStore()
    @Published private(set) var byUpload: [String: UploadProgress] = [:]
    private var task: Task<Void, Never>?

    /// Start (or keep) polling until nothing is pending.
    func watch(_ app: AppState) {
        guard task == nil else { return }
        task = Task { [weak self, weak app] in
            var idle = 0
            while let self, let app, !Task.isCancelled {
                let pending = await app.client?.pendingUploads() ?? []
                let next = Dictionary(uniqueKeysWithValues: pending.map { ($0.uploadId, $0) })
                if next != self.byUpload { self.byUpload = next }
                #if DEBUG
                E2E.sawUploads(pending)
                #endif
                idle = pending.contains(where: { !$0.done }) ? 0 : idle + 1
                if idle > 3 { break }
                try? await Task.sleep(for: .seconds(1))
            }
            self?.task = nil
        }
    }

    func progress(forPlaceholder blobId: String) -> UploadProgress? {
        StreamedUpload.uploadId(forPlaceholder: blobId).flatMap { byUpload[$0] }
    }
}

/// An attachment of mine that is still on its way up: what it is, and how far along.
struct UploadingAttachmentView: View {
    let attachment: ChatAttachment
    @ObservedObject private var uploads = UploadProgressStore.shared
    @EnvironmentObject private var app: AppState

    var body: some View {
        let progress = uploads.progress(forPlaceholder: attachment.blobId)
        HStack(spacing: 12) {
            if let thumbB64 = attachment.thumbB64, let data = Data(base64Encoded: thumbB64), let img = Image(data: data) {
                img.resizable().scaledToFill().frame(width: 44, height: 44)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            } else {
                Image(systemName: "arrow.up.doc.fill").font(.system(size: 26)).foregroundStyle(.skAccent.opacity(0.8))
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(attachment.name).font(.subheadline.weight(.semibold)).foregroundStyle(.white).lineLimit(1)
                if let progress, progress.total > 0 {
                    ProgressView(value: Double(min(progress.sent, progress.total)), total: Double(progress.total))
                        .tint(.skAccent)
                    Text("Uploading… " + StreamedUpload.progressText(sent: progress.sent, total: progress.total))
                        .font(.caption2).foregroundStyle(.white.opacity(0.55))
                } else {
                    ProgressView().progressViewStyle(.linear).tint(.skAccent)
                    Text("Waiting to upload · \(AttachmentService.formattedSize(attachment.size))")
                        .font(.caption2).foregroundStyle(.white.opacity(0.55))
                }
            }
        }
        .padding(12)
        .frame(maxWidth: 340)
        .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("attachment.uploading")
        .onAppear { uploads.watch(app) }
    }
}
