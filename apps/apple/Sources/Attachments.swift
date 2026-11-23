import SwiftUI
import CryptoKit
import AVKit
import ImageIO
import UniformTypeIdentifiers

/// End-to-end encrypted attachments for chat (files, photos, videos, audio) and shared songs.
///
/// Files never touch the server in the clear. Encryption is Signal's attachment scheme, done in
/// the shared Rust core (`encryptAttachment` / `decryptAttachment`): a fresh random key per file,
/// AES-256-CBC + HMAC-SHA256, the plaintext padded to size buckets so the blob length hides the
/// real size, and a SHA-256 digest of the ciphertext. Only ciphertext goes to the blob store
/// (`/api/blobs`, a resumable chunked upload). The key, digest and blob id travel INSIDE the chat
/// message body — itself E2EE via libsignal — so the server cannot read or swap the file.
/// Shared songs are Apple Music references (no file), rendered with the existing MusicCard player.

// MARK: - Wire format

/// Body prefixes for special chat messages (same \u{2} scheme as the feed, but these SHOW in chat).
enum ChatTags {
    static let attach = "\u{2}skwod/attach|"
    static let music = "\u{2}skwod/music|"

    /// Split a raw decrypted body into its renderable parts.
    static func parse(_ body: String) -> (text: String, attachment: ChatAttachment?, music: MusicTrack?) {
        if body.hasPrefix(attach), let data = String(body.dropFirst(attach.count)).data(using: .utf8),
           let a = try? JSONDecoder().decode(ChatAttachment.self, from: data) {
            return (a.caption ?? "", a, nil)
        }
        if body.hasPrefix(music), let data = String(body.dropFirst(music.count)).data(using: .utf8),
           let t = try? JSONDecoder().decode(MusicTrack.self, from: data) {
            return ("", nil, t)
        }
        return (body, nil, nil)
    }
}

// MARK: - Crypto

enum AttachmentError: LocalizedError {
    case tooLarge, unreadable, upload, download, crypto, notSignedIn
    /// The server refused the upload and said why, in a sentence meant for the user
    /// (no space joined yet, storage quota reached, the host's disk is nearly full).
    case refused(String)
    /// The descriptor declares — or the server started sending — more than this app will fetch.
    case oversized
    /// The server would not hand the file over (403/404: not linked to a message this account
    /// can read, or already deleted).
    case unavailable
    var errorDescription: String? {
        switch self {
        case .refused(let sentence): return sentence
        case .oversized: return "That file is larger than this app will download (max \(UploadLimit.label(Int64(AttachmentLimits.hardCap))))."
        case .unavailable: return "This file isn't available to you any more — it was deleted, or it was sent by an older app version that didn't share it."
        case .tooLarge: return UploadLimit.tooLargeSentence(limit: UploadLimit.current)
        case .unreadable: return "Couldn't read the file."
        case .upload: return "Upload failed — check your connection."
        case .download: return "Download failed — check your connection."
        case .crypto: return "Couldn't decrypt the file."
        case .notSignedIn: return "Not signed in."
        }
    }
}

enum AttachmentCrypto {
    static func seal(_ data: Data) throws -> (ciphertext: Data, keyB64: String, digestB64: String) {
        guard let enc = try? encryptAttachment(plaintext: data) else { throw AttachmentError.crypto }
        return (enc.ciphertext, enc.key.base64EncodedString(), enc.digest.base64EncodedString())
    }

    static func open(_ ciphertext: Data, attachment a: ChatAttachment) throws -> Data {
        guard let key = Data(base64Encoded: a.keyB64) else { throw AttachmentError.crypto }
        if let digestB64 = a.digestB64 {
            guard let digest = Data(base64Encoded: digestB64), a.size >= 0,
                  let plain = try? decryptAttachment(ciphertext: ciphertext, key: key, digest: digest,
                                                     plaintextLen: UInt64(a.size))
            else { throw AttachmentError.crypto }
            return plain
        }
        // Attachment from a pre-libsignal build (≤ 40): single-shot AES-256-GCM. Read-only path.
        let box = try AES.GCM.SealedBox(combined: ciphertext)
        return try AES.GCM.open(box, using: SymmetricKey(data: key))
    }
}

// MARK: - Blob transport

/// Thin client for the server's resumable blob store. Content is opaque ciphertext to the server;
/// a blob id is a random capability, so possession of the id alone yields only ciphertext.
struct BlobStore {
    let base: URL
    let token: String

    @MainActor
    init?(app: AppState) {
        guard let token = app.session?.token, let url = URL(string: app.serverURL), !app.serverURL.isEmpty else { return nil }
        self.base = url
        self.token = token
    }

    private func request(_ path: String, method: String) -> URLRequest {
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        return req
    }

    /// Create a blob and upload it in chunks. `tokenHash` (DM attachments only) registers the
    /// hash of a download token with the blob; the token itself only ever travels inside the
    /// encrypted message.
    ///
    /// `progress` is told how much of the ciphertext has left this device, 0…1, as the bytes
    /// go out (the system's own count of what it has written to the connection).
    func upload(_ data: Data, tokenHash: String? = nil, progress: Progress? = nil) async throws -> String {
        var create = request("api/blobs", method: "POST")
        create.setValue("application/json", forHTTPHeaderField: "Content-Type")
        var fields: [String: Any] = ["total_size": data.count]
        if let tokenHash { fields["download_token_hash"] = tokenHash }
        create.httpBody = try JSONSerialization.data(withJSONObject: fields)
        let body: Data, resp: URLResponse
        do { (body, resp) = try await URLSession.shared.data(for: create) } catch { throw AttachmentError.upload }
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200,
              let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let blobId = obj["blob_id"] as? String else { throw Self.uploadError(status: status, body: body) }

        // 1.5 MB chunks: the server's MAX_CHUNK is 16 MiB, but axum's request-body limit on
        // already-deployed servers is 2 MB — stay under it so uploads work against every host.
        let chunk = 1_500_000
        var offset = 0
        while offset < data.count {
            let end = min(offset + chunk, data.count)
            var patch = request("api/blobs/\(blobId)", method: "PATCH")
            patch.setValue("\(offset)", forHTTPHeaderField: "Upload-Offset")
            patch.setValue("application/offset+octet-stream", forHTTPHeaderField: "Content-Type")
            let piece = data.subdata(in: offset..<end)
            let meter = progress.map { UploadMeter(base: offset, total: data.count, report: $0) }
            let pbody: Data, presp: URLResponse
            do { (pbody, presp) = try await URLSession.shared.upload(for: patch, from: piece, delegate: meter) } catch { throw AttachmentError.upload }
            let pstatus = (presp as? HTTPURLResponse)?.statusCode ?? 0
            guard pstatus == 204 else { throw Self.uploadError(status: pstatus, body: pbody) }
            offset = end
            progress?(Double(offset) / Double(max(data.count, 1)))
        }
        return blobId
    }

    /// The most that is reported for bytes still on their way (the rest is the host confirming).
    static let inFlightCeiling = 0.97

    /// How much of an upload has gone out, 0…1. Called off the main actor.
    typealias Progress = @Sendable (Double) -> Void

    /// Counts the bytes of ONE chunk request as the system sends them.
    private final class UploadMeter: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        let base: Int, total: Int, report: Progress
        init(base: Int, total: Int, report: @escaping Progress) { self.base = base; self.total = total; self.report = report }
        func urlSession(_ session: URLSession, task: URLSessionTask, didSendBodyData bytesSent: Int64,
                        totalBytesSent: Int64, totalBytesExpectedToSend: Int64) {
            // Bytes the system has written — on a p2p skwod, to the local proxy, not yet to
            // the host. So never the full amount: that is only said once the host has
            // answered for the chunk (`upload`, after the 204).
            report(min(BlobStore.inFlightCeiling, Double(base + Int(totalBytesSent)) / Double(max(total, 1))))
        }
    }

    enum MusicPreviewError: Error { case hostTooOld, refused, failed }

    /// A story song's preview, fetched FOR this device by its host (`POST /api/music/preview`):
    /// the app never asks Apple itself. The URL goes in the body, so it is in no access log.
    func musicPreview(_ url: URL) async throws -> Data {
        var req = request("api/music/preview", method: "POST")
        req.timeoutInterval = 25
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["url": url.absoluteString])
        let stream: URLSession.AsyncBytes, resp: URLResponse
        do { (stream, resp) = try await URLSession.shared.bytes(for: req) } catch { throw MusicPreviewError.failed }
        switch (resp as? HTTPURLResponse)?.statusCode ?? 0 {
        case 200: break
        case 404, 405: stream.task.cancel(); throw MusicPreviewError.hostTooOld   // a host older than build 45
        case 400, 403, 429: stream.task.cancel(); throw MusicPreviewError.refused
        default: stream.task.cancel(); throw MusicPreviewError.failed
        }
        guard (resp.mimeType ?? "").lowercased().hasPrefix("audio/") else { stream.task.cancel(); throw MusicPreviewError.failed }
        do { return try await AttachmentLimits.read(stream, limit: StoryMusicPolicy.maxPreviewBytes) }
        catch { stream.task.cancel(); throw MusicPreviewError.failed }
    }

    /// A song card's artwork, fetched for this device by its host (`POST /api/music/artwork`).
    func musicArtwork(_ url: URL) async throws -> Data {
        var req = request("api/music/artwork", method: "POST")
        req.timeoutInterval = 20
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: ["url": url.absoluteString])
        let stream: URLSession.AsyncBytes, resp: URLResponse
        do { (stream, resp) = try await URLSession.shared.bytes(for: req) } catch { throw MusicPreviewError.failed }
        guard (resp as? HTTPURLResponse)?.statusCode == 200, (resp.mimeType ?? "").lowercased().hasPrefix("image/") else {
            stream.task.cancel()
            throw MusicPreviewError.failed
        }
        do { return try await AttachmentLimits.read(stream, limit: StoryMusicPolicy.maxArtworkBytes) }
        catch { stream.task.cancel(); throw MusicPreviewError.failed }
    }

    /// `GET /api/instance/limits`: the largest file this skwod's host accepts.
    /// `.some(nil)`: the server does not know the question (older than build 45) — its limit is
    /// the old fixed 100 MB. `nil`: no answer at all (offline, signed out) — keep what is known.
    func uploadLimit() async -> Int64?? {
        var req = request("api/instance/limits", method: "GET")
        req.timeoutInterval = 8
        guard let (body, resp) = try? await URLSession.shared.data(for: req) else { return nil }
        switch (resp as? HTTPURLResponse)?.statusCode ?? 0 {
        case 200: return UploadLimit.parse(body).map { .some($0) }
        case 404, 405: return .some(nil)
        default: return nil
        }
    }

    /// What a refused upload means. 403 (no space joined), 413 (this account's storage quota)
    /// and 507 (the host's disk is nearly full) come with a sentence written for the user.
    static func uploadError(status: Int, body: Data) -> AttachmentError {
        let sentence = ((try? JSONSerialization.jsonObject(with: body)) as? [String: Any])?["error"] as? String
        switch status {
        case 403, 413, 507:
            if let sentence, !sentence.isEmpty, sentence.count < 300 {
                return .refused(sentence.prefix(1).uppercased() + sentence.dropFirst() + (sentence.hasSuffix(".") ? "" : "."))
            }
            return .refused(status == 403 ? "You can't upload files here yet — join a server first."
                            : status == 413 ? "You've reached your storage limit on this Skwod. Delete some attachments, or ask the host for more room."
                            : "The host's disk is nearly full, so it isn't accepting files right now. Tell the host.")
        case 429:
            return .refused("Too many uploads at once — wait a moment and try again.")
        default:
            return .upload
        }
    }

    /// Fetch a blob's ciphertext. With a download `token` (a DM attachment) the token IS the
    /// credential: it goes in `x-skwod-blob-token` and no session token is sent, so the server
    /// cannot tell which account fetched the file.
    ///
    /// `limit` bounds what is read: what a message DESCRIBES is chosen by its sender, so a
    /// download is never open-ended. A `Content-Length` above the limit is refused before a
    /// byte is read, and reading stops at the limit even if the header is missing or lies.
    func download(_ blobId: String, token downloadToken: String? = nil,
                  limit: Int = AttachmentLimits.ciphertextLimit(forPlaintext: AttachmentLimits.inMemoryCap)) async throws -> Data {
        // Into memory: bounded by a fixed constant, never by what a server says it allows.
        let limit = min(limit, AttachmentLimits.ciphertextLimit(forPlaintext: AttachmentLimits.inMemoryCap))
        var req = URLRequest(url: base.appendingPathComponent("api/blobs/\(blobId)"))
        req.httpMethod = "GET"
        if let downloadToken, !downloadToken.isEmpty {
            req.setValue(downloadToken, forHTTPHeaderField: "x-skwod-blob-token")
        } else {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        let stream: URLSession.AsyncBytes, resp: URLResponse
        do { (stream, resp) = try await URLSession.shared.bytes(for: req) } catch { throw AttachmentError.download }
        switch (resp as? HTTPURLResponse)?.statusCode ?? 0 {
        case 200: break
        case 403, 404: stream.task.cancel(); throw AttachmentError.unavailable
        default: stream.task.cancel(); throw AttachmentError.download
        }
        if resp.expectedContentLength > Int64(limit) {
            stream.task.cancel()
            throw AttachmentError.oversized
        }
        do {
            return try await AttachmentLimits.read(stream, limit: limit,
                                                   expected: resp.expectedContentLength > 0 ? Int(resp.expectedContentLength) : nil)
        } catch let error as AttachmentError {
            stream.task.cancel()   // nothing partial is kept: the bytes only ever lived in memory
            throw error
        } catch {
            stream.task.cancel()
            throw AttachmentError.download
        }
    }

    /// `download`, streamed into the file at `destination` instead of into memory: a large
    /// attachment never has to fit in RAM. The same bounds apply — a `Content-Length` above the
    /// limit is refused before a byte is read, and writing stops one byte past it. Nothing
    /// partial is left behind on failure.
    func download(_ blobId: String, token downloadToken: String? = nil, limit: Int, to destination: URL) async throws {
        var req = URLRequest(url: base.appendingPathComponent("api/blobs/\(blobId)"))
        req.httpMethod = "GET"
        if let downloadToken, !downloadToken.isEmpty {
            req.setValue(downloadToken, forHTTPHeaderField: "x-skwod-blob-token")
        } else {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        let stream: URLSession.AsyncBytes, resp: URLResponse
        do { (stream, resp) = try await URLSession.shared.bytes(for: req) } catch { throw AttachmentError.download }
        switch (resp as? HTTPURLResponse)?.statusCode ?? 0 {
        case 200: break
        case 403, 404: stream.task.cancel(); throw AttachmentError.unavailable
        default: stream.task.cancel(); throw AttachmentError.download
        }
        if resp.expectedContentLength > Int64(limit) {
            stream.task.cancel()
            throw AttachmentError.oversized
        }
        FileManager.default.createFile(atPath: destination.path, contents: nil, attributes: [.posixPermissions: 0o600])
        guard let handle = try? FileHandle(forWritingTo: destination) else { stream.task.cancel(); throw AttachmentError.download }
        do {
            try await AttachmentLimits.write(stream, limit: limit, to: handle)
            try handle.close()
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(at: destination)
            stream.task.cancel()
            throw (error as? AttachmentError) ?? AttachmentError.download
        }
    }

    /// Delete a blob this account uploaded (a DM attachment whose message was removed, or an
    /// upload whose message never went out). Best effort.
    func delete(_ blobId: String) async {
        _ = try? await URLSession.shared.data(for: request("api/blobs/\(blobId)", method: "DELETE"))
    }
}

// MARK: - Download bounds

/// How much this app will fetch for an attachment someone else described. The descriptor (name,
/// size, blob id) is written by the sender, and before these bounds any member could make every
/// viewer of a channel or feed download and decrypt an arbitrarily large blob.
enum AttachmentLimits {
    /// Nothing larger is ever downloaded: what this skwod's host allows per file
    /// (`UploadLimit`), and never less than the 100 MB every host allowed before that was a
    /// setting — lowering the limit must not lock members out of files that are already there.
    /// It bounds the STREAMED (file-to-file) path only.
    static var hardCap: Int { Int(UploadLimit.downloadCap(limit: UploadLimit.current)) }
    /// Nothing larger is ever held in memory, whatever the server reports as its limit.
    static var inMemoryCap: Int { Int(UploadLimit.inMemoryDownloadCap(limit: UploadLimit.current)) }
    /// Fetched without being asked only up to this size; anything larger waits for a tap.
    static let autoCap = 10 * 1024 * 1024

    /// Is the declared size something this app will fetch at all?
    static func acceptable(declaredSize: Int64) -> Bool {
        declaredSize >= 0 && declaredSize <= Int64(hardCap)
    }

    /// The most ciphertext a plaintext of `size` bytes can be: Signal's attachment padding
    /// rounds up to size buckets (at most ~5% more, at least 541 bytes), plus IV, block padding
    /// and MAC. A generous bound — it only has to rule out "much more than was declared".
    static func ciphertextLimit(forPlaintext size: Int) -> Int {
        Int(Double(max(size, 0)) * 1.1) + 4096
    }

    enum Surface { case feed, chat }

    /// May this attachment be fetched without the user asking?
    ///
    /// - Feed: never. A fetch is made with the session credential, so fetching what scrolls
    ///   into view would tell the host who looked at which post and when.
    /// - Chat: only pictures, only up to the small cap, and not on a metered or Low Data
    ///   connection. (The chat views here fetch on tap anyway; this is the rule any automatic
    ///   loading has to pass.)
    /// Everything else is tap-to-download and shows its size.
    static func mayAutoDownload(kind: ChatAttachment.Kind, declaredSize: Int64, surface: Surface, expensiveNetwork: Bool) -> Bool {
        guard kind == .image, declaredSize >= 0, declaredSize <= Int64(autoCap) else { return false }
        switch surface {
        case .feed: return false
        case .chat: return !expensiveNetwork
        }
    }

    /// Write a byte stream to `handle` in 256 KB pieces, but never more than `limit` bytes:
    /// one byte past it throws `.oversized`.
    static func write<S: AsyncSequence>(_ stream: S, limit: Int, to handle: FileHandle) async throws where S.Element == UInt8 {
        var buffer = [UInt8]()
        buffer.reserveCapacity(256 * 1024)
        var total = 0
        for try await byte in stream {
            total += 1
            if total > limit { throw AttachmentError.oversized }
            buffer.append(byte)
            if buffer.count == 256 * 1024 {
                try handle.write(contentsOf: buffer)
                buffer.removeAll(keepingCapacity: true)
            }
        }
        if !buffer.isEmpty { try handle.write(contentsOf: buffer) }
    }

    /// Read a byte stream into memory, but never more than `limit` bytes: one byte past it
    /// throws `.oversized`, whatever the sender or the server claimed about the length.
    static func read<S: AsyncSequence>(_ stream: S, limit: Int, expected: Int? = nil) async throws -> Data where S.Element == UInt8 {
        var data = Data()
        data.reserveCapacity(min(expected ?? 64 * 1024, limit))
        var buffer = [UInt8]()
        buffer.reserveCapacity(64 * 1024)
        var total = 0
        for try await byte in stream {
            total += 1
            if total > limit { throw AttachmentError.oversized }
            buffer.append(byte)
            if buffer.count == 64 * 1024 {
                data.append(contentsOf: buffer)
                buffer.removeAll(keepingCapacity: true)
            }
        }
        data.append(contentsOf: buffer)
        return data
    }
}

// MARK: - Service

enum AttachmentService {
    /// The largest file this skwod's host accepts (`UploadLimit`, read from the server). Checked
    /// here before anything is encrypted; the server enforces it regardless.
    static var maxBytes: Int { Int(UploadLimit.current) }
    /// The same, for a file that is encrypted in one piece in memory (the feed's photos).
    static var inMemoryMaxBytes: Int { Int(min(UploadLimit.current, UploadLimit.inMemoryBytes)) }

    static func kind(for type: UTType?) -> ChatAttachment.Kind {
        guard let type else { return .file }
        if type.conforms(to: .image) { return .image }
        if type.conforms(to: .movie) || type.conforms(to: .video) { return .video }
        if type.conforms(to: .audio) { return .audio }
        return .file
    }

    /// Something ready to send: the tagged message body, and the blobs it refers to. A CHANNEL
    /// message must be sent with those ids (`sendChannelMessageWith(…blobIds:)`) so the server
    /// links them to the message — that link is what lets the other members download them.
    struct Outgoing {
        var body: String
        var blobIds: [String] = []
        var attachment: ChatAttachment? = nil
    }

    /// Where an attachment is going. It decides how the recipients get access to the blob.
    enum Destination {
        /// A channel message: access comes from the blob being linked to the message.
        case channel
        /// A direct message: access comes from a download token inside the descriptor.
        case directMessage
    }

    /// Seal `data`, upload it and build the descriptor.
    private static func seal(_ data: Data, name: String, mime: String, kind: ChatAttachment.Kind, thumb: Data?,
                             to destination: Destination, store: BlobStore, progress: BlobStore.Progress? = nil) async throws -> Outgoing {
        let (ciphertext, keyB64, digestB64) = try AttachmentCrypto.seal(data)
        var downloadToken: BlobDownloadToken?
        if case .directMessage = destination { downloadToken = newBlobDownloadToken() }
        let blobId = try await store.upload(ciphertext, tokenHash: downloadToken?.hashHex, progress: progress)
        let payload = ChatAttachment(name: name, mime: mime, size: Int64(data.count), kind: kind, blobId: blobId,
                                     keyB64: keyB64, digestB64: digestB64, thumbB64: thumb?.base64EncodedString(),
                                     caption: nil, token: downloadToken?.token)
        guard let json = String(data: try JSONEncoder().encode(payload), encoding: .utf8) else {
            throw AttachmentError.upload
        }
        return Outgoing(body: ChatTags.attach + json, blobIds: [blobId], attachment: payload)
    }

    /// Encrypt + upload a picked file, returning the tagged message body to send over E2EE chat.
    static func uploadFile(at url: URL, to destination: Destination, store: BlobStore) async throws -> Outgoing {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard var data = try? Data(contentsOf: url) else { throw AttachmentError.unreadable }
        guard data.count <= inMemoryMaxBytes else { throw AttachmentError.tooLarge }

        var type = UTType(filenameExtension: url.pathExtension)
        var name = url.lastPathComponent
        let k = kind(for: type)
        if k == .image {
            // A photo leaves this device as pixels only: no GPS position, camera model or capture
            // time (see `SafeImage.stripped`). HEIC/TIFF/RAW become JPEG, so the name follows.
            // An animated image is sent as it is (re-encoding would freeze it).
            if let clean = SafeImage.stripped(data) {
                data = clean.data
                if clean.type != type {
                    type = clean.type
                    name = (name as NSString).deletingPathExtension + "." + (clean.type.preferredFilenameExtension ?? "jpg")
                }
            } else if SafeImage.hasPrivateMetadata(data) {
                // Not re-encodable AND carrying location/camera data: refuse rather than leak it.
                throw AttachmentError.unreadable
            }
        }
        var thumb: Data?
        switch k {
        case .image: thumb = FeedMedia.downscaledJPEG(data, maxDimension: 480, quality: 0.4)
        case .video: thumb = await videoThumb(url)
        case .audio: thumb = await audioArtwork(url)   // embedded cover art, if any
        default: break
        }

        return try await seal(data, name: name, mime: type?.preferredMIMEType ?? "application/octet-stream",
                              kind: k, thumb: thumb, to: destination, store: store)
    }

    /// Encrypt + upload raw image data (from the camera or photo library, which give bytes not a
    /// file URL) and return the tagged E2EE message body. Same envelope as `uploadFile`, with a
    /// downscaled thumbnail for the inline preview.
    static func uploadImage(_ picked: Data, to destination: Destination, store: BlobStore,
                            thumbEdge: Int = 480, progress: BlobStore.Progress? = nil) async throws -> Outgoing {
        guard picked.count <= inMemoryMaxBytes else { throw AttachmentError.tooLarge }
        // The photo library hands over the original file, EXIF and GPS included: send pixels only.
        guard let clean = SafeImage.stripped(picked) else { throw AttachmentError.unreadable }
        let data = clean.data
        let ext = clean.type.preferredFilenameExtension ?? "jpg"
        let thumb = FeedMedia.downscaledJPEG(data, maxDimension: thumbEdge, quality: 0.4)
        return try await seal(data, name: "photo-\(Int(Date().timeIntervalSince1970)).\(ext)",
                              mime: clean.type.preferredMIMEType ?? "image/jpeg", kind: .image, thumb: thumb,
                              to: destination, store: store, progress: progress)
    }

    /// The tagged body for sharing an Apple Music song in chat.
    static func musicBody(_ track: MusicTrack) throws -> Outgoing {
        guard let json = String(data: try JSONEncoder().encode(track), encoding: .utf8) else {
            throw AttachmentError.upload
        }
        return Outgoing(body: ChatTags.music + json)
    }

    /// Download + decrypt an attachment into a cached temp file (named so players/openers can
    /// sniff the type). Idempotent per blob.
    static func localFile(for a: ChatAttachment, store: BlobStore) async throws -> URL {
        // Short-lived, backup-excluded, file-protected — see `AttachmentCache`.
        let dir = AttachmentCache.prepared()
        AttachmentCache.purgeExpired()
        // `blobId` and `name` come from the sender. Never let them shape the path: a name like
        // "../../x" would otherwise write the decrypted bytes outside this directory.
        guard isSafeBlobId(a.blobId) else { throw AttachmentError.download }
        // The size is the sender's claim. One this app would never fetch is refused before
        // anything is requested…
        guard AttachmentLimits.acceptable(declaredSize: a.size) else { throw AttachmentError.oversized }
        // The cached copy is found again only by a message that names the SAME content (digest
        // and key), not merely the same blob id and name (`AttachmentCacheName`).
        let dest = dir.appendingPathComponent(AttachmentCacheName.fileName(blobId: a.blobId, digestB64: a.digestB64, keyB64: a.keyB64,
                                                                           safeName: safeFileName(a.name)))
        if FileManager.default.fileExists(atPath: dest.path) { return dest }
        // …the download itself stops at what that claim allows (plus sealing overhead)…
        let limit = AttachmentLimits.ciphertextLimit(forPlaintext: Int(a.size))
        if let digestB64 = a.digestB64 {
            // Streamed: ciphertext to a file, then verified and decrypted file-to-file by the
            // core — nothing is written to `dest` unless the whole blob checks out against the
            // digest and key the message carries. Neither copy is ever held in memory whole.
            guard let key = Data(base64Encoded: a.keyB64), let digest = Data(base64Encoded: digestB64) else { throw AttachmentError.crypto }
            let sealed = dir.appendingPathComponent("\(a.blobId).part")
            let opened = dir.appendingPathComponent("\(a.blobId).open")
            defer {
                try? FileManager.default.removeItem(at: sealed)
                try? FileManager.default.removeItem(at: opened)
            }
            try await store.download(a.blobId, token: a.token, limit: limit, to: sealed)
            do {
                try decryptAttachmentFile(blobPath: sealed.path, outPath: opened.path, key: key, digest: digest, plaintextLen: UInt64(a.size))
            } catch {
                throw AttachmentError.crypto
            }
            try AttachmentCache.adopt(opened, as: dest)
            return dest
        }
        // An attachment from a pre-libsignal build (≤ 40): small, single-shot, in memory — so
        // bounded by the fixed in-memory cap, not by the host's (possibly much larger) limit.
        guard a.size <= Int64(AttachmentLimits.inMemoryCap) else { throw AttachmentError.oversized }
        let ciphertext = try await store.download(a.blobId, token: a.token, limit: limit)
        // …and what arrived is checked once more before any of it is decrypted.
        guard ciphertext.count <= limit else { throw AttachmentError.oversized }
        let plain = try AttachmentCrypto.open(ciphertext, attachment: a)
        guard plain.count <= AttachmentLimits.inMemoryCap else { throw AttachmentError.oversized }
        // Players/openers need a real file; it is written with the strongest protection the
        // platform offers and does not outlive a day, a relaunch or a sign-out.
        try AttachmentCache.write(plain, to: dest)
        return dest
    }

    /// Blob ids are server-issued UUIDs; anything else is refused before it reaches a path or URL.
    static func isSafeBlobId(_ id: String) -> Bool {
        !id.isEmpty && id.count <= 64 && id.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics.contains($0) && $0.isASCII || $0 == "-"
        }
    }

    /// Reduce a sender-supplied file name to one harmless path component.
    static func safeFileName(_ name: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_. ()"))
        var cleaned = String(name.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" })
        while cleaned.hasPrefix(".") { cleaned.removeFirst() }
        if cleaned.isEmpty { cleaned = "file" }
        return String(cleaned.suffix(120))
    }

    /// A small JPEG poster frame for a video, for the in-chat preview.
    static func videoThumb(_ url: URL) async -> Data? {
        let gen = AVAssetImageGenerator(asset: AVURLAsset(url: url))
        gen.appliesPreferredTrackTransform = true
        gen.maximumSize = CGSize(width: 480, height: 480)
        guard let cg = try? await gen.image(at: CMTime(seconds: 0.5, preferredTimescale: 600)).image else { return nil }
        return jpeg(cg)
    }

    /// Embedded cover art from an audio file (ID3/MP4 metadata), downscaled to a JPEG thumbnail.
    /// Nil when the file has no artwork — the audio row then falls back to its music-note icon.
    static func audioArtwork(_ url: URL) async -> Data? {
        let asset = AVURLAsset(url: url)
        guard let items = try? await asset.load(.metadata) else { return nil }
        // Common + format-specific artwork keys across ID3, iTunes/MP4.
        for item in items {
            guard let key = item.commonKey?.rawValue, key == AVMetadataKey.commonKeyArtwork.rawValue else { continue }
            if let data = try? await item.load(.dataValue), let cg = SafeImage.decode(data, maxEdge: 480) {
                return jpeg(cg)
            }
        }
        return nil
    }

    /// Encode a CGImage to a downscaled JPEG (max 480px, quality 0.45).
    private static func jpeg(_ cg: CGImage) -> Data? {
        let maxDim: CGFloat = 480
        let w = CGFloat(cg.width), h = CGFloat(cg.height)
        let scale = min(1, maxDim / max(w, h))
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil) else { return nil }
        let opts: [CFString: Any] = [
            kCGImageDestinationLossyCompressionQuality: 0.45,
            kCGImageDestinationImageMaxPixelSize: Int(max(w, h) * scale),
        ]
        CGImageDestinationAddImage(dest, cg, opts as CFDictionary)
        guard CGImageDestinationFinalize(dest) else { return nil }
        return out as Data
    }

    static func formattedSize(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }
}

// MARK: - Rendering

/// Renders an attachment bubble in the message list by kind.
struct AttachmentView: View {
    let attachment: ChatAttachment

    var body: some View {
        switch attachment.kind {
        case .image: ImageAttachmentView(a: attachment)
        case .video: VideoAttachmentView(a: attachment)
        case .audio: AudioAttachmentView(a: attachment)
        case .file: FileAttachmentView(a: attachment)
        }
    }
}

/// Shared download state machine for the attachment views.
@MainActor
final class AttachmentLoader: ObservableObject {
    @Published var localURL: URL?
    @Published var busy = false
    @Published var error: String?

    func fetch(_ a: ChatAttachment, app: AppState) async {
        guard localURL == nil, !busy else { return }
        guard let store = BlobStore(app: app) else { error = AttachmentError.notSignedIn.errorDescription; return }
        busy = true
        defer { busy = false }
        do { localURL = try await AttachmentService.localFile(for: a, store: store) }
        catch { self.error = (error as? AttachmentError)?.errorDescription ?? "Couldn't fetch the file." }
    }
}

/// An encrypted image: instant thumbnail, tap to fetch + view the full-resolution original.
private struct ImageAttachmentView: View {
    let a: ChatAttachment
    @EnvironmentObject private var app: AppState
    @StateObject private var loader = AttachmentLoader()
    @State private var showFull = false

    var body: some View {
        Group {
            if let thumbB64 = a.thumbB64, let data = Data(base64Encoded: thumbB64), let img = Image(data: data) {
                Button {
                    showFull = true
                    Task { await loader.fetch(a, app: app) }
                } label: {
                    img.resizable().scaledToFill()
                        .frame(maxWidth: 340, maxHeight: 280)
                        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                        .overlay(alignment: .bottomTrailing) {
                            if loader.busy { ProgressView().controlSize(.small).padding(8) }
                        }
                }
                .buttonStyle(.plain)
            } else {
                FileAttachmentView(a: a)   // no preview — behave like a file
            }
        }
        .sheet(isPresented: $showFull) {
            DismissableSheet {
                FullImageView(a: a, loader: loader)
            }
        }
        #if DEBUG
        .onReceive(NotificationCenter.default.publisher(for: .skwodE2EShowAttachment)) { note in
            // `object`: the blob to open (nil = any), or "close".
            if note.object as? String == "close" { showFull = false; return }
            if let blob = note.object as? String, blob != a.blobId { return }
            showFull = true
            Task { await loader.fetch(a, app: app) }
        }
        #endif
    }
}

/// The full-size decrypted image with an export affordance.
private struct FullImageView: View {
    let a: ChatAttachment
    @ObservedObject var loader: AttachmentLoader
    @EnvironmentObject private var app: AppState

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            // Drawn from memory: only within the fixed in-memory bound, whatever the host's limit.
            if let url = loader.localURL, a.size <= Int64(AttachmentLimits.inMemoryCap),
               let data = try? Data(contentsOf: url), let img = Image(data: data) {
                img.resizable().scaledToFit()
            } else if let error = loader.error {
                Text(error).foregroundStyle(.orange)
            } else {
                ProgressView().tint(.white)
            }
        }
        .frame(minWidth: 480, minHeight: 380)
        .toolbar {
            if let url = loader.localURL {
                ToolbarItem(placement: .primaryAction) {
                    #if os(macOS)
                    Button { NSWorkspace.shared.activateFileViewerSelecting([url]) } label: {
                        Label("Show in Finder", systemImage: "folder")
                    }
                    #else
                    ShareLink(item: url) { Label("Share", systemImage: "square.and.arrow.up") }
                    #endif
                }
            }
        }
        .task { await loader.fetch(a, app: app) }
    }
}

/// An encrypted video: poster frame + play; downloads, decrypts, then plays inline with AVKit.
private struct VideoAttachmentView: View {
    let a: ChatAttachment
    @EnvironmentObject private var app: AppState
    @StateObject private var loader = AttachmentLoader()
    @State private var player: AVPlayer?

    var body: some View {
        Group {
            if let player {
                VideoPlayer(player: player)
                    .frame(width: 340, height: 220)
                    .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            } else {
                Button { Task { await start() } } label: {
                    ZStack {
                        poster
                        if loader.busy {
                            ProgressView().tint(.white)
                        } else {
                            Image(systemName: "play.circle.fill")
                                .font(.system(size: 44)).foregroundStyle(.white.opacity(0.9))
                                .shadow(radius: 6)
                        }
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .overlay(alignment: .bottomLeading) {
            if let error = loader.error {
                Text(error).font(.caption2).foregroundStyle(.orange).padding(6)
            }
        }
    }

    @ViewBuilder private var poster: some View {
        if let thumbB64 = a.thumbB64, let data = Data(base64Encoded: thumbB64), let img = Image(data: data) {
            img.resizable().scaledToFill()
                .frame(width: 340, height: 220)
                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        } else {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(.white.opacity(0.06))
                .frame(width: 340, height: 220)
                .overlay(Text(a.name).font(.caption).foregroundStyle(.white.opacity(0.5)).padding())
        }
    }

    private func start() async {
        await loader.fetch(a, app: app)
        if let url = loader.localURL {
            let p = AVPlayer(url: url)
            player = p
            p.play()
        }
    }
}

/// An encrypted audio file: name + play/pause with elapsed progress, decrypted then played locally.
private struct AudioAttachmentView: View {
    let a: ChatAttachment
    @EnvironmentObject private var app: AppState
    @StateObject private var loader = AttachmentLoader()
    @StateObject private var audio = AudioClipPlayer()

    var body: some View {
        HStack(spacing: 12) {
            Button { Task { await toggle() } } label: {
                if loader.busy {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: audio.playing ? "pause.circle.fill" : "play.circle.fill")
                        .font(.system(size: 34)).foregroundStyle(.skAccent)
                }
            }
            .buttonStyle(.plain)
            // Embedded cover art, if the file carried any (else the play button stands alone).
            if let thumbB64 = a.thumbB64, let data = Data(base64Encoded: thumbB64), let img = Image(data: data) {
                img.resizable().scaledToFill()
                    .frame(width: 44, height: 44)
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(a.name).font(.subheadline.weight(.semibold)).foregroundStyle(.white).lineLimit(1)
                if audio.duration > 0 {
                    ProgressView(value: min(audio.progress, 1))
                        .tint(.skAccent)
                } else {
                    Text(AttachmentService.formattedSize(a.size))
                        .font(.caption).foregroundStyle(.white.opacity(0.5))
                }
                if let error = loader.error {
                    Text(error).font(.caption2).foregroundStyle(.orange)
                }
            }
        }
        .padding(10)
        .frame(maxWidth: 340)
        .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.white.opacity(0.08), lineWidth: 1))
    }

    private func toggle() async {
        if audio.playing { audio.pause(); return }
        await loader.fetch(a, app: app)
        if let url = loader.localURL { audio.play(url) }
    }
}

/// Minimal local-file audio player with progress, for encrypted voice notes / songs sent as files.
@MainActor
private final class AudioClipPlayer: ObservableObject {
    @Published var playing = false
    @Published var progress: Double = 0
    @Published var duration: Double = 0
    private var player: AVPlayer?
    private var timeObserver: Any?
    private var endObserver: NSObjectProtocol?

    func play(_ url: URL) {
        if player == nil {
            let p = AVPlayer(url: url)
            player = p
            duration = p.currentItem?.asset.duration.seconds ?? 0
            timeObserver = p.addPeriodicTimeObserver(forInterval: CMTime(seconds: 0.25, preferredTimescale: 600), queue: .main) { [weak self] t in
                MainActor.assumeIsolated {
                    guard let self, self.duration > 0 else { return }
                    self.progress = t.seconds / self.duration
                }
            }
            endObserver = NotificationCenter.default.addObserver(
                forName: .AVPlayerItemDidPlayToEndTime, object: p.currentItem, queue: .main
            ) { [weak self] _ in MainActor.assumeIsolated { self?.reset() } }
        }
        player?.play()
        playing = true
    }

    func pause() {
        player?.pause()
        playing = false
    }

    private func reset() {
        playing = false
        progress = 0
        player?.seek(to: .zero)
    }
}

/// A generic encrypted file: icon + name + size, download once, then open/share.
private struct FileAttachmentView: View {
    let a: ChatAttachment
    @EnvironmentObject private var app: AppState
    @StateObject private var loader = AttachmentLoader()

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "doc.fill")
                .font(.system(size: 26)).foregroundStyle(.skAccent.opacity(0.8))
            VStack(alignment: .leading, spacing: 2) {
                Text(a.name).font(.subheadline.weight(.semibold)).foregroundStyle(.white).lineLimit(1)
                Text(AttachmentService.formattedSize(a.size))
                    .font(.caption).foregroundStyle(.white.opacity(0.5))
                if let error = loader.error {
                    Text(error).font(.caption2).foregroundStyle(.orange)
                }
            }
            Spacer(minLength: 8)
            if loader.busy {
                ProgressView().controlSize(.small)
            } else if let url = loader.localURL {
                #if os(macOS)
                Button { NSWorkspace.shared.activateFileViewerSelecting([url]) } label: {
                    Image(systemName: "folder").font(.system(size: 17)).foregroundStyle(.white.opacity(0.75))
                }
                .buttonStyle(.plain).help("Show in Finder")
                #else
                ShareLink(item: url) {
                    Image(systemName: "square.and.arrow.up").font(.system(size: 17)).foregroundStyle(.white.opacity(0.75))
                }
                #endif
            } else {
                Button { Task { await loader.fetch(a, app: app) } } label: {
                    Image(systemName: "arrow.down.circle.fill").font(.system(size: 22)).foregroundStyle(.skAccent)
                }
                .buttonStyle(.plain).help("Download and decrypt")
            }
        }
        .padding(12)
        .frame(maxWidth: 340)
        .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.white.opacity(0.08), lineWidth: 1))
    }
}

/// Keeps `UploadLimit` in step with the skwod in front: asked when a skwod comes to the front,
/// on reconnect, and before a file is checked if the last answer is more than a minute old.
@MainActor
enum UploadLimitSync {
    private static var asked: (workspace: String, at: Date)?

    static func refresh(_ app: AppState, force: Bool = false) async {
        guard let workspace = app.current?.id else { return }
        UploadLimit.activate(workspace: workspace)
        if !force, let asked, asked.workspace == workspace, Date().timeIntervalSince(asked.at) < 60 { return }
        guard let store = BlobStore(app: app), let answer = await store.uploadLimit() else { return }
        asked = (workspace, Date())
        UploadLimit.learned(answer, workspace: workspace)
    }
}
