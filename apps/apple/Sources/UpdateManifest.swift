import CryptoKit
import Foundation

/// The signed statement inside the public release manifest (`manifest.json`), and the only
/// part of that file the iOS app believes.
///
/// The manifest is fetched from a public GitHub release. GitHub — or anyone who can write to
/// the release repository, or sit on the path to it — must not be able to tell the app that
/// an update exists, what it says, or WHICH TestFlight / App Store link to open: a look-alike
/// beta opened on the genuine app's say-so is a phishing tool. So the publisher signs a small
/// JSON statement (`tools/release/sign-manifest.sh`) with the Ed25519 update key and the app
/// reads the build number, version, notes and link from it, only after
///
///     signed_sig == Ed25519(publisher, "skwod-release-manifest-v1\n" || signed)
///
/// has verified over exactly the bytes that arrived. The unsigned `ios` object beside it is
/// what earlier builds read; this build never looks at it.
///
/// The key is the same one the Android updater pins (`Updater.kt`, `UPDATE_PUBLIC_KEY_B64`);
/// `package-release.sh` refuses to sign unless the key on disk matches both.
enum UpdateManifest {
    /// Ed25519 public key of the release publisher (raw 32 bytes, base64).
    static let publisherKeyB64 = "4Sh3oT9eIwxDNLwUYUnZbaGm2lt0jEnBT2EYzGx5pY8="
    static let label = "skwod-release-manifest-v1\n"
    /// A statement issued further in the future than this is refused (clock skew allowance).
    static let maxSkew: TimeInterval = 24 * 60 * 60
    static let maxStatementBytes = 16 * 1024

    struct IOSRelease: Equatable {
        let build: Int
        let version: String
        let notes: String
        /// An https link on testflight.apple.com or apps.apple.com, or nil.
        let link: URL?
        /// The statement is past its `expires`: genuine, but no proof of being the latest.
        let expired: Bool
    }

    enum Outcome: Equatable {
        /// Signed by the publisher. `ios` is nil when the statement has no iOS entry.
        case valid(ios: IOSRelease?, expired: Bool)
        /// No statement, a bad signature, malformed, or post-dated. Nothing in it is used.
        case invalid
    }

    /// Verify and read a manifest. Parsing happens after the signature check, never before.
    static func read(_ manifest: Data, publisherKeyB64: String = publisherKeyB64, now: Date = Date()) -> Outcome {
        guard let root = try? JSONSerialization.jsonObject(with: manifest) as? [String: Any],
              let signedB64 = root["signed"] as? String, let sigB64 = root["signed_sig"] as? String,
              let raw = Data(base64Encoded: signedB64), let sig = Data(base64Encoded: sigB64),
              !raw.isEmpty, raw.count <= maxStatementBytes, sig.count == 64,
              let keyBytes = Data(base64Encoded: publisherKeyB64),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyBytes),
              key.isValidSignature(sig, for: Data(label.utf8) + raw),
              let statement = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
              int(statement["v"]) == 1,
              let issued = int(statement["issued"]), let expires = int(statement["expires"]), issued < expires,
              TimeInterval(issued) <= now.timeIntervalSince1970 + maxSkew
        else { return .invalid }
        let expired = now.timeIntervalSince1970 >= TimeInterval(expires)
        guard let entry = statement["ios"] as? [String: Any], let build = int(entry["build"]) else {
            return .valid(ios: nil, expired: expired)
        }
        let release = IOSRelease(
            build: build,
            version: String((entry["version"] as? String ?? "\(build)").prefix(40)),
            notes: String((entry["notes"] as? String ?? "").prefix(500)),
            link: (entry["testflight"] as? String).flatMap(appleLink),
            expired: expired
        )
        return .valid(ios: release, expired: expired)
    }

    /// The only places an "update" button may lead: https on Apple's two hosts, default port,
    /// no credentials. Checked even for a signed link.
    static func appleLink(_ s: String) -> URL? {
        guard let comps = URLComponents(string: s), comps.scheme?.lowercased() == "https",
              let host = comps.host?.lowercased(), host == "testflight.apple.com" || host == "apps.apple.com",
              comps.port == nil || comps.port == 443, comps.user == nil, comps.password == nil,
              let url = comps.url else { return nil }
        return url
    }

    private static func int(_ v: Any?) -> Int? {
        // JSON numbers only (NSNumber bridges Bool too: refuse it).
        guard let n = v as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
        let d = n.doubleValue
        guard d == d.rounded(), abs(d) < 9e15 else { return nil }
        return n.intValue
    }
}
