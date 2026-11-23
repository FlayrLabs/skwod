import SwiftUI

/// Licence + third-party acknowledgements. skwod links Signal's libsignal, which is AGPL-3.0-only;
/// the app is therefore distributed under the same licence and this screen tells the user where the
/// corresponding source is (AGPL §13 / GPL §6).
struct AcknowledgementsSheet: View {
    @Environment(\.dismiss) private var dismiss

    static let sourceURL = "https://github.com/FlayrLabs/skwod"

    private struct Entry: Identifiable {
        let id = UUID()
        let name: String
        let license: String
        let note: String
    }

    private let entries: [Entry] = [
        Entry(name: "libsignal (libsignal-protocol v0.108.0)",
              license: "AGPL-3.0-only · © Signal Messenger, LLC",
              note: "The Signal Protocol: PQXDH, Double Ratchet + SPQR, Sender Keys, Sealed Sender, safety numbers. github.com/signalapp/libsignal"),
        Entry(name: "SparsePostQuantumRatchet (spqr), libcrux-ml-kem",
              license: "AGPL-3.0-only (spqr) · Apache-2.0 (libcrux)",
              note: "Post-quantum ratchet and ML-KEM/Kyber used by libsignal."),
        Entry(name: "RustCrypto (aes, cbc, hmac, sha2, hkdf, chacha20poly1305, argon2), curve25519-dalek, ed25519-dalek",
              license: "MIT / Apache-2.0 / BSD-3-Clause",
              note: "Attachment encryption, key backup, metadata sealing, server identity."),
        Entry(name: "SQLCipher, OpenSSL",
              license: "BSD-3-Clause · Apache-2.0",
              note: "The encrypted on-device cache."),
        Entry(name: "Arti (Tor), rustls, tokio, reqwest, UniFFI",
              license: "MIT / Apache-2.0 / MPL-2.0",
              note: "Private address lookups, networking, Swift/Kotlin bindings."),
        Entry(name: "iroh",
              license: "MIT / Apache-2.0 · © n0, inc.",
              note: "The peer-to-peer transport: reaching a host by its key, hole punching, relays."),
        Entry(name: "LiveKit client SDK",
              license: "Apache-2.0",
              note: "Voice and video transport (media is end-to-end encrypted with keys Skwod generates)."),
    ]

    var body: some View {
        ZStack {
            SkwodBackground()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Licences").font(.title2.bold()).foregroundStyle(.white)
                    Text("Skwod is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License, version 3 only. It comes with NO WARRANTY. The complete corresponding source code for this app and the server is available at:")
                        .font(.subheadline).foregroundStyle(.white.opacity(0.7))
                    Text(Self.sourceURL)
                        .font(.system(.footnote, design: .monospaced)).foregroundStyle(.skAccent)
                        .textSelection(.enabled)
                    Text("Skwod is not affiliated with or endorsed by Signal Messenger, LLC. “Signal” is their trademark; Skwod uses their open-source protocol library.")
                        .font(.caption).foregroundStyle(.white.opacity(0.5))
                    Divider().overlay(.white.opacity(0.1))
                    Text("Third-party software").font(.headline).foregroundStyle(.white)
                    ForEach(entries) { e in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(e.name).font(.subheadline.weight(.semibold)).foregroundStyle(.white)
                            Text(e.license).font(.caption).foregroundStyle(.skAccent)
                            Text(e.note).font(.caption).foregroundStyle(.white.opacity(0.55))
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Text("Full licence texts ship with the source (LICENSE, THIRD-PARTY-NOTICES.md).")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45))
                    Button("Done") { dismiss() }
                        .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                        .frame(maxWidth: .infinity)
                }
                .padding(24)
            }
        }
        .frame(minWidth: 380, maxWidth: 520, minHeight: 420)
    }
}
