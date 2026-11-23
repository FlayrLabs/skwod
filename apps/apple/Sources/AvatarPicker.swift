import SwiftUI
import PhotosUI
import UniformTypeIdentifiers

/// A reusable "pick + preview + save" sheet for setting an avatar (profile pic, server icon, skwod
/// icon). The image is center-cropped to a square, encrypted, and broadcast by the caller's `onPick`
/// (the AvatarStore handles the E2EE + fan-out). A "Remove" action clears it.
struct AvatarPickerSheet: View {
    let title: String
    let currentKey: String?
    let name: String
    /// Called with the picked image data (already full-res; the store squares + compresses it).
    let onPick: (Data) async -> Void
    /// Called to clear the avatar (nil = no remove affordance shown).
    let onRemoveAction: (() async -> Void)?

    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var item: PhotosPickerItem?
    @State private var picked: Data?
    @State private var busy = false
    @State private var showFileImporter = false

    init(title: String, currentKey: String?, name: String,
         onPick: @escaping (Data) async -> Void, onRemove: (() async -> Void)? = nil) {
        self.title = title
        self.currentKey = currentKey
        self.name = name
        self.onPick = onPick
        self.onRemoveAction = onRemove
    }

    var body: some View {
        NavigationStack {
            ZStack {
                SkwodBackground()
                VStack(spacing: 22) {
                    // Live preview: the newly picked image, else the current avatar, else monogram.
                    Group {
                        if let picked, let img = Image(data: picked) {
                            img.resizable().scaledToFill()
                        } else {
                            AvatarImage(key: currentKey, name: name, size: 160)
                        }
                    }
                    .frame(width: 160, height: 160)
                    .clipShape(Circle())
                    .overlay(Circle().strokeBorder(.white.opacity(0.12), lineWidth: 1))
                    .shadow(color: .black.opacity(0.4), radius: 14, y: 6)
                    .padding(.top, 12)

                    Text("Square images look best — we'll center-crop and encrypt it. Only members who share a server with you can see it.")
                        .font(.caption).foregroundStyle(.white.opacity(0.55))
                        .multilineTextAlignment(.center).padding(.horizontal, 24)

                    // iOS: the Photos library (the natural source on a phone). macOS: a file
                    // picker — Mac users have image FILES, and PhotosPicker there often can't
                    // transfer the item as Data (why "Save" appeared to do nothing).
                    #if os(iOS)
                    PhotosPicker(selection: $item, matching: .images) {
                        Label(picked == nil ? "Choose a photo" : "Choose a different photo", systemImage: "photo.on.rectangle")
                            .frame(maxWidth: .infinity).padding(.vertical, 4)
                    }
                    .controlSize(.large).buttonStyle(.glass).tint(.skAccent).padding(.horizontal, 24)
                    #else
                    Button { showFileImporter = true } label: {
                        Label(picked == nil ? "Choose a photo" : "Choose a different photo", systemImage: "photo.on.rectangle")
                            .frame(maxWidth: .infinity).padding(.vertical, 4)
                    }
                    .controlSize(.large).buttonStyle(.glass).tint(.skAccent).padding(.horizontal, 24)
                    #endif

                    if let onRemoveAction, currentKey != nil, app.avatars.data(for: currentKey!) != nil {
                        Button(role: .destructive) {
                            busy = true
                            Task { await onRemoveAction(); busy = false; dismiss() }
                        } label: {
                            Label("Remove current photo", systemImage: "trash").frame(maxWidth: .infinity).padding(.vertical, 2)
                        }
                        .controlSize(.large).buttonStyle(.glass).tint(.red).padding(.horizontal, 24)
                    }
                    Spacer()
                }
                .padding(.top, 8)
            }
            .navigationTitle(title)
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        guard let picked else { dismiss(); return }
                        busy = true
                        Task { await onPick(picked); busy = false; dismiss() }
                    }
                    .disabled(picked == nil || busy)
                }
            }
            .task(id: item) {
                if let item, let data = try? await item.loadTransferable(type: Data.self) {
                    picked = data
                }
            }
            .fileImporter(isPresented: $showFileImporter, allowedContentTypes: [.image]) { result in
                if case let .success(url) = result {
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                    picked = try? Data(contentsOf: url)
                }
            }
        }
    }
}
