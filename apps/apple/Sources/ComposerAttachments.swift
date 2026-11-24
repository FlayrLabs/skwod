import SwiftUI
import UniformTypeIdentifiers
#if os(macOS)
import AppKit
#else
import UIKit
#endif

/// Something pasted or dropped onto the chat, waiting in the composer to be sent — exactly what
/// "Attach" would have sent: an image goes out as pixels (metadata stripped, `.image`), any other
/// file by its URL (`.file`, streamed; never read into memory here).
struct StagedAttachment: Identifiable, Equatable {
    enum Payload: Equatable { case image(Data), file(URL) }
    let id = UUID()
    let payload: Payload
    let name: String
    /// A decoded preview for an image (made once, at staging).
    let preview: Image?

    static func == (a: StagedAttachment, b: StagedAttachment) -> Bool { a.id == b.id }
}

/// Turning clipboard / drag contents into staged attachments, within the limits: the host's
/// per-file limit (`UploadLimit`, via `AttachmentService.maxBytes`) for files, and the in-memory
/// bound for images held as data.
enum ComposerIntake {
    /// At most this many waiting at once.
    static let maxStaged = 10

    enum Problem: Error { case tooLarge, unreadable }

    static func image(_ data: Data, name: String = "Pasted image") -> Result<StagedAttachment, Problem> {
        guard data.count <= AttachmentService.inMemoryMaxBytes else { return .failure(.tooLarge) }
        guard let preview = Image(data: data) else { return .failure(.unreadable) }
        return .success(StagedAttachment(payload: .image(data), name: name, preview: preview))
    }

    static func file(_ url: URL) -> Result<StagedAttachment, Problem> {
        let values = try? url.resourceValues(forKeys: [.fileSizeKey, .isDirectoryKey])
        guard values?.isDirectory != true, let size = values?.fileSize else { return .failure(.unreadable) }
        guard size <= AttachmentService.maxBytes else { return .failure(.tooLarge) }
        // An image file gets a preview (decoded once; only within the in-memory bound).
        var preview: Image?
        if let type = UTType(filenameExtension: url.pathExtension), type.conforms(to: .image),
           size <= AttachmentService.inMemoryMaxBytes, let data = try? Data(contentsOf: url, options: .mappedIfSafe) {
            preview = Image(data: data)
        }
        return .success(StagedAttachment(payload: .file(url), name: url.lastPathComponent, preview: preview))
    }

    static func sentence(_ p: Problem) -> String {
        switch p {
        case .tooLarge: return UploadLimit.tooLargeSentence(limit: UploadLimit.current)
        case .unreadable: return "That couldn't be attached — it isn't a file Skwod can read."
        }
    }

    /// Load what a drag / drop carries. File URLs first (a Finder drag), then images (a
    /// screenshot thumbnail, a picture dragged out of another app — often a file promise, which
    /// `loadFileRepresentation` resolves). The temporary file a provider hands over is read
    /// INSIDE its callback: it is deleted when the callback returns.
    static func load(_ providers: [NSItemProvider], into deliver: @escaping @MainActor (Result<StagedAttachment, Problem>) -> Void) -> Bool {
        var handled = false
        for provider in providers.prefix(maxStaged) {
            if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
                handled = true
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    guard let url else { Task { @MainActor in deliver(.failure(.unreadable)) }; return }
                    let result = file(url)
                    Task { @MainActor in deliver(result) }
                }
            } else if provider.hasItemConformingToTypeIdentifier(UTType.image.identifier) {
                handled = true
                provider.loadFileRepresentation(forTypeIdentifier: UTType.image.identifier) { url, _ in
                    var result: Result<StagedAttachment, Problem> = .failure(.unreadable)
                    if let url {
                        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? Int.max
                        if size > AttachmentService.inMemoryMaxBytes {
                            result = .failure(.tooLarge)
                        } else if let data = try? Data(contentsOf: url) {
                            result = image(data, name: url.lastPathComponent)
                        }
                    }
                    let final = result
                    Task { @MainActor in deliver(final) }
                }
            }
        }
        return handled
    }

    static let dropTypes: [UTType] = [.fileURL, .image]

    #if os(macOS)
    /// What ⌘V would attach: files copied in Finder, or an image (a screenshot copied with
    /// ⌃⇧⌘4, an image copied from a browser). Nil when the clipboard holds text — then ⌘V
    /// pastes the text as always.
    static func fromPasteboard(_ pb: NSPasteboard = .general) -> [Result<StagedAttachment, Problem>]? {
        if let urls = pb.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL], !urls.isEmpty {
            return urls.prefix(maxStaged).map(file)
        }
        // Text wins over an image that came with it (rich text copies carry both).
        if pb.string(forType: .string) != nil { return nil }
        for type in [NSPasteboard.PasteboardType.png, .tiff, NSPasteboard.PasteboardType("public.jpeg"), NSPasteboard.PasteboardType("public.heic")] {
            if let data = pb.data(forType: type) { return [image(data)] }
        }
        return nil
    }
    #else
    /// The clipboard's images (iOS). Reading them asks the user's permission the first time.
    static func fromPasteboard() -> [Result<StagedAttachment, Problem>] {
        let pb = UIPasteboard.general
        var out: [Result<StagedAttachment, Problem>] = []
        if pb.hasImages {
            for img in (pb.images ?? []).prefix(maxStaged) {
                if let data = img.pngData() ?? img.jpegData(compressionQuality: 0.9) { out.append(image(data)) }
            }
        }
        return out
    }
    #endif
}

/// The strip above the composer showing what will be sent with the next message, each with a
/// remove button.
struct StagedAttachmentsTray: View {
    @Binding var staged: [StagedAttachment]

    var body: some View {
        if !staged.isEmpty {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ForEach(staged) { item in
                        ZStack(alignment: .topTrailing) {
                            Group {
                                if let preview = item.preview {
                                    preview.resizable().scaledToFill()
                                } else {
                                    VStack(spacing: 4) {
                                        Image(systemName: "doc.fill").font(.system(size: 22)).foregroundStyle(.white.opacity(0.7))
                                        Text(item.name).font(.caption2).foregroundStyle(.white.opacity(0.7))
                                            .lineLimit(2).multilineTextAlignment(.center)
                                    }
                                    .padding(6)
                                }
                            }
                            .frame(width: 72, height: 72)
                            .background(.white.opacity(0.06))
                            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
                            Button {
                                staged.removeAll { $0.id == item.id }
                            } label: {
                                Image(systemName: "xmark.circle.fill").font(.system(size: 17))
                                    .foregroundStyle(.white, .black.opacity(0.7))
                            }
                            .buttonStyle(.plain)
                            .padding(3)
                            .help("Remove")
                            .accessibilityLabel("Remove \(item.name)")
                        }
                    }
                }
                .padding(.horizontal, 4)
            }
            .frame(height: 76)
            .accessibilityIdentifier("composer.staged")
        }
    }
}

/// The emoji picker: a popover anchored to the composer's emoji button (it used to be the
/// system character palette, which opens at the text caret — the left of the chat bar).
struct EmojiPickerPopover: View {
    let onPick: (String) -> Void
    static let emoji: [String] = [
        "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "🙂", "😉", "😊", "😇",
        "🥰", "😍", "😘", "😋", "😛", "😜", "🤪", "😎", "🤩", "🥳", "😏", "😒",
        "😞", "😔", "😟", "😕", "🙁", "😣", "😢", "😭", "😤", "😠", "😡", "🤯",
        "😳", "🥺", "😱", "😨", "🤗", "🤔", "🤭", "🤫", "😶", "😐", "🙄", "😬",
        "😴", "🤤", "😷", "🤒", "🤠", "🤡", "👻", "💀", "👽", "🤖", "💩", "😺",
        "👍", "👎", "👏", "🙌", "🙏", "🤝", "💪", "👀", "✌️", "🤞", "👋", "🫡",
        "❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "💔", "💯", "🔥", "✨", "🎉",
        "🎂", "🍕", "🍺", "☕️", "⚽️", "🏀", "🎮", "🎵", "📷", "✅", "❌", "⚠️",
    ]

    var body: some View {
        // Build 49: the same picker as the iPhone sheet (search, recents, categories), in the
        // popover anchored to the composer's emoji button. It stays open for several picks.
        EmojiPickerView(onPick: onPick, dismissOnPick: false)
            .frame(width: 360, height: 380)
            .accessibilityIdentifier("composer.emojiPicker")
    }
}

#if os(macOS)
/// ⌘V in the composer with files or an image on the clipboard attaches them (the text field on
/// its own would ignore them). Installed while the composer is on screen; acts only while its
/// field has focus, and lets every other ⌘V through untouched.
@MainActor
final class ComposerPasteMonitor {
    private var monitor: Any?

    func start(isFocused: @escaping @MainActor () -> Bool, deliver: @escaping @MainActor ([Result<StagedAttachment, ComposerIntake.Problem>]) -> Void) {
        stop()
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
            guard flags == .command, event.charactersIgnoringModifiers?.lowercased() == "v",
                  MainActor.assumeIsolated({ isFocused() }),
                  let items = ComposerIntake.fromPasteboard() else { return event }
            MainActor.assumeIsolated { deliver(items) }
            return nil
        }
    }

    func stop() {
        if let monitor { NSEvent.removeMonitor(monitor) }
        monitor = nil
    }
}
#endif

#if os(iOS)
/// The iOS composer field: a UITextView so that the system Paste (the edit menu, ⌘V on a
/// hardware keyboard) can take images and files as well as text. Text pastes as always; images
/// and files go to `onPasteItems` and are staged exactly like a drop (same conversation tagging).
/// Looks like the SwiftUI field it replaces: plain, white text, 1–6 lines.
struct ComposerTextView: UIViewRepresentable {
    @Binding var text: String
    var placeholder: String
    var onPasteItems: ([NSItemProvider]) -> Void

    final class PastingTextView: UITextView {
        var onPasteItems: (([NSItemProvider]) -> Void)?

        /// What the clipboard holds that a text view would ignore: images or files.
        private var hasAttachables: Bool {
            let pb = UIPasteboard.general
            // `has…` checks never read the contents, so they don't ask for paste permission.
            return pb.hasImages || pb.contains(pasteboardTypes: [UTType.fileURL.identifier, UTType.image.identifier, UTType.movie.identifier, UTType.pdf.identifier])
        }

        override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
            if action == #selector(paste(_:)), onPasteItems != nil, hasAttachables { return true }
            return super.canPerformAction(action, withSender: sender)
        }

        override func paste(_ sender: Any?) {
            let pb = UIPasteboard.general
            // Text (with or without a picture riding along, e.g. rich text) pastes as text.
            if pb.hasStrings && !pb.hasImages && !pb.contains(pasteboardTypes: [UTType.fileURL.identifier]) {
                super.paste(sender)
                return
            }
            guard let onPasteItems, hasAttachables else { super.paste(sender); return }
            let providers = pb.itemProviders.filter {
                $0.hasItemConformingToTypeIdentifier(UTType.image.identifier) || $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)
            }
            if providers.isEmpty { super.paste(sender) } else { onPasteItems(providers) }
        }
    }

    func makeUIView(context: Context) -> PastingTextView {
        let view = PastingTextView()
        view.delegate = context.coordinator
        view.backgroundColor = .clear
        view.textColor = .white
        view.font = .preferredFont(forTextStyle: .body)
        view.adjustsFontForContentSizeCategory = true
        view.textContainerInset = .zero
        view.textContainer.lineFragmentPadding = 0
        view.isScrollEnabled = false
        view.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        view.onPasteItems = onPasteItems
        view.accessibilityIdentifier = "composer.field"
        view.accessibilityLabel = placeholder
        #if DEBUG
        E2E.composerField = view
        // Screenshots: bring the keyboard up on the composer (`SKWOD_E2E_FOCUS_COMPOSER=<s>`).
        if let delay = E2E.env("SKWOD_E2E_FOCUS_COMPOSER").flatMap(Double.init) {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak view] in
                view?.becomeFirstResponder()
                if let typed = E2E.env("SKWOD_E2E_TYPE") { view?.insertText(typed) }
            }
        }
        #endif
        return view
    }

    func updateUIView(_ view: PastingTextView, context: Context) {
        view.onPasteItems = onPasteItems
        context.coordinator.parent = self
        // Never while the keyboard is composing (marked text: Japanese, Chinese, dictation…).
        if view.markedTextRange == nil, view.text != text { view.text = text }
        view.accessibilityLabel = placeholder
    }

    /// 1 to 6 lines; scrolls beyond that.
    func sizeThatFits(_ proposal: ProposedViewSize, uiView: PastingTextView, context: Context) -> CGSize? {
        let width = proposal.width ?? 240
        let lineHeight = uiView.font?.lineHeight ?? 20
        let fitted = uiView.sizeThatFits(CGSize(width: width, height: .greatestFiniteMagnitude)).height
        let height = min(max(fitted, lineHeight), lineHeight * 6)
        uiView.isScrollEnabled = fitted > lineHeight * 6
        return CGSize(width: width, height: ceil(height))
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, UITextViewDelegate {
        var parent: ComposerTextView
        init(_ parent: ComposerTextView) { self.parent = parent }
        func textViewDidChange(_ textView: UITextView) {
            if parent.text != textView.text { parent.text = textView.text }
        }
    }
}
#endif
