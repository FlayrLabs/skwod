import SwiftUI
import PhotosUI
import CoreImage
import CoreImage.CIFilterBuiltins

// MARK: - Model

/// One draggable/resizable/rotatable text layer on the canvas (Instagram-style).
struct TextOverlay: Identifiable {
    let id = UUID()
    var text: String = ""
    var colorIndex: Int = 0
    var style: OverlayStyle = .classic
    var pill: Bool = false
    /// Center, in UNIT coordinates (0–1 of the canvas) so layout survives canvas/render resizes.
    var unitPosition: CGPoint = CGPoint(x: 0.5, y: 0.5)
    var scale: CGFloat = 1
    var rotation: Angle = .zero

    var color: Color { TextOverlay.palette[colorIndex % TextOverlay.palette.count] }
    /// Legible foreground when the pill background is on (white pill → black text, etc.).
    var pillForeground: Color { TextOverlay.darkText[colorIndex % TextOverlay.palette.count] ? .black : .white }

    static let palette: [Color] = [.white, .black, Color(red: 1, green: 0.27, blue: 0.27),
                                   .orange, .yellow, Color(red: 0.3, green: 0.85, blue: 0.4),
                                   .cyan, Color(red: 0.35, green: 0.55, blue: 1), .purple, .pink]
    /// Whether the pill of palette[i] needs dark text to stay readable.
    static let darkText: [Bool] = [true, false, false, true, true, true, true, false, false, false]
}

/// Instagram-style text looks.
enum OverlayStyle: String, CaseIterable {
    case classic, modern, typewriter, serif

    func font(size: CGFloat) -> Font {
        switch self {
        case .classic: return .system(size: size, weight: .bold, design: .rounded)
        case .modern: return .system(size: size, weight: .heavy)
        case .typewriter: return .system(size: size, weight: .semibold, design: .monospaced)
        case .serif: return .system(size: size, weight: .bold, design: .serif)
        }
    }

    var label: String {
        switch self {
        case .classic: return "Classic"
        case .modern: return "Modern"
        case .typewriter: return "Type"
        case .serif: return "Serif"
        }
    }
}

/// Photo filter presets (CoreImage), Instagram-style names.
enum StoryFilter: String, CaseIterable, Identifiable {
    case original = "Normal"
    case vivid = "Vivid"
    case warm = "Warm"
    case cool = "Cool"
    case fade = "Fade"
    case instant = "Retro"
    case mono = "Mono"
    case noir = "Noir"

    var id: String { rawValue }

    /// Apply this preset to encoded image data → a platform image (nil = undecodable input).
    func apply(to data: Data) -> PlatformImage? {
        guard let base = CIImage(data: data) else { return nil }
        let output: CIImage
        switch self {
        case .original:
            output = base
        case .vivid:
            let f = CIFilter.vibrance(); f.inputImage = base; f.amount = 0.9
            let c = CIFilter.colorControls(); c.inputImage = f.outputImage; c.saturation = 1.15; c.contrast = 1.05
            output = c.outputImage ?? base
        case .warm:
            let f = CIFilter.temperatureAndTint(); f.inputImage = base
            f.neutral = CIVector(x: 6500, y: 0); f.targetNeutral = CIVector(x: 4800, y: 0)
            output = f.outputImage ?? base
        case .cool:
            let f = CIFilter.temperatureAndTint(); f.inputImage = base
            f.neutral = CIVector(x: 6500, y: 0); f.targetNeutral = CIVector(x: 8500, y: 0)
            output = f.outputImage ?? base
        case .fade:
            let f = CIFilter.photoEffectFade(); f.inputImage = base; output = f.outputImage ?? base
        case .instant:
            let f = CIFilter.photoEffectInstant(); f.inputImage = base; output = f.outputImage ?? base
        case .mono:
            let f = CIFilter.photoEffectMono(); f.inputImage = base; output = f.outputImage ?? base
        case .noir:
            let f = CIFilter.photoEffectNoir(); f.inputImage = base; output = f.outputImage ?? base
        }
        guard let cg = StoryFilter.context.createCGImage(output, from: output.extent) else { return nil }
        #if os(macOS)
        return NSImage(cgImage: cg, size: NSSize(width: cg.width, height: cg.height))
        #else
        return UIImage(cgImage: cg)
        #endif
    }

    private static let context = CIContext()
}

// MARK: - Editor

/// The Instagram-style full-screen editor used by BOTH stories (9:16) and posts (1:1): pick a
/// photo, swipe-strip filters, add text layers you can drag / pinch-resize / rotate / recolor,
/// attach a song — then the canvas is flattened into one image and handed back.
struct StoryEditorView: View {
    enum Mode { case story, post }
    var mode: Mode = .story
    /// Start from an existing photo (post flow: photo picked in the composer).
    var initialImage: Data? = nil
    /// Flattened image + chosen song + (stories) which part of it plays. Nil image = user
    /// shared a music-only story.
    var onDone: (Data?, MusicTrack?, MusicClip?) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var pickerItem: PhotosPickerItem?
    @State private var imageData: Data?
    @State private var filter: StoryFilter = .original
    /// Filtered full-res image cache (recomputed when photo or filter changes).
    @State private var filteredImage: PlatformImage?
    /// Which (photo, filter) produced `filteredImage` — guards against racing detached renders
    /// finishing out of order, and lets flatten() detect a stale/in-flight preview.
    @State private var filteredKey: String = ""
    @State private var overlays: [TextOverlay] = []
    @State private var editing: TextOverlay?       // layer open in the text editor
    @State private var music: MusicTrack?
    /// Which part of the song a story plays (set when a song is picked).
    @State private var clip = MusicClip.fallback
    @State private var showMusic = false
    @State private var showFilters = false
    @State private var canvasSize: CGSize = .zero
    /// In-flight gesture state per layer (committed on end).
    @GestureState private var dragOffset: CGSize = .zero
    @State private var activeLayer: UUID?

    private var aspect: CGFloat { mode == .story ? 9.0 / 16.0 : 1.0 }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            GeometryReader { geo in
                let size = fittedCanvas(in: geo.size)
                ZStack {
                    canvas(size: size)
                        .frame(width: size.width, height: size.height)
                        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
                        .position(x: geo.size.width / 2, y: geo.size.height / 2)
                        .onAppear { canvasSize = size }
                        .onChange(of: geo.size) { _, _ in canvasSize = fittedCanvas(in: geo.size) }
                }
            }
            chrome
            if editing != nil { textEditor }
        }
        #if os(macOS)
        .frame(minWidth: 520, minHeight: 760)
        #endif
        .task(id: pickerItem) {
            if let item = pickerItem, let data = try? await item.loadTransferable(type: Data.self) {
                imageData = data
                filter = .original
                refilter()
            }
        }
        .onAppear {
            if imageData == nil { imageData = initialImage }
            refilter()
        }
        .sheet(isPresented: $showMusic) { MusicSearchSheet { music = $0; clip = .fallback } }
        .onDisappear { StoryClipPlayer.shared.stop() }
    }

    private func fittedCanvas(in container: CGSize) -> CGSize {
        // Largest aspect-correct canvas that fits, leaving room for the chrome.
        let w = min(container.width - 24, (container.height - 130) * aspect)
        return CGSize(width: max(w, 100), height: max(w / aspect, 100))
    }

    // MARK: Canvas

    @ViewBuilder private func canvas(size: CGSize) -> some View {
        // Is the actively dragged layer currently hovering the trash can?
        let hoverTrash: Bool = {
            guard let id = activeLayer, let layer = overlays.first(where: { $0.id == id }) else { return false }
            return inTrashZone(CGPoint(x: layer.unitPosition.x + dragOffset.width / size.width,
                                       y: layer.unitPosition.y + dragOffset.height / size.height))
        }()
        ZStack {
            background(size: size)
            ForEach(overlays) { layer in
                overlayText(layer)
                    .scaleEffect(layer.scale)
                    .rotationEffect(layer.rotation)
                    .opacity(activeLayer == layer.id && hoverTrash ? 0.5 : 1)
                    .position(x: layer.unitPosition.x * size.width + (activeLayer == layer.id ? dragOffset.width : 0),
                              y: layer.unitPosition.y * size.height + (activeLayer == layer.id ? dragOffset.height : 0))
                    .gesture(layerGesture(layer, size: size))
                    .onTapGesture { editing = layer }
            }
            // Instagram's drag-to-delete: the trash can appears at the bottom while dragging;
            // dropping the layer on it deletes it.
            if activeLayer != nil {
                VStack {
                    Spacer()
                    Image(systemName: hoverTrash ? "trash.fill" : "trash")
                        .font(.system(size: hoverTrash ? 22 : 17, weight: .semibold))
                        .foregroundStyle(.white)
                        .frame(width: hoverTrash ? 58 : 46, height: hoverTrash ? 58 : 46)
                        .background(hoverTrash ? AnyShapeStyle(Color.red) : AnyShapeStyle(.black.opacity(0.5)), in: Circle())
                        .padding(.bottom, 16)
                }
                .frame(width: size.width, height: size.height)
                .allowsHitTesting(false)
                .animation(.snappy(duration: 0.15), value: hoverTrash)
                .transition(.opacity)
            }
        }
        .contentShape(Rectangle())
    }

    /// The drop-to-delete region: the bottom-center strip of the canvas where the trash can sits.
    private func inTrashZone(_ unit: CGPoint) -> Bool {
        abs(unit.x - 0.5) < 0.18 && unit.y > 0.86
    }

    @ViewBuilder private func background(size: CGSize) -> some View {
        if let img = filteredImage {
            #if os(macOS)
            Image(nsImage: img).resizable().scaledToFill()
                .frame(width: size.width, height: size.height).clipped()
            #else
            Image(uiImage: img).resizable().scaledToFill()
                .frame(width: size.width, height: size.height).clipped()
            #endif
        } else {
            LinearGradient(colors: [Color(red: 0.16, green: 0.17, blue: 0.32),
                                    Color(red: 0.34, green: 0.2, blue: 0.44)],
                           startPoint: .topLeading, endPoint: .bottomTrailing)
            if imageData == nil {
                PhotosPicker(selection: $pickerItem, matching: .images) {
                    VStack(spacing: 10) {
                        Image(systemName: "photo.badge.plus").font(.system(size: 44)).foregroundStyle(.white)
                        Text("Add a photo").font(.headline).foregroundStyle(.white.opacity(0.85))
                    }
                    .padding(24)
                    .background(.white.opacity(0.12), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                }
                .buttonStyle(.plain)
            }
        }
    }

    /// One rendered text layer (shared by the live canvas and the flatten pass).
    @ViewBuilder fileprivate func overlayText(_ layer: TextOverlay, renderScale: CGFloat = 1) -> some View {
        Text(layer.text)
            .font(layer.style.font(size: 30 * renderScale))
            .multilineTextAlignment(.center)
            .foregroundStyle(layer.pill ? layer.pillForeground : layer.color)
            .padding(.horizontal, (layer.pill ? 14 : 4) * renderScale)
            .padding(.vertical, (layer.pill ? 8 : 2) * renderScale)
            .background(
                layer.pill ? AnyShapeStyle(layer.color) : AnyShapeStyle(.clear),
                in: RoundedRectangle(cornerRadius: 12 * renderScale, style: .continuous)
            )
            .shadow(color: layer.pill ? .clear : .black.opacity(0.45), radius: 2 * renderScale, y: 1 * renderScale)
    }

    /// Drag + pinch + rotate, all simultaneous — the Instagram feel.
    private func layerGesture(_ layer: TextOverlay, size: CGSize) -> some Gesture {
        let drag = DragGesture()
            .updating($dragOffset) { v, state, _ in state = v.translation }
            .onChanged { _ in activeLayer = layer.id }
            .onEnded { v in
                let dropped = CGPoint(x: layer.unitPosition.x + v.translation.width / size.width,
                                      y: layer.unitPosition.y + v.translation.height / size.height)
                if inTrashZone(dropped) {
                    // Dropped on the trash can → delete the layer (Instagram's drag-to-delete).
                    overlays.removeAll { $0.id == layer.id }
                } else {
                    move(layer.id) {
                        $0.unitPosition = dropped
                        // Keep the center reachable (can't lose a layer off-canvas).
                        $0.unitPosition.x = min(max($0.unitPosition.x, 0.03), 0.97)
                        $0.unitPosition.y = min(max($0.unitPosition.y, 0.03), 0.97)
                    }
                }
                activeLayer = nil
            }
        let pinch = MagnifyGesture()
            .onEnded { v in move(layer.id) { $0.scale = min(max($0.scale * v.magnification, 0.4), 6) } }
        let rotate = RotateGesture()
            .onEnded { v in move(layer.id) { $0.rotation += v.rotation } }
        return drag.simultaneously(with: pinch).simultaneously(with: rotate)
    }

    private func move(_ id: UUID, _ change: (inout TextOverlay) -> Void) {
        guard let i = overlays.firstIndex(where: { $0.id == id }) else { return }
        change(&overlays[i])
    }

    // MARK: Chrome (top/bottom bars, filter strip)

    private var chrome: some View {
        VStack {
            HStack(spacing: 18) {
                Button { dismiss() } label: { chromeIcon("xmark") }
                Spacer()
                if imageData != nil {
                    PhotosPicker(selection: $pickerItem, matching: .images) { chromeIcon("photo") }
                        .buttonStyle(.plain)
                    Button { withAnimation(.snappy) { showFilters.toggle() } } label: { chromeIcon("wand.and.stars") }
                }
                Button { newTextLayer() } label: {
                    Text("Aa").font(.system(size: 17, weight: .heavy)).foregroundStyle(.white)
                        .frame(width: 38, height: 38).background(.black.opacity(0.45), in: Circle())
                }
                Button { showMusic = true } label: { chromeIcon(music == nil ? "music.note" : "music.note.list") }
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 16).padding(.top, 12)

            Spacer()

            if let m = music, mode == .story {
                // Instagram's "pick the part": the strip, a length, and it plays as you choose.
                MusicClipTrimmer(track: m, clip: $clip, onRemove: { music = nil })
                    .id(m.id)
                    .frame(maxWidth: 420)
                    .padding(.horizontal, 16).padding(.bottom, 6)
            } else if let m = music {
                HStack(spacing: 8) {
                    Image(systemName: "music.note").font(.caption.bold())
                    Text("\(m.title) — \(m.artist)").font(.caption.weight(.semibold)).lineLimit(1)
                    Button { music = nil } label: { Image(systemName: "xmark").font(.caption2.bold()) }
                        .buttonStyle(.plain)
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background(.black.opacity(0.5), in: Capsule())
                .padding(.bottom, 6)
            }

            if showFilters && imageData != nil { filterStrip }

            HStack {
                Spacer()
                Button { share() } label: {
                    HStack(spacing: 6) {
                        Text(mode == .story ? "Share story" : "Done")
                            .font(.system(size: 15, weight: .bold))
                        Image(systemName: "arrow.right")
                            .font(.system(size: 13, weight: .bold))
                    }
                    .foregroundStyle(.black)
                    .padding(.horizontal, 18).padding(.vertical, 11)
                    .background(.white, in: Capsule())
                }
                .buttonStyle(.plain)
                .disabled(imageData == nil && music == nil && overlays.isEmpty)
            }
            .padding(.horizontal, 16).padding(.bottom, 14)
        }
    }

    private func chromeIcon(_ system: String) -> some View {
        Image(systemName: system).font(.system(size: 16, weight: .semibold)).foregroundStyle(.white)
            .frame(width: 38, height: 38).background(.black.opacity(0.45), in: Circle())
    }

    /// Instagram's swipeable filter row, as tappable thumbnails.
    private var filterStrip: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 12) {
                ForEach(StoryFilter.allCases) { f in
                    Button {
                        filter = f
                        refilter()
                    } label: {
                        VStack(spacing: 5) {
                            thumb(for: f)
                                .frame(width: 56, height: 56)
                                .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
                                    .strokeBorder(filter == f ? .white : .white.opacity(0.15), lineWidth: 2))
                            Text(f.rawValue).font(.caption2.weight(filter == f ? .bold : .regular))
                                .foregroundStyle(filter == f ? .white : .white.opacity(0.6))
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
        }
        .background(.black.opacity(0.35))
    }

    @ViewBuilder private func thumb(for f: StoryFilter) -> some View {
        if let data = thumbData, let img = f.apply(to: data) {
            #if os(macOS)
            Image(nsImage: img).resizable().scaledToFill()
            #else
            Image(uiImage: img).resizable().scaledToFill()
            #endif
        } else {
            Rectangle().fill(.white.opacity(0.1))
        }
    }

    /// Small downscaled copy so the 8 filter thumbnails don't each run CoreImage on a 12MP photo.
    private var thumbData: Data? {
        guard let data = imageData else { return nil }
        if let cached = Self.thumbCache.object(forKey: data.hashValue as NSNumber) { return cached as Data }
        guard let img = PlatformImage(data: data) else { return nil }
        let side: CGFloat = 112
        #if os(macOS)
        let small = NSImage(size: NSSize(width: side, height: side), flipped: false) { rect in
            img.draw(in: rect); return true
        }
        guard let tiff = small.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
              let out = rep.representation(using: .jpeg, properties: [.compressionFactor: 0.8]) else { return nil }
        #else
        let fmt = UIGraphicsImageRendererFormat(); fmt.scale = 1
        let out = UIGraphicsImageRenderer(size: CGSize(width: side, height: side), format: fmt)
            .jpegData(withCompressionQuality: 0.8) { _ in
                img.draw(in: CGRect(x: 0, y: 0, width: side, height: side))
            }
        #endif
        Self.thumbCache.setObject(out as NSData, forKey: data.hashValue as NSNumber)
        return out
    }
    private static let thumbCache = NSCache<NSNumber, NSData>()

    private func renderKey(_ data: Data, _ f: StoryFilter) -> String { "\(data.hashValue):\(f.rawValue)" }

    private func refilter() {
        guard let data = imageData else { filteredImage = nil; filteredKey = ""; return }
        let f = filter
        let key = renderKey(data, f)
        Task.detached(priority: .userInitiated) {
            let img = f.apply(to: data)
            await MainActor.run {
                // Only accept the render still matching the CURRENT selection — two racing
                // detached tasks can finish out of order.
                if renderKey(imageData ?? Data(), filter) == key {
                    filteredImage = img
                    filteredKey = key
                }
            }
        }
    }

    /// The filtered image for the CURRENT (photo, filter), computed synchronously if the async
    /// preview hasn't landed yet — flatten() must never fall back to the gradient while a chosen
    /// photo's filter render is still in flight.
    private func currentFilteredImage() -> PlatformImage? {
        guard let data = imageData else { return nil }
        if filteredKey == renderKey(data, filter), let img = filteredImage { return img }
        return filter.apply(to: data)
    }

    private func newTextLayer() {
        var layer = TextOverlay()
        // Stagger new layers slightly so stacked ones stay grabbable.
        layer.unitPosition = CGPoint(x: 0.5, y: 0.4 + CGFloat(overlays.count % 4) * 0.08)
        overlays.append(layer)
        editing = layer
    }

    // MARK: Text editor overlay

    private var textEditor: some View {
        TextLayerEditor(
            layer: Binding(
                get: { editing ?? TextOverlay() },
                set: { editing = $0 }
            ),
            onDone: {
                guard var layer = editing else { return }
                layer.text = layer.text.trimmingCharacters(in: .whitespacesAndNewlines)
                if let i = overlays.firstIndex(where: { $0.id == layer.id }) {
                    if layer.text.isEmpty { overlays.remove(at: i) } else { overlays[i] = layer }
                }
                editing = nil
            },
            onDelete: {
                if let layer = editing { overlays.removeAll { $0.id == layer.id } }
                editing = nil
            }
        )
    }

    // MARK: Flatten + share

    private func share() {
        let out = flatten()
        StoryClipPlayer.shared.stop()
        onDone(out, music, music != nil && mode == .story ? clip : nil)
        dismiss()
    }

    /// Flatten the styled canvas — filtered photo + all text layers — into one image, at story
    /// resolution. The result is a plain photo, so every existing viewer just renders it.
    private func flatten() -> Data? {
        guard imageData != nil || !overlays.isEmpty else { return nil }
        let renderSize = mode == .story ? CGSize(width: 1080, height: 1920) : CGSize(width: 1080, height: 1080)
        let renderScale = canvasSize.width > 0 ? renderSize.width / canvasSize.width : 1
        // Resolve the photo for the CURRENT selection (synchronously if the preview task is still
        // in flight) — never publish the gradient in place of a chosen photo.
        let photo = currentFilteredImage()
        let content = ZStack {
            if let img = photo {
                #if os(macOS)
                Image(nsImage: img).resizable().scaledToFill()
                    .frame(width: renderSize.width, height: renderSize.height).clipped()
                #else
                Image(uiImage: img).resizable().scaledToFill()
                    .frame(width: renderSize.width, height: renderSize.height).clipped()
                #endif
            } else {
                LinearGradient(colors: [Color(red: 0.16, green: 0.17, blue: 0.32),
                                        Color(red: 0.34, green: 0.2, blue: 0.44)],
                               startPoint: .topLeading, endPoint: .bottomTrailing)
            }
            ForEach(overlays) { layer in
                overlayText(layer, renderScale: renderScale)
                    .scaleEffect(layer.scale)
                    .rotationEffect(layer.rotation)
                    .position(x: layer.unitPosition.x * renderSize.width,
                              y: layer.unitPosition.y * renderSize.height)
            }
        }
        .frame(width: renderSize.width, height: renderSize.height)

        let renderer = ImageRenderer(content: content)
        renderer.proposedSize = ProposedViewSize(renderSize)
        #if os(macOS)
        guard let img = renderer.nsImage, let tiff = img.tiffRepresentation,
              let rep = NSBitmapImageRep(data: tiff) else { return imageData }
        return rep.representation(using: .jpeg, properties: [.compressionFactor: 0.88]) ?? imageData
        #else
        guard let img = renderer.uiImage else { return imageData }
        return img.jpegData(compressionQuality: 0.88) ?? imageData
        #endif
    }
}

extension View {
    /// Present the story editor the Instagram way: full-screen on iOS, a large sheet on macOS.
    @ViewBuilder func storyEditorCover<C: View>(isPresented: Binding<Bool>, @ViewBuilder content: @escaping () -> C) -> some View {
        #if os(iOS)
        fullScreenCover(isPresented: isPresented, content: content)
        #else
        sheet(isPresented: isPresented, content: content)
        #endif
    }
}

// MARK: - Text layer editor (color / font / pill)

/// Full-screen text editing mode: centered field over a dim veil, color swatches, font styles,
/// and the pill-background toggle — Instagram's exact affordances.
private struct TextLayerEditor: View {
    @Binding var layer: TextOverlay
    var onDone: () -> Void
    var onDelete: () -> Void
    @FocusState private var focused: Bool

    var body: some View {
        ZStack {
            Color.black.opacity(0.62).ignoresSafeArea()
                .onTapGesture { onDone() }

            VStack(spacing: 18) {
                HStack {
                    Button("Delete", role: .destructive, action: onDelete)
                        .buttonStyle(.plain).foregroundStyle(.red.opacity(0.9))
                    Spacer()
                    Button("Done", action: onDone)
                        .buttonStyle(.plain).font(.headline).foregroundStyle(.white)
                }
                .padding(.horizontal, 20).padding(.top, 14)

                Spacer()

                TextField("Type something…", text: $layer.text, axis: .vertical)
                    .textFieldStyle(.plain)
                    .font(layer.style.font(size: 30))
                    .multilineTextAlignment(.center)
                    .foregroundStyle(layer.pill ? layer.pillForeground : layer.color)
                    .padding(.horizontal, layer.pill ? 14 : 4).padding(.vertical, layer.pill ? 8 : 2)
                    .background(layer.pill ? AnyShapeStyle(layer.color) : AnyShapeStyle(.clear),
                                in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .frame(maxWidth: 340)
                    .focused($focused)
                    .onSubmit(onDone)

                Spacer()

                // Font styles.
                HStack(spacing: 8) {
                    ForEach(OverlayStyle.allCases, id: \.self) { s in
                        Button {
                            layer.style = s
                        } label: {
                            Text(s.label).font(s.font(size: 13))
                                .foregroundStyle(layer.style == s ? .black : .white)
                                .padding(.horizontal, 12).padding(.vertical, 7)
                                .background(layer.style == s ? AnyShapeStyle(.white) : AnyShapeStyle(.white.opacity(0.15)),
                                            in: Capsule())
                        }
                        .buttonStyle(.plain)
                    }
                    // Pill toggle (Instagram's "A" button).
                    Button {
                        layer.pill.toggle()
                    } label: {
                        Image(systemName: layer.pill ? "a.square.fill" : "a.square")
                            .font(.system(size: 22))
                            .foregroundStyle(.white)
                    }
                    .buttonStyle(.plain)
                }

                // Color swatches.
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        ForEach(Array(TextOverlay.palette.enumerated()), id: \.offset) { i, c in
                            Button {
                                layer.colorIndex = i
                            } label: {
                                Circle().fill(c)
                                    .frame(width: 30, height: 30)
                                    .overlay(Circle().strokeBorder(.white, lineWidth: layer.colorIndex == i ? 3 : 1))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 20)
                }
                .padding(.bottom, 24)
            }
        }
        .onAppear { focused = true }
    }
}
