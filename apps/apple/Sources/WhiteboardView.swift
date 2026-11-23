import SwiftUI

// A collaborative whiteboard: draw with finger/mouse, pick colors, undo, clear. When opened in a
// channel it's realtime + end-to-end encrypted — each finished stroke syncs to everyone over the
// same Sender-Key path as chat (see GameSync). Without a channel it's a local sketch pad.

/// The shared palette — strokes travel as a palette INDEX (not a raw color), so every device renders
/// the same hue without color-encoding headaches.
let WhiteboardPalette: [Color] = [.skAccent, .white, .purple, .pink, .green, .orange, .yellow]

struct Stroke: Identifiable {
    var id = UUID().uuidString
    /// Points normalized 0…1 within the canvas, so a phone sketch lines up on a Mac.
    var points: [CGPoint]
    var colorIndex: Int
    var width: CGFloat

    var color: Color { WhiteboardPalette[max(0, min(colorIndex, WhiteboardPalette.count - 1))] }
}

struct WhiteboardView: View {
    /// The channel this board syncs in — nil for a local/preview sketch (no sync).
    var channelId: String? = nil
    @EnvironmentObject private var app: AppState

    @State private var strokes: [Stroke] = []
    @State private var current: Stroke?
    @State private var colorIndex = 0
    @State private var width: CGFloat = 4
    /// Stroke ids we've already seen (local or remote) so the merge stays idempotent.
    @State private var seen: Set<String> = []
    /// Everything drawn at/before this wire-time is cleared.
    @State private var clearedBefore: Int64 = 0
    @State private var canvasSize: CGSize = .zero

    private var sync: GameSync? {
        guard let channelId else { return nil }
        return GameSync(app: app, channelId: channelId)
    }

    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(spacing: 14) {
                canvas
                toolbar
            }
            .padding()
        }
        .navigationTitle("Whiteboard")
        #if os(macOS)
        .frame(minWidth: 640, minHeight: 560)
        #endif
        .task(id: channelId) { await runSync() }
    }

    private var canvas: some View {
        GeometryReader { geo in
            Canvas { ctx, size in
                for stroke in strokes + [current].compactMap({ $0 }) {
                    var path = Path()
                    let pts = stroke.points.map { CGPoint(x: $0.x * size.width, y: $0.y * size.height) }
                    if let first = pts.first {
                        path.move(to: first)
                        for p in pts.dropFirst() { path.addLine(to: p) }
                    }
                    ctx.stroke(path, with: .color(stroke.color),
                               style: StrokeStyle(lineWidth: stroke.width, lineCap: .round, lineJoin: .round))
                }
            }
            .contentShape(Rectangle())
            .onAppear { canvasSize = geo.size }
            .onChange(of: geo.size) { _, s in canvasSize = s }
            .gesture(
                DragGesture(minimumDistance: 0)
                    .onChanged { v in
                        let p = norm(v.location, in: geo.size)
                        if current == nil { current = Stroke(points: [p], colorIndex: colorIndex, width: width) }
                        else { current?.points.append(p) }
                    }
                    .onEnded { _ in
                        if let c = current, c.points.count > 1 {
                            strokes.append(c)
                            seen.insert(c.id)
                            broadcast(c)
                        }
                        current = nil
                    }
            )
        }
        .background(.black.opacity(0.25))
        .glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).strokeBorder(.white.opacity(0.12), lineWidth: 1))
    }

    private var toolbar: some View {
        HStack(spacing: 14) {
            ForEach(Array(WhiteboardPalette.enumerated()), id: \.offset) { i, c in
                Button { colorIndex = i } label: {
                    Circle().fill(c).frame(width: 26, height: 26)
                        .overlay(Circle().strokeBorder(.white, lineWidth: colorIndex == i ? 2.5 : 0))
                }.buttonStyle(.plain)
            }
            Spacer()
            Button { undo() } label: { Image(systemName: "arrow.uturn.backward") }
                .buttonStyle(.glass)
            Button(role: .destructive) { clearAll() } label: { Image(systemName: "trash") }
                .buttonStyle(.glass)
        }
        .padding(12)
        .glassEffect(.regular, in: .capsule)
    }

    private func norm(_ p: CGPoint, in size: CGSize) -> CGPoint {
        CGPoint(x: size.width > 0 ? p.x / size.width : 0, y: size.height > 0 ? p.y / size.height : 0)
    }

    /// Local undo only affects your own last stroke locally; the shared board keeps others' strokes.
    private func undo() { if !strokes.isEmpty { strokes.removeLast() } }

    private func clearAll() {
        strokes.removeAll(); current = nil
        // Clear the view optimistically but DON'T touch clearedBefore from a local clock — mixing a
        // local wall-clock with server message timestamps silently drops legit strokes under skew.
        // `seen` keeps the just-cleared strokes from reappearing; the authoritative clearedBefore is
        // set in runSync from the clear message's SERVER createdAt when it round-trips.
        if let sync {
            Task { await sync.send(WhiteboardEvent(kind: "clear", strokeId: nil, points: nil, colorIndex: nil, width: nil)) }
        }
    }

    private func broadcast(_ s: Stroke) {
        guard let sync else { return }
        let pts = s.points.map { [Double($0.x), Double($0.y)] }
        Task { await sync.send(WhiteboardEvent(kind: "stroke", strokeId: s.id, points: pts, colorIndex: s.colorIndex, width: Double(s.width))) }
    }

    /// Merge remote strokes + clears while the board is open. Append-only + dedupe by id keeps it
    /// convergent; a clear hides everything drawn at/before its wire-time.
    private func runSync() async {
        guard let sync else { return }
        await sync.updates { await syncOnce() }
    }

    private func syncOnce() async {
        guard let sync else { return }
        do {
            let events = await sync.fetch(WhiteboardEvent.self)
            // Latest clear wins: drop everything and reset dedupe; strokes after it are re-added below.
            if let lastClear = events.filter({ $0.event.kind == "clear" }).map(\.createdAt).max(), lastClear > clearedBefore {
                clearedBefore = lastClear
                strokes.removeAll()
                seen.removeAll()
            }
            for m in events where m.event.kind == "stroke" {
                guard m.createdAt > clearedBefore,
                      let sid = m.event.strokeId, !seen.contains(sid),
                      let raw = m.event.points else { continue }
                seen.insert(sid)
                let pts = raw.map { CGPoint(x: $0.first ?? 0, y: $0.count > 1 ? $0[1] : 0) }
                strokes.append(Stroke(id: sid, points: pts, colorIndex: m.event.colorIndex ?? 0, width: CGFloat(m.event.width ?? 4)))
            }
        }
    }
}
