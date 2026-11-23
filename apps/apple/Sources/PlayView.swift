import SwiftUI

struct PlayView: View {
    var body: some View {
        SkwodScreen(title: "Play") {
            ScrollView {
                VStack(spacing: 16) {
                    NavigationLink(value: PlayDest.chess) {
                        HubTile(title: "Chess", subtitle: "Play a game in-channel", icon: "checkerboard.rectangle", tint: .skAccent)
                    }.buttonStyle(.plain)
                    NavigationLink(value: PlayDest.whiteboard) {
                        HubTile(title: "Whiteboard", subtitle: "Sketch together", icon: "scribble.variable", tint: .purple)
                    }.buttonStyle(.plain)
                    NavigationLink(value: PlayDest.voice) {
                        HubTile(title: "Voice & Video", subtitle: "E2EE calls (fail-closed)", icon: "waveform", tint: .green)
                    }.buttonStyle(.plain)
                }
                .padding()
            }
            .navigationDestination(for: PlayDest.self) { dest in
                switch dest {
                case .chess: ChessView()
                case .whiteboard: WhiteboardView()
                case .voice: CallView()
                }
            }
        }
    }
}

enum PlayDest: Hashable { case chess, whiteboard, voice }

struct HubTile: View {
    let title: String, subtitle: String, icon: String
    var tint: Color
    var body: some View {
        HStack(spacing: 16) {
            Image(systemName: icon).font(.title).foregroundStyle(tint).frame(width: 52, height: 52)
                .glassEffect(.regular.tint(tint.opacity(0.2)), in: .rect(cornerRadius: 14, style: .continuous))
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline).foregroundStyle(.white)
                Text(subtitle).font(.subheadline).foregroundStyle(.white.opacity(0.55))
            }
            Spacer()
            Image(systemName: "chevron.right").foregroundStyle(.white.opacity(0.3))
        }
        .padding(16)
        .glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
    }
}

// CallView (the real E2EE LiveKit call) lives in CallView.swift.
