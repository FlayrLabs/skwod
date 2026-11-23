import SwiftUI

// A genuinely playable chess game: correct per-piece movement, blocking, capture, and turns.
// Realtime, end-to-end-encrypted: when opened in a channel, moves sync to the other player over the
// same Sender-Key path as chat (see GameSync). Without a channel it's a local single-device board.

enum PieceColor { case white, black }
enum PieceType { case pawn, knight, bishop, rook, queen, king }

struct Piece: Equatable {
    var color: PieceColor
    var type: PieceType
    var glyph: String {
        switch (color, type) {
        case (.white, .king): "♔"; case (.white, .queen): "♕"; case (.white, .rook): "♖"
        case (.white, .bishop): "♗"; case (.white, .knight): "♘"; case (.white, .pawn): "♙"
        case (.black, .king): "♚"; case (.black, .queen): "♛"; case (.black, .rook): "♜"
        case (.black, .bishop): "♝"; case (.black, .knight): "♞"; case (.black, .pawn): "♟"
        }
    }

    /// Two-char wire code, e.g. "wp", "bk".
    var code: String {
        let c = color == .white ? "w" : "b"
        let t: String
        switch type {
        case .pawn: t = "p"; case .knight: t = "n"; case .bishop: t = "b"
        case .rook: t = "r"; case .queen: t = "q"; case .king: t = "k"
        }
        return c + t
    }

    init(color: PieceColor, type: PieceType) { self.color = color; self.type = type }

    init?(code: String) {
        guard code.count == 2 else { return nil }
        let chars = Array(code)
        color = chars[0] == "w" ? .white : .black
        switch chars[1] {
        case "p": type = .pawn; case "n": type = .knight; case "b": type = .bishop
        case "r": type = .rook; case "q": type = .queen; case "k": type = .king
        default: return nil
        }
    }
}

struct Square: Hashable { var r: Int; var c: Int }

@Observable
final class ChessGame {
    var board: [[Piece?]]
    var turn: PieceColor = .white
    var selected: Square?
    var legal: Set<Square> = []
    /// Monotonic move counter, for last-write-wins reconciliation over the wire.
    var seq = 0
    /// Seats (user ids). nil = open; solo play holds both until a second player moves.
    var white: String?
    var black: String?

    init() { board = ChessGame.initial() }

    static func initial() -> [[Piece?]] {
        var b = Array(repeating: Array<Piece?>(repeating: nil, count: 8), count: 8)
        let back: [PieceType] = [.rook, .knight, .bishop, .queen, .king, .bishop, .knight, .rook]
        for c in 0..<8 {
            b[0][c] = Piece(color: .black, type: back[c]); b[1][c] = Piece(color: .black, type: .pawn)
            b[6][c] = Piece(color: .white, type: .pawn); b[7][c] = Piece(color: .white, type: back[c])
        }
        return b
    }

    func reset() {
        board = ChessGame.initial(); turn = .white; selected = nil; legal = []
        seq += 1; white = nil; black = nil
    }

    /// Attempt a move as `me`. Returns true if the board changed (so the caller can broadcast).
    /// Seat rules: you may move a color if you hold that seat OR the seat is still open (solo/first
    /// move claims it). Once both seats are distinct users, each may move only their own color.
    @discardableResult
    func tap(_ sq: Square, as me: String?) -> Bool {
        if let sel = selected {
            var moved = false
            if legal.contains(sq), let mover = board[sel.r][sel.c], mayMove(mover.color, as: me) {
                claimSeat(mover.color, for: me)
                board[sq.r][sq.c] = board[sel.r][sel.c]
                board[sel.r][sel.c] = nil
                if board[sq.r][sq.c]?.type == .pawn, sq.r == 0 || sq.r == 7 {
                    board[sq.r][sq.c]?.type = .queen
                }
                turn = (turn == .white) ? .black : .white
                seq += 1
                moved = true
            }
            selected = nil; legal = []
            return moved
        } else if let p = board[sq.r][sq.c], p.color == turn, mayMove(p.color, as: me) {
            selected = sq
            legal = moves(from: sq)
        }
        return false
    }

    /// May `me` move `color` right now (seat is theirs or still open)?
    func mayMove(_ color: PieceColor, as me: String?) -> Bool {
        guard let me else { return true }   // no channel context → local play, anything goes
        let seat = color == .white ? white : black
        return seat == nil || seat == me
    }

    private func claimSeat(_ color: PieceColor, for me: String?) {
        guard let me else { return }
        if color == .white, white == nil { white = me }
        if color == .black, black == nil { black = me }
    }

    /// Which color `me` controls, for the status line. nil = spectator.
    func seat(for me: String?) -> PieceColor? {
        guard let me else { return nil }
        if white == me { return .white }
        if black == me { return .black }
        if white == nil { return .white }   // open — you'd claim white on your first move
        if black == nil { return .black }
        return nil
    }

    // MARK: wire snapshot

    func snapshot(by me: String?) -> ChessSnapshot {
        var cells = [String](repeating: "", count: 64)
        for r in 0..<8 { for c in 0..<8 { cells[r * 8 + c] = board[r][c]?.code ?? "" } }
        return ChessSnapshot(seq: seq, cells: cells, turn: turn == .white ? "white" : "black",
                             white: white, black: black, by: me)
    }

    /// Overwrite the board from a snapshot. Caller (runSync) decides WHICH snapshot wins via a
    /// deterministic (seq, by) ordering, so both devices converge even on a simultaneous move.
    func apply(_ snap: ChessSnapshot) {
        var b = Array(repeating: Array<Piece?>(repeating: nil, count: 8), count: 8)
        for i in 0..<min(64, snap.cells.count) {
            b[i / 8][i % 8] = Piece(code: snap.cells[i])
        }
        board = b
        turn = snap.turn == "white" ? .white : .black
        white = snap.white; black = snap.black
        seq = snap.seq
        selected = nil; legal = []
    }

    private func moves(from sq: Square) -> Set<Square> {
        guard let p = board[sq.r][sq.c] else { return [] }
        var out = Set<Square>()
        func add(_ r: Int, _ c: Int) -> Bool {
            guard (0..<8).contains(r), (0..<8).contains(c) else { return false }
            if let t = board[r][c] { if t.color != p.color { out.insert(Square(r: r, c: c)) }; return false }
            out.insert(Square(r: r, c: c)); return true
        }
        func ray(_ dr: Int, _ dc: Int) { var r = sq.r + dr, c = sq.c + dc; while add(r, c) { r += dr; c += dc } }
        switch p.type {
        case .pawn:
            let dir = p.color == .white ? -1 : 1
            let start = p.color == .white ? 6 : 1
            if (0..<8).contains(sq.r + dir), board[sq.r + dir][sq.c] == nil {
                out.insert(Square(r: sq.r + dir, c: sq.c))
                if sq.r == start, board[sq.r + 2*dir][sq.c] == nil { out.insert(Square(r: sq.r + 2*dir, c: sq.c)) }
            }
            for dc in [-1, 1] {
                let r = sq.r + dir, c = sq.c + dc
                if (0..<8).contains(r), (0..<8).contains(c), let t = board[r][c], t.color != p.color { out.insert(Square(r: r, c: c)) }
            }
        case .knight:
            for (dr, dc) in [(-2,-1),(-2,1),(-1,-2),(-1,2),(1,-2),(1,2),(2,-1),(2,1)] { _ = add(sq.r+dr, sq.c+dc) }
        case .bishop: for (dr, dc) in [(-1,-1),(-1,1),(1,-1),(1,1)] { ray(dr, dc) }
        case .rook: for (dr, dc) in [(-1,0),(1,0),(0,-1),(0,1)] { ray(dr, dc) }
        case .queen: for (dr, dc) in [(-1,-1),(-1,1),(1,-1),(1,1),(-1,0),(1,0),(0,-1),(0,1)] { ray(dr, dc) }
        case .king: for dr in -1...1 { for dc in -1...1 where dr != 0 || dc != 0 { _ = add(sq.r+dr, sq.c+dc) } }
        }
        return out
    }
}

struct ChessView: View {
    /// The channel this game plays in — nil for a local/preview board (no sync).
    var channelId: String? = nil
    @EnvironmentObject private var app: AppState
    @State private var game = ChessGame()
    @State private var appliedSeq = -1
    @State private var appliedBy = ""

    private var me: String? { channelId == nil ? nil : app.session?.userId }
    private var sync: GameSync? {
        guard let channelId else { return nil }
        return GameSync(app: app, channelId: channelId)
    }

    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(spacing: 18) {
                HStack {
                    Label(game.turn == .white ? "White to move" : "Black to move",
                          systemImage: "circle.fill")
                        .foregroundStyle(game.turn == .white ? .white : .black)
                        .font(.headline)
                        .padding(.horizontal, 14).padding(.vertical, 8)
                        .glassEffect(.regular, in: .capsule)
                    Spacer()
                    Button("Reset") { reset() }.buttonStyle(.glass)
                }
                board
                statusLine
            }
            .padding()
            .frame(maxWidth: 520)
        }
        .navigationTitle("Chess")
        #if os(macOS)
        .frame(minWidth: 560, minHeight: 640)
        #endif
        .task(id: channelId) { await runSync() }
    }

    @ViewBuilder private var statusLine: some View {
        if channelId != nil, let seat = game.seat(for: me) {
            let mine = (seat == .white && game.turn == .white) || (seat == .black && game.turn == .black)
            Text(mine ? "Your move — you're \(seat == .white ? "White ♔" : "Black ♚")"
                      : "You're \(seat == .white ? "White ♔" : "Black ♚") — waiting for your opponent")
                .font(.caption).foregroundStyle(mine ? .skAccent : .white.opacity(0.5))
        } else {
            Text(channelId == nil ? "Tap a piece, then a highlighted square."
                                  : "Watching — both seats are taken.")
                .font(.caption).foregroundStyle(.white.opacity(0.5))
        }
    }

    private var board: some View {
        GlassEffectContainer {
            VStack(spacing: 0) {
                ForEach(0..<8, id: \.self) { r in
                    HStack(spacing: 0) {
                        ForEach(0..<8, id: \.self) { c in
                            let sq = Square(r: r, c: c)
                            ZStack {
                                Rectangle()
                                    .fill((r + c).isMultiple(of: 2) ? Color.white.opacity(0.14) : Color.black.opacity(0.28))
                                if game.selected == sq {
                                    Rectangle().fill(.skAccent.opacity(0.4))
                                }
                                if game.legal.contains(sq) {
                                    Circle().fill(.skAccent.opacity(0.55)).frame(width: 14, height: 14)
                                }
                                if let p = game.board[r][c] {
                                    Text(p.glyph).font(.system(size: 30))
                                        .foregroundStyle(p.color == .white ? .white : .black)
                                        .shadow(radius: 1)
                                }
                            }
                            .aspectRatio(1, contentMode: .fit)
                            .contentShape(Rectangle())
                            .onTapGesture { tap(sq) }
                        }
                    }
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(.white.opacity(0.15), lineWidth: 1))
        }
    }

    private func tap(_ sq: Square) {
        let moved = withAnimation(.snappy(duration: 0.15)) { game.tap(sq, as: me) }
        if moved, let sync { Task { await sync.send(game.snapshot(by: me)) } }
    }

    private func reset() {
        game.reset()
        if let sync { Task { await sync.send(game.snapshot(by: me)) } }
    }

    /// Poll for moves while the board is open, converging both devices on a deterministic winner:
    /// highest `seq`, ties broken by the smallest mover id (`by`). Because `by` is embedded in the
    /// snapshot (device-consistent), two clients that reach the same seq from a simultaneous first
    /// move pick the SAME winning snapshot and converge instead of desyncing forever.
    private func runSync() async {
        guard let sync else { return }
        await sync.updates { await syncOnce() }
    }

    private func syncOnce() async {
        guard let sync else { return }
        do {
            let events = await sync.fetch(ChessSnapshot.self).map(\.event)
            if let win = events.max(by: { a, b in
                a.seq != b.seq ? a.seq < b.seq : (a.by ?? "") > (b.by ?? "")
            }) {
                let winBy = win.by ?? ""
                let newer = win.seq > appliedSeq || (win.seq == appliedSeq && winBy < appliedBy)
                // Never revert a local move we haven't broadcast yet (win.seq >= our seq).
                if newer, win.seq >= game.seq {
                    game.apply(win)
                    appliedSeq = win.seq
                    appliedBy = winBy
                }
            }
        }
    }
}
