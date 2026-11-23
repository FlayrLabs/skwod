package io.skwod.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

// A genuinely playable chess game with correct per-piece movement, blocking, capture, turns, and
// pawn→queen promotion. Realtime + E2EE when opened in a channel: moves sync to the other player
// over the same Sender-Key path as chat (see GameSync), using a cross-platform ChessSnapshot so a
// phone and a Mac can share a board. Without a channel it's a local single-device board.
private val START = arrayOf(
    "rnbqkbnr", "pppppppp", "........", "........", "........", "........", "PPPPPPPP", "RNBQKBNR"
)
private fun glyph(c: Char) = when (c) {
    'K' -> "♔"; 'Q' -> "♕"; 'R' -> "♖"; 'B' -> "♗"; 'N' -> "♘"; 'P' -> "♙"
    'k' -> "♚"; 'q' -> "♛"; 'r' -> "♜"; 'b' -> "♝"; 'n' -> "♞"; 'p' -> "♟"; else -> ""
}
private fun isWhite(c: Char) = c.isUpperCase() && c != '.'
private fun inB(r: Int, f: Int) = r in 0..7 && f in 0..7

private fun charToCell(c: Char): String = when {
    c == '.' -> ""
    c.isUpperCase() -> "w" + c.lowercaseChar()
    else -> "b$c"
}
private fun cellToChar(cell: String): Char = when {
    cell.length < 2 -> '.'
    cell[0] == 'w' -> cell[1].uppercaseChar()
    else -> cell[1]
}

@Composable
fun ChessScreen(channelId: String? = null) {
    val model = AppModel.get(LocalContext.current)
    val scope = rememberCoroutineScope()
    val me = if (channelId == null) null else model.current?.userId
    val sync = remember(channelId) { channelId?.let { GameSync(model, it) } }

    var board by remember { mutableStateOf(START.map { it.toCharArray() }.toTypedArray()) }
    var turn by remember { mutableStateOf(true) } // true = white to move
    var seq by remember { mutableStateOf(0) }
    var white by remember { mutableStateOf<String?>(null) }
    var black by remember { mutableStateOf<String?>(null) }
    var sel by remember { mutableStateOf<Pair<Int, Int>?>(null) }
    var appliedSeq by remember { mutableStateOf(-1) }
    var appliedBy by remember { mutableStateOf("") }

    fun snapshot(): ChessSnapshot {
        val cells = ArrayList<String>(64)
        for (r in 0..7) for (f in 0..7) cells.add(charToCell(board[r][f]))
        return ChessSnapshot(seq, cells, if (turn) "white" else "black", white, black, me)
    }
    fun applySnap(s: ChessSnapshot) {
        val b = START.map { it.toCharArray() }.toTypedArray()
        for (r in 0..7) for (f in 0..7) b[r][f] = '.'
        for (i in 0 until minOf(64, s.cells.size)) b[i / 8][i % 8] = cellToChar(s.cells[i])
        board = b; turn = s.turn == "white"; white = s.white; black = s.black; seq = s.seq; sel = null
    }
    fun mayMove(pieceWhite: Boolean): Boolean {
        if (me == null) return true
        val seat = if (pieceWhite) white else black
        return seat == null || seat == me
    }

    // Follow the opponent's moves (event-driven, see GameSync.watch); converge on the deterministic winner (highest seq, ties broken
    // by smallest mover id). Never revert a local move we haven't broadcast (win.seq >= our seq).
    LaunchedEffect(channelId) {
        val s = sync ?: return@LaunchedEffect
        s.watch {
            val events = s.fetchChess().map { it.event }
            val win = events.maxWithOrNull(compareBy<ChessSnapshot> { it.seq }.thenByDescending { it.by ?: "" })
            if (win != null) {
                val winBy = win.by ?: ""
                val newer = win.seq > appliedSeq || (win.seq == appliedSeq && winBy < appliedBy)
                if (newer && win.seq >= seq) { applySnap(win); appliedSeq = win.seq; appliedBy = winBy }
            }
        }
    }

    fun legal(fromR: Int, fromF: Int, toR: Int, toF: Int): Boolean {
        val p = board[fromR][fromF]; if (p == '.') return false
        val target = board[toR][toF]
        if (isWhite(p) && isWhite(target)) return false
        if (!isWhite(p) && target != '.' && !isWhite(target)) return false
        val dr = toR - fromR; val df = toF - fromF
        val adr = kotlin.math.abs(dr); val adf = kotlin.math.abs(df)
        return when (p.lowercaseChar()) {
            'p' -> {
                val fwd = if (isWhite(p)) -1 else 1
                (df == 0 && dr == fwd && target == '.') ||
                    (df == 0 && dr == 2 * fwd && target == '.' && board[fromR + fwd][fromF] == '.' &&
                        ((isWhite(p) && fromR == 6) || (!isWhite(p) && fromR == 1))) ||
                    (adf == 1 && dr == fwd && target != '.' && isWhite(target) != isWhite(p))
            }
            'n' -> (adr == 2 && adf == 1) || (adr == 1 && adf == 2)
            'b' -> adr == adf && adr > 0 && pathClear(fromR, fromF, toR, toF, board)
            'r' -> (dr == 0 || df == 0) && (adr + adf > 0) && pathClear(fromR, fromF, toR, toF, board)
            'q' -> ((adr == adf && adr > 0) || dr == 0 || df == 0) && (adr + adf > 0) &&
                pathClear(fromR, fromF, toR, toF, board)
            'k' -> adr <= 1 && adf <= 1 && (adr + adf > 0)
            else -> false
        }
    }

    val seat = when {
        me == null -> null
        white == me -> true
        black == me -> true
        white == null -> true
        black == null -> false
        else -> null
    }
    val statusLine = when {
        channelId == null -> "Tap a piece, then a highlighted square."
        seat == null -> "Watching — both seats are taken."
        else -> {
            val mine = (seat && turn) || (!seat && !turn)
            if (mine) "Your move — you're ${if (seat) "White ♔" else "Black ♚"}"
            else "You're ${if (seat) "White ♔" else "Black ♚"} — waiting for your opponent"
        }
    }

    Column(Modifier.fillMaxSize().padding(12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            ScreenTitle("Chess", subtitle = if (turn) "White to move" else "Black to move")
            Spacer(Modifier.weight(1f))
            TextButton(onClick = {
                board = START.map { it.toCharArray() }.toTypedArray(); turn = true; sel = null
                seq += 1; white = null; black = null
                sync?.let { scope.launch { it.sendChess(snapshot()) } }
            }) { Text("Reset") }
        }
        Spacer(Modifier.height(4.dp))
        Text(statusLine, color = Color.White.copy(alpha = 0.55f), style = MaterialTheme.typography.labelSmall)
        Spacer(Modifier.height(12.dp))
        for (r in 0..7) {
            Row(Modifier.fillMaxWidth()) {
                for (f in 0..7) {
                    val dark = (r + f) % 2 == 1
                    val isSel = sel == (r to f)
                    Box(
                        Modifier.weight(1f).aspectRatio(1f)
                            .background(if (isSel) SkAccent.copy(alpha = 0.45f) else if (dark) Color(0xFF11151F) else Color(0xFF2A3142))
                            .clickable {
                                val piece = board[r][f]
                                if (sel != null) {
                                    val (sr, sf) = sel!!
                                    val mover = board[sr][sf]
                                    if (legal(sr, sf, r, f) && isWhite(mover) == turn && mayMove(isWhite(mover))) {
                                        // Claim the seat for this color on first move.
                                        if (me != null) {
                                            if (isWhite(mover) && white == null) white = me
                                            if (!isWhite(mover) && black == null) black = me
                                        }
                                        board[r][f] = mover; board[sr][sf] = '.'
                                        // Promotion to queen at the last rank.
                                        if (mover.lowercaseChar() == 'p' && (r == 0 || r == 7))
                                            board[r][f] = if (isWhite(mover)) 'Q' else 'q'
                                        board = board.map { it.copyOf() }.toTypedArray()
                                        turn = !turn; seq += 1
                                        sync?.let { scope.launch { it.sendChess(snapshot()) } }
                                    }
                                    sel = null
                                } else if (piece != '.' && isWhite(piece) == turn && mayMove(isWhite(piece))) {
                                    sel = r to f
                                }
                            },
                        contentAlignment = Alignment.Center
                    ) {
                        val p = board[r][f]
                        if (p != '.') Text(
                            glyph(p), fontSize = 30.sp, fontWeight = FontWeight.Bold,
                            color = if (isWhite(p)) Color.White else Color.Black
                        )
                    }
                }
            }
        }
    }
}

private fun pathClear(fr: Int, ff: Int, tr: Int, tf: Int, b: Array<CharArray>): Boolean {
    val sr = Integer.signum(tr - fr); val sf = Integer.signum(tf - ff)
    var r = fr + sr; var f = ff + sf
    while (r != tr || f != tf) {
        if (!inB(r, f) || b[r][f] != '.') return false
        r += sr; f += sf
    }
    return true
}
