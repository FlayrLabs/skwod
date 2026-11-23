package io.skwod.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Someone who is not (yet) accepted into a server and needs a member's decision. */
data class WaitingMember(
    val userId: String,
    /** The name the SERVER gives this account. It is a claim until [trust] says it checks out. */
    val username: String,
    val source: Source,
    /** Whether that name really belongs to this account (see [WaitingTrust]). */
    val trust: WaitingTrust.Verdict = WaitingTrust.Verdict.UNCHECKED,
    /** The account's key fingerprint as this device holds it — independent of any name. */
    val fingerprint: String? = null,
    /** Nobody the user has history with: no conversation with this account, never verified. */
    val isNew: Boolean = false,
    /**
     * Whether this device has PINNED [fingerprint]. Listing someone never pins (the list only
     * peeks), so a first-sight fingerprint is shown as "unverified": it is what the server lists
     * right now, nothing more.
     */
    val fingerprintPinned: Boolean = false,
) {
    /** "Let in" is offered only for an entry whose name checked out. */
    val canLetIn: Boolean get() = trust == WaitingTrust.Verdict.OK
    /** A short, readable form of the fingerprint: the first two blocks. */
    val shortFingerprint: String? get() = fingerprint?.takeIf { it.length >= 10 }?.let { "${it.substring(0, 5)} ${it.substring(5, 10)}" }
    /** The fingerprint as the list shows it: an unpinned one is always labelled "unverified". */
    val fingerprintLabel: String get() = shortFingerprint?.let { if (fingerprintPinned) it else "$it (unverified)" } ?: "unknown"
    /** The name as it may be DISPLAYED: invisible characters never reach the screen. */
    val displayName: String get() = NameSkeleton.visible(username)

    enum class Source {
        /** Asked to join with an invite that needs approval. The server has not admitted them. */
        REQUEST,
        /**
         * The server already lists them as a member — they used an auto-join link, or the server
         * simply added them — but nobody this device trusts has let them in. This device gives
         * them no keys until someone does.
         */
        HELD,
    }
}

/**
 * Is the name on a "Waiting to join" entry trustworthy enough to act on?
 *
 * "Let in" signs a member approval that every other member's device will honour, and the user
 * decides by reading a NAME. But the name comes from the server: a hostile host can list a ghost
 * account under a friend's name. So before the name is shown as a name:
 *
 * - the directory lookup for that username (`findUser`) must return this very account. If it
 *   returns another account, or nobody, the label is not this account's name;
 * - the name must not be the name of someone ELSE the user already has here — an accepted member
 *   of the server, or a DM contact — under a different account id. That is what an impersonation
 *   looks like, and it gets the strongest warning.
 *
 * - the comparison is on confusable SKELETONS, not on the characters: `mеrhan` with a Cyrillic
 *   е, `merhan` with a zero-width space in it and full-width `ｍｅｒｈａｎ` all look like "merhan"
 *   and all collide with it ([NameSkeleton]);
 * - a name with anything but plain ASCII in it is never OK. Usernames here are `[a-z0-9_]`, so
 *   such a name is not one the server would have accepted from a person typing it.
 *
 * Anything but [Verdict.OK] disables "Let in". Pure (no android.*), so it is unit-tested.
 */
object WaitingTrust {
    enum class Verdict {
        /** The name resolves to this account and collides with nobody the user knows. */
        OK,
        /** Not checked yet, or the directory could not be reached. No decision is offered. */
        UNCHECKED,
        /** The directory says this username belongs to a different account (or to nobody). */
        NAME_MISMATCH,
        /** Someone the user already knows by this name has a DIFFERENT account id. */
        IMPERSONATION,
        /**
         * The name contains non-ASCII or invisible characters (look-alike letters, zero-width
         * characters, full-width forms). Never let in on the strength of such a name.
         */
        UNUSUAL_CHARACTERS,
    }

    /** What `findUser(username)` said. */
    sealed class Lookup {
        data class Found(val userId: String) : Lookup()
        /** The directory has no such user. */
        object Nobody : Lookup()
        /** The lookup itself failed (offline, server error). */
        object Failed : Lookup()
    }

    /**
     * Usernames are compared the way the server stores them — trimmed, case-folded — after
     * compatibility normalization (NFKC) and with every invisible character removed.
     */
    fun normalize(name: String): String = NameSkeleton.fold(name)

    /** [known]: accounts the user already knows under a name, as (user id, name). */
    fun assess(userId: String, username: String, lookup: Lookup, known: List<Pair<String, String>>): Verdict {
        if (normalize(username).isEmpty()) return Verdict.NAME_MISMATCH
        // What the eye sees decides: two names with the same skeleton are the same name to a reader.
        val skeleton = NameSkeleton.skeleton(username)
        if (known.any { it.first != userId && NameSkeleton.skeleton(it.second) == skeleton }) return Verdict.IMPERSONATION
        if (NameSkeleton.isUnusual(username)) return Verdict.UNUSUAL_CHARACTERS
        return when (lookup) {
            is Lookup.Failed -> Verdict.UNCHECKED
            is Lookup.Nobody -> Verdict.NAME_MISMATCH
            is Lookup.Found -> if (lookup.userId == userId) Verdict.OK else Verdict.NAME_MISMATCH
        }
    }

    /** What to say under an entry whose name did not check out: (text, strong). */
    fun warning(w: WaitingMember): Pair<String, Boolean>? = when (w.trust) {
        Verdict.OK -> null
        Verdict.UNCHECKED -> "Couldn't check this name against the account yet. Let in is off until it has been checked." to false
        Verdict.NAME_MISMATCH -> "This name doesn't match this account: looking the name up does not lead to it. Don't let them in on the strength of the name." to false
        Verdict.IMPERSONATION -> "Possible impersonation. You already know someone whose name looks like ${w.displayName}, and this is a DIFFERENT account. Do not let it in." to true
        Verdict.UNUSUAL_CHARACTERS -> "This name contains unusual or invisible characters, which real usernames here never have. It may be made to look like someone else's name. Let in is off." to true
    }
}

/**
 * What a name LOOKS like, for comparing names the way a reader does (UTS #39 "skeleton").
 *
 * [fold]: NFKC (full-width and other compatibility forms become the plain letters), every
 * invisible character removed (format/control characters, default-ignorables, variation
 * selectors, Hangul fillers, tag characters), case-folded. [skeleton] then maps look-alikes onto
 * one representative: Cyrillic and Greek letters onto the Latin ones they imitate, and the usual
 * Latin/digit confusions (0/o, 1/l/i, rn/m, vv/w). Two names with the same skeleton read the
 * same. The table is deliberately small: it only has to make an imitation of an ASCII username
 * collide with it, and anything non-ASCII is refused outright anyway ([isUnusual]).
 * Pure Kotlin/JDK (`java.text.Normalizer`), so it is unit-tested on the JVM.
 */
object NameSkeleton {
    /** Characters that take no space on screen (or only steer layout). */
    fun isInvisible(cp: Int): Boolean {
        val type = Character.getType(cp)
        if (type == Character.FORMAT.toInt() || type == Character.CONTROL.toInt()) return true
        return cp == 0x00AD || cp == 0x034F || cp in 0x115F..0x1160 || cp in 0x17B4..0x17B5 ||
            cp in 0x180B..0x180F || cp in 0x200B..0x200F || cp in 0x202A..0x202E || cp in 0x2060..0x206F ||
            cp == 0x3164 || cp in 0xFE00..0xFE0F || cp == 0xFEFF || cp == 0xFFA0 || cp in 0xE0000..0xE0FFF
    }

    private fun stripInvisible(s: String): String {
        val out = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            if (!isInvisible(cp)) out.appendCodePoint(cp)
            i += Character.charCount(cp)
        }
        return out.toString()
    }

    private fun nfkc(s: String): String = java.text.Normalizer.normalize(s, java.text.Normalizer.Form.NFKC)

    /** The name with nothing invisible in it — what may be put on screen. */
    fun visible(name: String): String = stripInvisible(name).trim()

    /** NFKC, invisible characters removed, case-folded, trimmed. */
    fun fold(name: String): String {
        // Strip on both sides of NFKC: normalization can itself produce a filler (U+3164 → U+1160).
        val plain = stripInvisible(nfkc(stripInvisible(name)))
        // Upper- then lower-casing folds the characters a single pass leaves apart (ς/σ, ſ/s).
        return nfkc(plain.uppercase(java.util.Locale.ROOT).lowercase(java.util.Locale.ROOT)).trim()
    }

    /**
     * True when the name has anything in it that an honest `[a-z0-9_]` username cannot have:
     * a non-ASCII character or an invisible one. (Case and surrounding spaces do not count.)
     */
    fun isUnusual(name: String): Boolean {
        val t = name.trim()
        var i = 0
        while (i < t.length) {
            val cp = t.codePointAt(i)
            if (cp > 0x7E || cp < 0x20 || isInvisible(cp)) return true
            i += Character.charCount(cp)
        }
        return false
    }

    /** Look-alike → the Latin character it imitates (applied to the folded, mark-free name). */
    private val confusables: Map<Int, String> = HashMap<Int, String>().apply {
        fun put(chars: String, latin: String) { var i = 0; while (i < chars.length) { val cp = chars.codePointAt(i); this[cp] = latin; i += Character.charCount(cp) } }
        // Cyrillic (lower case; the name is case-folded first).
        put("\u0430\u04D1\u04D3", "a"); put("\u0432\u044C\u0463", "b"); put("\u0441\u04AB", "c"); put("\u0501\u0256", "d")
        put("\u0435\u0451\u0454\u04BD", "e"); put("\u0493", "f"); put("\u0261\u0581", "g"); put("\u04BB\u043D\u0570", "h")
        put("\u0456\u0457\u04CF\u0131", "l"); put("\u0458", "j"); put("\u043A\u049B", "k"); put("\u043C", "m")
        put("\u043F\u0578\u057C", "n"); put("\u043E\u0585\u05E1", "o"); put("\u0440", "p"); put("\u051B\u0566", "q")
        put("\u0433", "r"); put("\u0455", "s"); put("\u0442", "t"); put("\u0446\u057D", "u"); put("\u0475\u0474", "v")
        put("\u051D\u0448\u0461", "w"); put("\u0445\u04B3", "x"); put("\u0443\u04AF\u04B1", "y"); put("\u0437", "3"); put("\u0431", "6")
        // Greek.
        put("\u03B1", "a"); put("\u03B2", "b"); put("\u03F2", "c"); put("\u03B5", "e"); put("\u03B7", "n"); put("\u03B9", "l")
        put("\u03F3", "j"); put("\u03BA", "k"); put("\u03BC", "u"); put("\u03BD", "v"); put("\u03BF\u03C3", "o"); put("\u03C1", "p")
        put("\u03C4", "t"); put("\u03C5", "u"); put("\u03C7", "x"); put("\u03C9", "w"); put("\u03B3", "y")
        // Latin / digits / punctuation that read alike.
        put("0", "o"); put("1i|!", "l"); put("\u00F8", "o"); put("\u0111", "d"); put("\u0142", "l"); put("\u00DF", "ss")
        put("\u2010\u2011\u2012\u2013\u2014\u2212", "-")
    }

    /** The name as its look-alike-free skeleton; equal skeletons read as the same name. */
    fun skeleton(name: String): String {
        // Decompose and drop combining marks, so "mérhan" and "merhan" meet.
        val decomposed = java.text.Normalizer.normalize(fold(name), java.text.Normalizer.Form.NFD)
        val out = StringBuilder(decomposed.length)
        var i = 0
        while (i < decomposed.length) {
            val cp = decomposed.codePointAt(i)
            i += Character.charCount(cp)
            val type = Character.getType(cp)
            if (type == Character.NON_SPACING_MARK.toInt() || type == Character.ENCLOSING_MARK.toInt() ||
                type == Character.COMBINING_SPACING_MARK.toInt() || Character.isWhitespace(cp)) continue
            val mapped = confusables[cp]
            if (mapped != null) out.append(mapped) else out.appendCodePoint(cp)
        }
        // Sequences that read as one letter.
        return out.toString().replace("rn", "m").replace("vv", "w")
    }
}

/** Ask the directory which account a username belongs to (`findUser`), as a [WaitingTrust.Lookup]. */
suspend fun directoryLookup(c: uniffi.skwod_core.SkwodClient, username: String): WaitingTrust.Lookup =
    if (username.isEmpty()) WaitingTrust.Lookup.Nobody else try {
        WaitingTrust.Lookup.Found(c.findUser(username).userId)
    } catch (e: uniffi.skwod_core.CoreException.Engine) {
        if (e.detail.contains("404") || e.detail.contains("user not found")) WaitingTrust.Lookup.Nobody else WaitingTrust.Lookup.Failed
    } catch (_: Exception) { WaitingTrust.Lookup.Failed }

/**
 * Who is waiting to join each server: join requests that need approval plus members the core is
 * holding. This replaces the alert that used to pop up per person; it feeds the "Waiting to join"
 * section of the members view and the badge on the members button. The Android peer of Apple's
 * `WaitingRoom`.
 */
class WaitingRoom(private val model: AppModel) {
    /** serverId → people waiting (Compose state: the badge and the list recompose). */
    private val byServer = mutableStateMapOf<String, List<WaitingMember>>()
    /** A decision that did not go through, shown under the list. */
    var problem by mutableStateOf<String?>(null)
    /** People with a decision in flight (their buttons are disabled). */
    private val busy = mutableStateMapOf<String, Boolean>()

    fun waiting(serverId: String): List<WaitingMember> = byServer[serverId] ?: emptyList()
    fun count(serverId: String): Int = byServer[serverId]?.size ?: 0
    fun isBusy(userId: String): Boolean = busy[userId] == true

    /** Forget everything (workspace switch / sign-out). */
    fun reset() { byServer.clear(); busy.clear(); problem = null }

    /**
     * Re-read who is waiting in [serverId] from the core (held members) and the server (join
     * requests — only people allowed to approve them get a list; for everyone else it is empty).
     */
    suspend fun refresh(serverId: String) {
        val asked = model.bound ?: return
        val c = asked.client
        if (serverId.isEmpty() || serverId == "demo") return
        val out = withContext(Dispatchers.IO) {
            val held = try { c.heldMembers(serverId) } catch (_: Exception) { emptyList() }
            val requests = try { c.listJoinRequests(serverId) } catch (_: Exception) { emptyList() }
            if (held.isEmpty() && requests.isEmpty()) return@withContext emptyList()
            // Only someone the server STILL lists is waiting (see `merge`). Without the list we
            // cannot tell, so leave what is shown as it is.
            val members = try { c.listMembers(serverId).map { it.userId to it.username } } catch (_: Exception) { return@withContext null }
            val merged = merge(requests.map { it.userId to it.username }, held, members.toMap(), model.current?.userId)
            val known = knownPeople(members, merged.map { it.userId }.toSet())
            merged.map { checked(it, c, known) }
        }
        if (out == null) return
        // Answered for the workspace that was asked: after a switch nobody is listed as waiting
        // (and offered "Let in") in the other one.
        if (!Asked.holds(asked, model.bound)) return
        if (out.isEmpty()) byServer.remove(serverId) else if (byServer[serverId] != out) byServer[serverId] = out
    }

    /**
     * Accounts the user already knows under a name: accepted members of the server (everyone it
     * lists who is not waiting) and the people they have DMs with.
     */
    private fun knownPeople(members: List<Pair<String, String>>, waiting: Set<String>): List<Pair<String, String>> =
        // …and everyone in the contact book the user pinned or verified (never a server-only name).
        members.filter { it.first !in waiting } + model.contacts.knownPeople()

    /** Fill in the trust verdict, fingerprint and "new" marker for one entry (IO thread). */
    private suspend fun checked(entry: WaitingMember, c: uniffi.skwod_core.SkwodClient, known: List<Pair<String, String>>): WaitingMember {
        // "New" = nobody the user has history with: no conversation with this account, and
        // never verified. (An existing friend joining one more server is not marked.)
        val hasConversation = model.chat.dms.any { it.peerUserId == entry.userId }
        val isNew = !hasConversation && !(try { c.contactStatus(entry.userId).verified } catch (_: Exception) { false })
        // Listing someone must not trust them: peek never pins. Pinning happens only when the
        // user acts (Let in, starting a DM, verifying).
        val peek = try { c.peekAccountFingerprint(entry.userId) } catch (_: Exception) { null }
        val lookup = directoryLookup(c, entry.username)
        return entry.copy(trust = WaitingTrust.assess(entry.userId, entry.username, lookup, known),
            fingerprint = peek?.fingerprint, fingerprintPinned = peek?.pinned == true, isNew = isNew)
    }

    /**
     * "Let in": the explicit decision the core signs as a member approval. For a join request
     * the server admits them first; then they are provisioned (space + channel keys) when this
     * device can.
     */
    suspend fun letIn(w: WaitingMember, serverId: String) {
        val asked = model.bound ?: return
        val c = asked.client
        if (busy.put(w.userId, true) == true) return
        problem = null
        // The decision is about to be SIGNED: check the label again, now, rather than trusting
        // what was on screen a moment ago. Anything but a clean match stops here.
        val fresh = withContext(Dispatchers.IO) {
            val members = try { c.listMembers(serverId).map { it.userId to it.username } } catch (_: Exception) { return@withContext null }
            checked(w, c, knownPeople(members, waiting(serverId).map { it.userId }.toSet() + w.userId))
        }
        // The workspace changed while the name was being checked: nothing is signed, nothing said.
        if (!Asked.holds(asked, model.bound)) { busy.remove(w.userId); return }
        if (fresh == null || !fresh.canLetIn) {
            problem = if (fresh == null) "Couldn't check ${w.displayName} just now, so nothing was signed. Try again."
            else "Not let in: the name \"${w.displayName}\" does not check out for this account."
            busy.remove(w.userId)
            refresh(serverId)
            return
        }
        var handOffFailed = false
        try {
            withContext(Dispatchers.IO) {
                // The explicit decision is what trusts this account's keys: pin them now (the
                // list itself only ever peeked).
                try { c.accountFingerprint(w.userId) } catch (_: Exception) {}
                when (w.source) {
                    WaitingMember.Source.REQUEST -> {
                        c.approveJoinRequest(serverId, w.userId)
                        handOffFailed = !handOffKeys(c, serverId, w)
                    }
                    WaitingMember.Source.HELD -> c.approveMember(serverId, w.userId)
                }
                // Hand them the channel keys now rather than on the next periodic sync.
                model.current?.userId?.let { me -> try { c.syncServerMembership(serverId, me) } catch (_: Exception) { handOffFailed = true } }
            }
        } catch (e: Exception) {
            if (Asked.holds(asked, model.bound)) problem = "Couldn't let ${w.displayName} in. ${describe(e)}"
        } finally { busy.remove(w.userId) }
        if (!Asked.holds(asked, model.bound)) return
        // "Let in" is the user vouching for this account under this name, on this device.
        // (In the contact book of the workspace it was done in — not one switched to since.)
        if (problem == null && model.client === c) { model.refreshRoster(); if (model.client === c) model.contacts.markKnown(w.userId, w.username, WaitingTrust.Lookup.Found(w.userId)) }
        if (handOffFailed && problem == null) {
            // They are admitted, but have no keys from us yet. Say so, and keep trying.
            problem = "${w.displayName} was let in, but their keys could not be handed over yet. Skwod keeps trying while this device is online."
            retryHandOff(serverId, w)
        }
        refresh(serverId)
    }

    /**
     * Give an approved member the server's keys, retrying a few times: a hand-off that fails
     * (their device is not registered yet, the host blipped) must not be dropped silently.
     * The username lookup must resolve to the SAME account that was approved. Returns success.
     */
    private suspend fun handOffKeys(c: uniffi.skwod_core.SkwodClient, serverId: String, w: WaitingMember, attempts: Int = 3): Boolean {
        for (wait in Backoff.delays(attempts, 1_500, 10_000)) {
            try {
                val found = c.findUser(w.username)
                if (found.userId != w.userId) return false          // not their name any more: send nothing
                c.provisionMember(serverId, found.userId, found.deviceId)
                return true
            } catch (_: Exception) { kotlinx.coroutines.delay(wait) }
        }
        return false
    }

    /** Background retries (30 s → 5 min apart) for a hand-off that did not go through. */
    private fun retryHandOff(serverId: String, w: WaitingMember) {
        val workspace = model.current?.id
        model.launchIO {
            for (wait in Backoff.delays(8, 30_000, 300_000)) {
                kotlinx.coroutines.delay(wait)
                val c = model.client ?: return@launchIO
                if (model.current?.id != workspace) return@launchIO
                if (handOffKeys(c, serverId, w, attempts = 1)) {
                    model.current?.userId?.let { me -> try { c.syncServerMembership(serverId, me) } catch (_: Exception) {} }
                    if (problem?.startsWith(w.displayName) == true) problem = null
                    return@launchIO
                }
            }
            problem = "${w.displayName} still has no keys from this device. Ask them to open Skwod, then open this list again."
        }
    }

    /**
     * "Decline": a join request is denied; a held member is removed from the server (which needs
     * the right to kick — otherwise they simply stay held, with no keys from this device).
     */
    suspend fun decline(w: WaitingMember, serverId: String) {
        val asked = model.bound ?: return
        val c = asked.client
        if (busy.put(w.userId, true) == true) return
        problem = null
        try {
            when (w.source) {
                WaitingMember.Source.REQUEST ->
                    try { withContext(Dispatchers.IO) { c.denyJoinRequest(serverId, w.userId) } }
                    catch (e: Exception) { if (Asked.holds(asked, model.bound)) problem = "Couldn't decline ${w.displayName}. ${describe(e)}" }
                WaitingMember.Source.HELD ->
                    // kickMember also rotates this server's channel keys.
                    if (!model.kickMember(serverId, w.userId) && Asked.holds(asked, model.bound)) {
                        problem = "${w.displayName} is still listed by the server — removing them needs the owner or a moderator. They get no keys from this device either way."
                    }
            }
        } finally { busy.remove(w.userId) }
        refresh(serverId)
    }

    private fun describe(e: Exception): String =
        if (e.message?.contains("403") == true) "You don't have permission." else "Check your connection and try again."

    companion object {
        /**
         * Join requests first, then held members that are not also a request, are not me and
         * are still listed by the server ([names] = its current member list).
         * Pure, so it is unit-tested.
         */
        fun merge(requests: List<Pair<String, String>>, held: List<String>, names: Map<String, String>, me: String?): List<WaitingMember> {
            val out = requests.map { WaitingMember(it.first, it.second, WaitingMember.Source.REQUEST) }.toMutableList()
            val requested = out.map { it.userId }.toSet()
            for (id in held.sorted()) {
                // A held user the server no longer lists (declined, kicked, left) is not waiting.
                val name = names[id] ?: continue
                if (id in requested || id == me) continue
                out.add(WaitingMember(id, name, WaitingMember.Source.HELD))
            }
            return out
        }
    }
}
