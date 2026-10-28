package dev.quorumscore.protocol

const val ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
const val TOTAL_CAP = 1_000_000_000_000L
const val MIN_MEMBERS = 3
const val MAX_MEMBERS = 30

private const val WINDOW_MIN_MS = 60_000L
private const val WINDOW_MAX_MS = 1_209_600_000L
private val KNOWN_TYPES = setOf(
    "genesis",
    "score_batch",
    "undo",
    "add_member",
    "replace_key",
    "remove_member",
    "leave",
    "rename_member",
    "rename_group",
    "rename_label",
    "dissolve",
)

fun threshold(n: Int): Int {
    require(n in MIN_MEMBERS..MAX_MEMBERS) { "n" }
    return n / 2 + 1
}

data class Line(val delta: Long, val label: String, val note: String, val subject: String)

data class Member(val memberId: String, val spkiB64: String, val displayName: String)

enum class Status { Active, Dissolved }

data class GroupState(
    val groupId: String,
    val name: String,
    val status: Status,
    val height: Long,
    val tipHash: String,
    val active: Map<String, Member>,
    val former: Map<String, Member>,
    val totals: Map<String, Long>,
    val byLabel: Map<String, Map<String, Long>>,
    val renamedAway: Map<String, String>,
    val batches: Map<String, List<Line>>,
    val undone: Set<String>,
    val retiredKeys: Set<String>,
)

fun GroupState.partitionHolds(): Boolean {
    val members = totals.keys + byLabel.values.flatMap { it.keys }
    return members.all { member ->
        val parts = byLabel.values.sumOf { it[member] ?: 0L }
        (totals[member] ?: 0L) == parts
    }
}

data class MemberSig(val memberId: String, val bytes: ByteArray)

data class ReceivedEntry(val canonical: ByteArray, val signatures: List<MemberSig>)

sealed interface FoldResult {
    data class Ok(val state: GroupState) : FoldResult
    data class Frozen(val prefix: GroupState?, val conflicts: List<ByteArray>) : FoldResult
    data class Invalid(val reason: String) : FoldResult
    data class UpgradeRequired(val prefix: GroupState) : FoldResult
}

fun fold(entries: List<ReceivedEntry>, verifier: Verifier): FoldResult {
    val parsed = linkedMapOf<String, Parsed>()
    for (received in entries) {
        val value = parseCanonical(received.canonical) ?: continue
        val entry = parseEntry(value, received.canonical) ?: continue
        val prior = parsed[entry.hash]
        if (prior == null) {
            parsed[entry.hash] = entry.copy(signatures = received.signatures)
        } else if (prior.canonical.contentEquals(entry.canonical)) {
            parsed[entry.hash] = prior.copy(signatures = prior.signatures + received.signatures)
        }
    }
    val genesis = parsed.values.filter { isGenesisCandidate(it, verifier) }
    if (genesis.isEmpty()) return FoldResult.Invalid("no_genesis")
    if (genesis.size > 1) return FoldResult.Frozen(null, genesis.map { it.canonical })
    var state = genesisState(genesis.single())
    while (true) {
        val children = parsed.values.filter {
            it.prevHash == state.tipHash && it.height == state.height + 1 && it.groupId == state.groupId
        }
        val foreign = children.filter { it.v != 1 || it.type !in KNOWN_TYPES }
        val valid = children.mapNotNull { child ->
            if (child.v != 1 || child.type !in KNOWN_TYPES) return@mapNotNull null
            if (!windowOk(child)) return@mapNotNull null
            val signers = certificate(child, state.active, verifier)
            val need = threshold(state.active.size)
            if (child.proposer !in signers || signers.size < need) return@mapNotNull null
            apply(state, child, verifier)?.let { child to it }
        }
        when {
            valid.size > 1 -> return FoldResult.Frozen(state, valid.map { it.first.canonical })
            valid.size == 1 -> state = valid.single().second
            foreign.isNotEmpty() -> return FoldResult.UpgradeRequired(state)
            else -> return FoldResult.Ok(state)
        }
    }
}

private data class Parsed(
    val canonical: ByteArray,
    val hash: String,
    val v: Int,
    val type: String,
    val groupId: String,
    val height: Long,
    val prevHash: String,
    val proposer: String,
    val createdAtMs: Long,
    val expiresAtMs: Long,
    val body: Body,
    val signatures: List<MemberSig>,
)

private sealed interface Body {
    data class Genesis(val name: String, val members: List<Member>) : Body
    data class Score(val lines: List<Line>) : Body
    data class Undo(val targetHash: String) : Body
    data class Consenting(val consent: Consent, val sig: ByteArray) : Body
    data class Remove(val subject: String, val note: String) : Body
    data class Leave(val note: String) : Body
    data class RenameMember(val subject: String, val displayName: String) : Body
    data class RenameGroup(val name: String) : Body
    data class RenameLabel(val from: String, val to: String) : Body
    data class Dissolve(val note: String) : Body
    data object Unknown : Body
}

private data class Consent(
    val canonical: ByteArray,
    val displayName: String,
    val groupId: String,
    val memberId: String,
    val spkiB64: String,
)

private class Schema : Exception()

private fun isGenesisCandidate(entry: Parsed, verifier: Verifier): Boolean {
    val body = entry.body as? Body.Genesis ?: return false
    if (entry.v != 1 || entry.type != "genesis") return false
    if (entry.height != 0L || entry.prevHash != ZERO_HASH) return false
    if (!windowOk(entry)) return false
    if (body.members.size !in MIN_MEMBERS..MAX_MEMBERS) return false
    val signers = certificate(entry, body.members.associateBy { it.memberId }, verifier)
    return signers.size == body.members.size && entry.proposer in signers && body.members.all { it.memberId in signers }
}

private fun genesisState(entry: Parsed): GroupState {
    val body = entry.body as Body.Genesis
    return GroupState(
        groupId = entry.groupId,
        name = body.name,
        status = Status.Active,
        height = 0,
        tipHash = entry.hash,
        active = body.members.associateBy { it.memberId },
        former = emptyMap(),
        totals = body.members.associate { it.memberId to 0L },
        byLabel = emptyMap(),
        renamedAway = emptyMap(),
        batches = emptyMap(),
        undone = emptySet(),
        retiredKeys = emptySet(),
    )
}

private fun certificate(entry: Parsed, keys: Map<String, Member>, verifier: Verifier): Set<String> {
    val input = sigInput(entry.hash)
    val accepted = mutableSetOf<String>()
    for (sig in entry.signatures) {
        if (sig.memberId in accepted) continue
        val member = keys[sig.memberId] ?: continue
        val spki = decodeSpki(member.spkiB64) ?: continue
        if (!isLowS(sig.bytes)) continue
        if (verifier.verify(spki, input, sig.bytes)) accepted += sig.memberId
    }
    return accepted
}

private fun windowOk(entry: Parsed): Boolean {
    if (entry.expiresAtMs < entry.createdAtMs) return false
    val span = entry.expiresAtMs - entry.createdAtMs
    return span in WINDOW_MIN_MS..WINDOW_MAX_MS
}

private fun apply(state: GroupState, entry: Parsed, verifier: Verifier): GroupState? {
    if (state.status != Status.Active) return null
    if (entry.proposer !in state.active) return null
    val next = try {
        when (val body = entry.body) {
            is Body.Score -> applyScore(state, entry.hash, body.lines)
            is Body.Undo -> applyUndo(state, body.targetHash)
            is Body.Consenting -> applyConsent(state, entry, body, verifier)
            is Body.Remove -> removeMember(state, body.subject)
            is Body.Leave -> removeMember(state, entry.proposer)
            is Body.RenameMember -> renameMember(state, entry.proposer, body)
            is Body.RenameGroup -> {
                if (!validName(body.name)) return null
                state.copy(name = body.name)
            }
            is Body.RenameLabel -> renameLabel(state, body.from, body.to)
            is Body.Dissolve -> state.copy(status = Status.Dissolved)
            is Body.Genesis, Body.Unknown -> return null
        }
    } catch (_: ArithmeticException) {
        return null
    } catch (_: Schema) {
        return null
    }
    return next.copy(height = entry.height, tipHash = entry.hash)
}

private fun applyScore(state: GroupState, hash: String, lines: List<Line>): GroupState {
    val (totals, byLabel) = addLines(state, lines, requireActive = true, resolveLabels = false)
    return state.copy(totals = totals, byLabel = byLabel, batches = state.batches + (hash to lines))
}

private fun applyUndo(state: GroupState, target: String): GroupState {
    if (target in state.undone) throw Schema()
    val lines = state.batches[target] ?: throw Schema()
    val negated = lines.map { it.copy(delta = it.delta.negExact()) }
    val (totals, byLabel) = addLines(state, negated, requireActive = false, resolveLabels = true)
    return state.copy(totals = totals, byLabel = byLabel, undone = state.undone + target)
}

private fun addLines(
    state: GroupState,
    lines: List<Line>,
    requireActive: Boolean,
    resolveLabels: Boolean,
): Pair<Map<String, Long>, Map<String, Map<String, Long>>> {
    val totals = state.totals.toMutableMap()
    val byLabel = state.byLabel.mapValues { it.value.toMutableMap() }.toMutableMap()
    for (line in lines) {
        if (requireActive && line.subject !in state.active) throw Schema()
        val label = if (resolveLabels) {
            val live = resolveLabel(state, line.label)
            if (live !in state.byLabel) throw Schema()
            live
        } else {
            if (line.label in state.renamedAway) throw Schema()
            line.label
        }
        val bucket = byLabel.getOrPut(label) { mutableMapOf() }
        val nextLabel = addExact(bucket[line.subject] ?: 0L, line.delta)
        if (nextLabel !in -TOTAL_CAP..TOTAL_CAP) throw Schema()
        bucket[line.subject] = nextLabel
        val next = addExact(totals[line.subject] ?: 0L, line.delta)
        if (next !in -TOTAL_CAP..TOTAL_CAP) throw Schema()
        totals[line.subject] = next
    }
    return totals.toMap() to byLabel.mapValues { it.value.toMap() }
}

private fun renameLabel(state: GroupState, from: String, to: String): GroupState {
    if (!validLabel(from) || !validLabel(to) || from == to) throw Schema()
    if (from !in state.byLabel || from in state.renamedAway || to in state.renamedAway) throw Schema()
    val source = state.byLabel.getValue(from)
    val merged = (state.byLabel[to] ?: emptyMap()).toMutableMap()
    for ((member, delta) in source) {
        val next = addExact(merged[member] ?: 0L, delta)
        if (next !in -TOTAL_CAP..TOTAL_CAP) throw Schema()
        merged[member] = next
    }
    val away = state.renamedAway.mapValues { (_, dest) -> if (dest == from) to else dest } + (from to to)
    return state.copy(byLabel = state.byLabel - from + (to to merged), renamedAway = away)
}

private fun resolveLabel(state: GroupState, label: String): String {
    var current = label
    val seen = mutableSetOf<String>()
    while (current in state.renamedAway) {
        if (!seen.add(current)) throw Schema()
        current = state.renamedAway.getValue(current)
    }
    return current
}

private fun applyConsent(state: GroupState, entry: Parsed, body: Body.Consenting, verifier: Verifier): GroupState {
    val consent = body.consent
    if (consent.groupId != entry.groupId) throw Schema()
    if (!validName(consent.displayName)) throw Schema()
    if (!validMemberId(consent.memberId)) throw Schema()
    val spki = decodeSpki(consent.spkiB64) ?: throw Schema()
    if (!isLowS(body.sig) || !verifier.verify(spki, consentSigInput(consent.canonical), body.sig)) throw Schema()
    val adding = entry.type == "add_member"
    if (adding) {
        if (state.active.size + 1 > MAX_MEMBERS) throw Schema()
        if (consent.memberId in state.active || consent.memberId in state.former) throw Schema()
        if (consent.spkiB64 in state.retiredKeys || state.active.values.any { it.spkiB64 == consent.spkiB64 }) throw Schema()
        if (state.former.values.any { it.spkiB64 == consent.spkiB64 }) throw Schema()
        val member = Member(consent.memberId, consent.spkiB64, consent.displayName)
        return state.copy(
            active = state.active + (member.memberId to member),
            totals = state.totals + (member.memberId to 0L),
        )
    }
    val seat = state.active[consent.memberId] ?: throw Schema()
    if (consent.spkiB64 == seat.spkiB64) throw Schema()
    if (consent.spkiB64 in state.retiredKeys) throw Schema()
    val used = (state.active.values + state.former.values).any { it.spkiB64 == consent.spkiB64 }
    if (used) throw Schema()
    val replaced = seat.copy(spkiB64 = consent.spkiB64, displayName = consent.displayName)
    return state.copy(
        active = state.active + (seat.memberId to replaced),
        retiredKeys = state.retiredKeys + seat.spkiB64,
    )
}

private fun removeMember(state: GroupState, subject: String): GroupState {
    val member = state.active[subject] ?: throw Schema()
    if (state.active.size - 1 < MIN_MEMBERS) throw Schema()
    return state.copy(
        active = state.active - subject,
        former = state.former + (subject to member),
        retiredKeys = state.retiredKeys + member.spkiB64,
    )
}

private fun renameMember(state: GroupState, proposer: String, body: Body.RenameMember): GroupState {
    if (body.subject != proposer || body.subject !in state.active || !validName(body.displayName)) throw Schema()
    val member = state.active.getValue(body.subject)
    return state.copy(active = state.active + (body.subject to member.copy(displayName = body.displayName)))
}

private fun parseEntry(value: Jv, canonical: ByteArray): Parsed? {
    return try {
        val root = value.obj()
        root.requireKeys(
            setOf("body", "created_at_ms", "expires_at_ms", "group_id", "height", "prev_hash", "proposer", "type", "v"),
        )
        val type = root.str("type")
        val v = root.num("v").toIntExact()
        val groupId = root.str("group_id")
        val proposer = root.str("proposer")
        val prev = root.str("prev_hash")
        if (!validGroupId(groupId) || !validMemberId(proposer) || !validHash(prev)) throw Schema()
        val header = Parsed(
            canonical = canonical,
            hash = entryHash(canonical),
            v = v,
            type = type,
            groupId = groupId,
            height = root.num("height"),
            prevHash = prev,
            proposer = proposer,
            createdAtMs = root.num("created_at_ms"),
            expiresAtMs = root.num("expires_at_ms"),
            body = Body.Unknown,
            signatures = emptyList(),
        )
        if (header.height < 0) throw Schema()
        if (v != 1 || type !in KNOWN_TYPES) return header
        header.copy(body = parseBody(type, root.obj("body")))
    } catch (_: Schema) {
        null
    } catch (_: ArithmeticException) {
        null
    }
}

private fun parseBody(type: String, body: Map<String, Jv>): Body = when (type) {
    "genesis" -> {
        body.requireKeys(setOf("members", "name", "rules"))
        if (!validName(body.str("name"))) throw Schema()
        rulesMatch(body.obj("rules"))
        val members = (body.getValue("members") as? Jv.Arr)?.values?.map { parseMember(it) } ?: throw Schema()
        if (members.size != members.map { it.memberId }.toSet().size) throw Schema()
        if (members.size != members.map { it.spkiB64 }.toSet().size) throw Schema()
        if (members.zipWithNext().any { it.first.memberId >= it.second.memberId }) throw Schema()
        Body.Genesis(body.str("name"), members)
    }
    "score_batch" -> {
        body.requireKeys(setOf("lines"))
        val lines = (body.getValue("lines") as? Jv.Arr)?.values?.map { parseLine(it) } ?: throw Schema()
        if (lines.isEmpty() || lines.size > 20) throw Schema()
        if (lines.map { it.subject }.distinct().size != lines.size) throw Schema()
        Body.Score(lines)
    }
    "undo" -> {
        body.requireKeys(setOf("target_hash"))
        val target = body.str("target_hash")
        if (!validHash(target)) throw Schema()
        Body.Undo(target)
    }
    "add_member", "replace_key" -> {
        body.requireKeys(setOf("consent_msg", "consent_sig_b64"))
        val consentValue = body.getValue("consent_msg")
        val fields = consentValue.obj()
        fields.requireKeys(setOf("display_name", "group_id", "member_id", "pubkey_spki_b64"))
        val sig = decodeSpki(body.str("consent_sig_b64")) ?: throw Schema()
        if (sig.size != 64) throw Schema()
        Body.Consenting(
            Consent(
                canonical = canonicalBytes(consentValue),
                displayName = fields.str("display_name"),
                groupId = fields.str("group_id"),
                memberId = fields.str("member_id"),
                spkiB64 = fields.str("pubkey_spki_b64"),
            ),
            sig,
        )
    }
    "remove_member" -> {
        body.requireKeys(setOf("note", "subject"))
        val subject = body.str("subject")
        val note = body.str("note")
        if (!validMemberId(subject) || !validNote(note)) throw Schema()
        Body.Remove(subject, note)
    }
    "leave" -> {
        body.requireKeys(setOf("note"))
        val note = body.str("note")
        if (!validNote(note)) throw Schema()
        Body.Leave(note)
    }
    "rename_member" -> {
        body.requireKeys(setOf("display_name", "subject"))
        Body.RenameMember(body.str("subject"), body.str("display_name"))
    }
    "rename_group" -> {
        body.requireKeys(setOf("name"))
        Body.RenameGroup(body.str("name"))
    }
    "rename_label" -> {
        body.requireKeys(setOf("from", "to"))
        Body.RenameLabel(body.str("from"), body.str("to"))
    }
    "dissolve" -> {
        body.requireKeys(setOf("note"))
        val note = body.str("note")
        if (!validNote(note)) throw Schema()
        Body.Dissolve(note)
    }
    else -> throw Schema()
}

private fun parseMember(value: Jv): Member {
    val fields = value.obj()
    fields.requireKeys(setOf("display_name", "member_id", "pubkey_spki_b64"))
    val name = fields.str("display_name")
    val id = fields.str("member_id")
    val key = fields.str("pubkey_spki_b64")
    if (!validName(name) || !validMemberId(id) || decodeSpki(key) == null) throw Schema()
    return Member(id, key, name)
}

private fun parseLine(value: Jv): Line {
    val fields = value.obj()
    fields.requireKeys(setOf("delta", "label", "note", "subject"))
    val line = Line(fields.num("delta"), fields.str("label"), fields.str("note"), fields.str("subject"))
    if (!validLabel(line.label) || !validNote(line.note) || !validMemberId(line.subject)) throw Schema()
    if (line.delta == 0L || line.delta !in -1_000_000L..1_000_000L) throw Schema()
    return line
}

private fun rulesMatch(rules: Map<String, Jv>) {
    val got = canonicalBytes(Jv.Obj(rules.entries.map { it.key to it.value }))
    if (!got.contentEquals(canonicalBytes(rulesJson()))) throw Schema()
}

private fun Jv.obj(): Map<String, Jv> = (this as? Jv.Obj)?.fields?.toMap() ?: throw Schema()

private fun Map<String, Jv>.requireKeys(keys: Set<String>) {
    if (this.keys != keys) throw Schema()
}

private fun Map<String, Jv>.str(key: String): String = (this[key] as? Jv.Str)?.value ?: throw Schema()

private fun Map<String, Jv>.num(key: String): Long = (this[key] as? Jv.Num)?.value ?: throw Schema()

private fun Map<String, Jv>.obj(key: String): Map<String, Jv> = this[key]?.obj() ?: throw Schema()

private fun Long.toIntExact(): Int {
    if (this !in Int.MIN_VALUE..Int.MAX_VALUE) throw ArithmeticException()
    return toInt()
}

private fun addExact(left: Long, right: Long): Long {
    val sum = left + right
    if (((left xor sum) and (right xor sum)) < 0) throw ArithmeticException()
    return sum
}

private fun Long.negExact(): Long {
    if (this == Long.MIN_VALUE) throw ArithmeticException()
    return -this
}

internal fun validName(value: String): Boolean = textOk(value, 1, 40)

internal fun validLabel(value: String): Boolean = textOk(value, 1, 40)

internal fun validNote(value: String): Boolean = textOk(value, 0, 140)

private fun textOk(value: String, min: Int, max: Int): Boolean {
    val count = codePointCount(value)
    if (count !in min..max || !isNfc(value) || value != value.trim()) return false
    return value.none { ch ->
        val code = ch.code
        code <= 0x1F || code == 0x7F || code == 0x2028 || code == 0x2029
    }
}

private fun codePointCount(value: String): Int {
    var index = 0
    var count = 0
    while (index < value.length) {
        index += if (value[index].isHighSurrogate()) 2 else 1
        count++
    }
    return count
}

private fun validMemberId(value: String): Boolean =
    value.length == 36 && value[8] == '-' && value[13] == '-' && value[18] == '-' && value[23] == '-' &&
        value.all { it == '-' || it in '0'..'9' || it in 'a'..'f' }

private fun validGroupId(value: String): Boolean =
    value.length == 32 && value.all { it in '0'..'9' || it in 'a'..'f' }

private fun validHash(value: String): Boolean =
    value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' }

object Entries {
    fun genesis(
        groupId: String,
        proposer: String,
        name: String,
        members: List<Member>,
        createdAtMs: Long,
        expiresAtMs: Long,
    ): ByteArray = document(
        type = "genesis",
        groupId = groupId,
        height = 0,
        prevHash = ZERO_HASH,
        proposer = proposer,
        createdAtMs = createdAtMs,
        expiresAtMs = expiresAtMs,
        body = Jv.Obj(
            listOf(
                "members" to Jv.Arr(members.sortedBy { it.memberId }.map { memberJson(it) }),
                "name" to Jv.Str(name),
                "rules" to rulesJson(),
            ),
        ),
    )

    fun scoreBatch(
        groupId: String,
        height: Long,
        prevHash: String,
        proposer: String,
        lines: List<Line>,
        createdAtMs: Long,
        expiresAtMs: Long,
    ): ByteArray = document(
        type = "score_batch",
        groupId = groupId,
        height = height,
        prevHash = prevHash,
        proposer = proposer,
        createdAtMs = createdAtMs,
        expiresAtMs = expiresAtMs,
        body = Jv.Obj(listOf("lines" to Jv.Arr(lines.map { lineJson(it) }))),
    )

    fun undo(
        groupId: String,
        height: Long,
        prevHash: String,
        proposer: String,
        targetHash: String,
        createdAtMs: Long,
        expiresAtMs: Long,
    ): ByteArray = document(
        type = "undo",
        groupId = groupId,
        height = height,
        prevHash = prevHash,
        proposer = proposer,
        createdAtMs = createdAtMs,
        expiresAtMs = expiresAtMs,
        body = Jv.Obj(listOf("target_hash" to Jv.Str(targetHash))),
    )

    fun renameLabel(
        groupId: String,
        height: Long,
        prevHash: String,
        proposer: String,
        from: String,
        to: String,
        createdAtMs: Long,
        expiresAtMs: Long,
    ): ByteArray = document(
        type = "rename_label",
        groupId = groupId,
        height = height,
        prevHash = prevHash,
        proposer = proposer,
        createdAtMs = createdAtMs,
        expiresAtMs = expiresAtMs,
        body = Jv.Obj(listOf("from" to Jv.Str(from), "to" to Jv.Str(to))),
    )

    fun removeMember(
        groupId: String,
        height: Long,
        prevHash: String,
        proposer: String,
        subject: String,
        note: String,
        createdAtMs: Long,
        expiresAtMs: Long,
    ): ByteArray = document(
        type = "remove_member",
        groupId = groupId,
        height = height,
        prevHash = prevHash,
        proposer = proposer,
        createdAtMs = createdAtMs,
        expiresAtMs = expiresAtMs,
        body = Jv.Obj(listOf("note" to Jv.Str(note), "subject" to Jv.Str(subject))),
    )
}

private fun document(
    type: String,
    groupId: String,
    height: Long,
    prevHash: String,
    proposer: String,
    createdAtMs: Long,
    expiresAtMs: Long,
    body: Jv,
): ByteArray = canonicalBytes(
    Jv.Obj(
        listOf(
            "body" to body,
            "created_at_ms" to Jv.Num(createdAtMs),
            "expires_at_ms" to Jv.Num(expiresAtMs),
            "group_id" to Jv.Str(groupId),
            "height" to Jv.Num(height),
            "prev_hash" to Jv.Str(prevHash),
            "proposer" to Jv.Str(proposer),
            "type" to Jv.Str(type),
            "v" to Jv.Num(1),
        ),
    ),
)

private fun rulesJson(): Jv = Jv.Obj(
    listOf(
        "batch_max_lines" to Jv.Num(20),
        "delta_max" to Jv.Num(1_000_000),
        "delta_min" to Jv.Num(-1_000_000),
        "max_members" to Jv.Num(MAX_MEMBERS.toLong()),
        "min_members" to Jv.Num(MIN_MEMBERS.toLong()),
        "threshold" to Jv.Str("majority"),
        "total_cap" to Jv.Num(TOTAL_CAP),
    ),
)

private fun memberJson(member: Member): Jv = Jv.Obj(
    listOf(
        "display_name" to Jv.Str(member.displayName),
        "member_id" to Jv.Str(member.memberId),
        "pubkey_spki_b64" to Jv.Str(member.spkiB64),
    ),
)

private fun lineJson(line: Line): Jv = Jv.Obj(
    listOf(
        "delta" to Jv.Num(line.delta),
        "label" to Jv.Str(line.label),
        "note" to Jv.Str(line.note),
        "subject" to Jv.Str(line.subject),
    ),
)
