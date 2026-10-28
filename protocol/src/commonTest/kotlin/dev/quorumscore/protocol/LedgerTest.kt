package dev.quorumscore.protocol

import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class LedgerTest {
    private val created = 1_760_745_600_000L
    private val expires = created + 86_400_000L
    private val ada = "11111111-1111-4111-8111-111111111111"
    private val bea = "22222222-2222-4222-8222-222222222222"
    private val cam = "33333333-3333-4333-8333-333333333333"
    private val group = "6f1d5c0a2e8b4c7d9a1b3e5f708192a3"
    private val adaKey = Base64.encode("ada-spki-material".encodeToByteArray())
    private val beaKey = Base64.encode("bea-spki-material".encodeToByteArray())
    private val camKey = Base64.encode("cam-spki-material".encodeToByteArray())
    private val verifier = TableVerifier(setOf(adaKey, beaKey, camKey))
    private val members = listOf(
        Member(ada, adaKey, "Ada"),
        Member(bea, beaKey, "Bea"),
        Member(cam, camKey, "Cam"),
    )

    @Test
    fun majorityOverlapsForEveryLegalGroup() {
        for (n in MIN_MEMBERS..MAX_MEMBERS) {
            val t = threshold(n)
            val overlap = 2 * t - n
            assertTrue(t >= 2)
            assertTrue(overlap >= 1)
            assertTrue(overlap < t)
        }
        assertEquals(2, threshold(3))
        assertEquals(3, threshold(4))
        assertEquals(16, threshold(30))
    }

    @Test
    fun lowSRejectsZeroAndHighS() {
        val low = ByteArray(64).also { it[31] = 1; it[63] = 1 }
        assertTrue(isLowS(low))
        assertTrue(!isLowS(ByteArray(64)))
        val high = ByteArray(64).also { it[31] = 1; it.fill(0xFF.toByte(), 32, 64) }
        assertTrue(!isLowS(high))
    }

    @Test
    fun foldIsOrderIndependentAndKeepsGameColumnsWithTheTotal() {
        val chain = story()
        val forward = fold(chain, verifier) as FoldResult.Ok
        val backward = fold(chain.reversed(), verifier) as FoldResult.Ok
        assertEquals(forward.state.totals, backward.state.totals)
        assertEquals(forward.state.byLabel, backward.state.byLabel)
        assertEquals(-2L, forward.state.totals.getValue(ada))
        assertEquals(0L, forward.state.totals.getValue(bea))
        assertEquals(7L, forward.state.totals.getValue(cam))
        assertEquals(0L, forward.state.byLabel.getValue("Board games").getValue(ada))
        assertEquals(-2L, forward.state.byLabel.getValue("Spades").getValue(ada))
        assertEquals(7L, forward.state.byLabel.getValue("Spades").getValue(cam))
        assertTrue(forward.state.partitionHolds())
        assertEquals(4L, forward.state.height)
    }

    @Test
    fun oneSignatureDoesNotChangeTheTotal() {
        val genesis = genesis()
        val score = Entries.scoreBatch(
            group, 1, entryHash(genesis), ada,
            listOf(Line(10, "Catan", "won", ada)),
            created, expires,
        )
        val result = fold(
            listOf(
                received(genesis, ada, bea, cam),
                received(score, ada),
            ),
            verifier,
        ) as FoldResult.Ok
        assertEquals(0L, result.state.totals.getValue(ada))
        assertEquals(0L, result.state.height)
        assertTrue(result.state.byLabel.isEmpty())
    }

    @Test
    fun twoSignedChildrenFreezeAtTheParent() {
        val genesis = genesis()
        val parent = entryHash(genesis)
        val left = Entries.scoreBatch(group, 1, parent, ada, listOf(Line(1, "Catan", "", ada)), created, expires)
        val right = Entries.scoreBatch(group, 1, parent, bea, listOf(Line(2, "Spades", "", bea)), created, expires)
        val result = fold(
            listOf(
                received(genesis, ada, bea, cam),
                received(left, ada, bea),
                received(right, bea, cam),
            ),
            verifier,
        )
        val frozen = assertIs<FoldResult.Frozen>(result)
        assertEquals(0L, frozen.prefix?.height)
        assertEquals(0L, frozen.prefix?.totals?.getValue(ada))
        assertEquals(2, frozen.conflicts.size)
    }

    @Test
    fun aGroupCannotShrinkBelowThree() {
        val genesis = genesis()
        val remove = Entries.removeMember(
            group, 1, entryHash(genesis), ada, cam, "no", created, expires,
        )
        val result = fold(
            listOf(received(genesis, ada, bea, cam), received(remove, ada, bea)),
            verifier,
        ) as FoldResult.Ok
        assertEquals(3, result.state.active.size)
        assertEquals(0L, result.state.height)
    }

    @Test
    fun junkAndHighSSignaturesDoNotDropACommit() {
        val genesis = genesis()
        val score = Entries.scoreBatch(
            group, 1, entryHash(genesis), ada,
            listOf(Line(4, "Chess", "endgame", cam)),
            created, expires,
        )
        val high = ByteArray(64).also { it[31] = 1; it.fill(0xFF.toByte(), 32, 64) }
        val committed = fold(
            listOf(
                received(genesis, ada, bea, cam),
                ReceivedEntry(
                    score,
                    listOf(
                        MemberSig(ada, high),
                        MemberSig(ada, TEST_SIG),
                        MemberSig(bea, TEST_SIG),
                        MemberSig("ffffffff-ffff-ffff-ffff-ffffffffffff", TEST_SIG),
                    ),
                ),
            ),
            verifier,
        ) as FoldResult.Ok
        assertEquals(4L, committed.state.totals.getValue(cam))
        assertEquals(4L, committed.state.byLabel.getValue("Chess").getValue(cam))
    }

    private fun genesis(): ByteArray = Entries.genesis(
        group, ada, "Thursday Table", members, created, expires,
    )

    private fun story(): List<ReceivedEntry> {
        val genesis = genesis()
        val h0 = entryHash(genesis)
        val catan = Entries.scoreBatch(
            group, 1, h0, ada,
            listOf(Line(10, "Catan", "won", ada), Line(5, "Catan", "", bea)),
            created, expires,
        )
        val h1 = entryHash(catan)
        val spades = Entries.scoreBatch(
            group, 2, h1, cam,
            listOf(Line(7, "Spades", "", cam), Line(-2, "Spades", "set", ada)),
            created, expires,
        )
        val h2 = entryHash(spades)
        val rename = Entries.renameLabel(group, 3, h2, ada, "Catan", "Board games", created, expires)
        val h3 = entryHash(rename)
        val undo = Entries.undo(group, 4, h3, bea, h1, created, expires)
        return listOf(
            received(genesis, ada, bea, cam),
            received(catan, ada, bea),
            received(spades, bea, cam),
            received(rename, ada, cam),
            received(undo, bea, cam),
        )
    }

    private fun received(bytes: ByteArray, vararg signers: String): ReceivedEntry {
        return ReceivedEntry(bytes, signers.map { MemberSig(it, TEST_SIG.copyOf()) })
    }
}

private val TEST_SIG = ByteArray(64).also { it[31] = 1; it[63] = 1 }

private class TableVerifier(private val keys: Set<String>) : Verifier {
    override fun verify(spkiDer: ByteArray, sigInput: ByteArray, signature: ByteArray): Boolean {
        return Base64.encode(spkiDer) in keys && signature.contentEquals(TEST_SIG)
    }
}


