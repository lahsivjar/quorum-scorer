package dev.quorumscore.protocol

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class JvmSignatureTest {
    @Test
    fun entryHashUsesTheDomainPrefix() {
        val canonical = """{"a":1}""".encodeToByteArray()
        val expected = sha256ForTest("QS1\n".encodeToByteArray() + canonical)
        assertEquals(expected, entryHash(canonical))
    }

    @Test
    fun lowSSignatureVerifiesAndHighSDoesNot() {
        val keys = keyPair()
        val message = "QS1-SIG\n".encodeToByteArray() + ByteArray(32) { 7 }
        val signature = JvmP256.sign(keys.private, message)
        val spki = (keys.public as ECPublicKey).encoded
        assertTrue(isLowS(signature))
        assertTrue(JvmVerifier.verify(spki, message, signature))
        val high = highS(signature)
        assertFalse(isLowS(high))
        assertFalse(JvmVerifier.verify(spki, message, high))
        val flipped = message.copyOf()
        flipped[flipped.lastIndex] = (flipped[flipped.lastIndex] + 1).toByte()
        assertFalse(JvmVerifier.verify(spki, flipped, signature))
    }

    @Test
    fun aRealMajorityCommitsAndAFlippedLabelDoesNot() {
        val ada = keyPair()
        val bea = keyPair()
        val cam = keyPair()
        val adaId = "11111111-1111-4111-8111-111111111111"
        val beaId = "22222222-2222-4222-8222-222222222222"
        val camId = "33333333-3333-4333-8333-333333333333"
        val created = 1_760_745_600_000L
        val expires = created + 86_400_000L
        val members = listOf(
            Member(adaId, Base64.encode(ada.public.encoded), "Ada"),
            Member(beaId, Base64.encode(bea.public.encoded), "Bea"),
            Member(camId, Base64.encode(cam.public.encoded), "Cam"),
        )
        val genesis = Entries.genesis(
            "6f1d5c0a2e8b4c7d9a1b3e5f708192a3",
            adaId,
            "Thursday Table",
            members,
            created,
            expires,
        )
        val score = Entries.scoreBatch(
            "6f1d5c0a2e8b4c7d9a1b3e5f708192a3",
            1,
            entryHash(genesis),
            adaId,
            listOf(Line(10, "Catan", "won", adaId)),
            created,
            expires,
        )
        val ok = fold(
            listOf(
                signed(genesis, adaId to ada.private, beaId to bea.private, camId to cam.private),
                signed(score, adaId to ada.private, beaId to bea.private),
            ),
            JvmVerifier,
        )
        val state = assertIs<FoldResult.Ok>(ok).state
        assertEquals(10L, state.totals.getValue(adaId))
        assertEquals(10L, state.byLabel.getValue("Catan").getValue(adaId))

        val flipped = score.copyOf()
        val label = "Catan".encodeToByteArray()
        val at = indexOf(flipped, label)
        flipped[at] = (flipped[at] + 1).toByte()
        val ignored = fold(
            listOf(
                signed(genesis, adaId to ada.private, beaId to bea.private, camId to cam.private),
                ReceivedEntry(flipped, signed(score, adaId to ada.private, beaId to bea.private).signatures),
            ),
            JvmVerifier,
        )
        assertEquals(0L, assertIs<FoldResult.Ok>(ignored).state.totals.getValue(adaId))
    }
}

private fun keyPair() = KeyPairGenerator.getInstance("EC").apply {
    initialize(ECGenParameterSpec("secp256r1"))
}.generateKeyPair()

private fun signed(bytes: ByteArray, vararg keys: Pair<String, java.security.PrivateKey>): ReceivedEntry {
    val input = sigInput(entryHash(bytes))
    return ReceivedEntry(bytes, keys.map { (id, key) -> MemberSig(id, JvmP256.sign(key, input)) })
}

private fun sha256ForTest(bytes: ByteArray): String {
    val digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
    return buildString(digest.size * 2) {
        for (byte in digest) append("%02x".format(byte))
    }
}

private fun highS(signature: ByteArray): ByteArray {
    val n = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    val s = BigInteger(1, signature.copyOfRange(32, 64))
    val flipped = n.subtract(s).toByteArray().let { raw ->
        val mag = if (raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
        ByteArray(32 - mag.size) + mag
    }
    return signature.copyOfRange(0, 32) + flipped
}

private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
    for (start in 0..haystack.size - needle.size) {
        if (haystack.copyOfRange(start, start + needle.size).contentEquals(needle)) return start
    }
    error("missing")
}
