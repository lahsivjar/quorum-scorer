package dev.quorumscore.protocol

import kotlin.io.encoding.Base64

/** Half the secp256r1 order. A signature is low-S when `s` is at most this value. */
private const val HALF_N = "7fffffff800000007fffffffffffffffffde737d56d38bcf4279dce5617e3192a8"

fun interface Verifier {
    /**
     * True when [signature] is a valid P-1363 signature by [spkiDer] over [sigInput].
     * Callers reject high-S signatures before this returns.
     */
    fun verify(spkiDer: ByteArray, sigInput: ByteArray, signature: ByteArray): Boolean
}

fun isLowS(signature: ByteArray): Boolean {
    if (signature.size != 64) return false
    val r = signature.copyOfRange(0, 32)
    val s = signature.copyOfRange(32, 64)
    if (r.all { it == 0.toByte() } || s.all { it == 0.toByte() }) return false
    return s.toHexString() <= HALF_N
}

fun entryHash(canonical: ByteArray): String {
    val prefixed = "QS1\n".encodeToByteArray() + canonical
    return sha256(prefixed).toHexString()
}

fun sigInput(hashHex: String): ByteArray {
    require(hashHex.all { it in '0'..'9' || it in 'a'..'f' }) { "hex" }
    return "QS1-SIG\n".encodeToByteArray() + hashHex.hexToByteArray()
}

internal fun consentSigInput(consentCanonical: ByteArray): ByteArray {
    val hash = sha256("QS1-CONSENT\n".encodeToByteArray() + consentCanonical)
    return "QS1-CONSENT-SIG\n".encodeToByteArray() + hash
}

internal fun decodeSpki(b64: String): ByteArray? {
    if (b64.isEmpty() || b64.any { it.isWhitespace() }) return null
    val bytes = try {
        Base64.decode(b64)
    } catch (_: IllegalArgumentException) {
        return null
    }
    if (bytes.isEmpty() || Base64.encode(bytes) != b64) return null
    return bytes
}
