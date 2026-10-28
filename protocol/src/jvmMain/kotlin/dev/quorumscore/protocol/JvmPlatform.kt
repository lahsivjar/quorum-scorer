package dev.quorumscore.protocol

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.text.Normalizer
import java.security.MessageDigest

private val CURVE_N = BigInteger(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
private val HALF_N = CURVE_N.shiftRight(1)

actual fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

actual fun decodeUtf8Strict(bytes: ByteArray): String? {
    val decoder = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
    return try {
        decoder.decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: CharacterCodingException) {
        null
    }
}

actual fun isNfc(value: String): Boolean = Normalizer.isNormalized(value, Normalizer.Form.NFC)

object JvmVerifier : Verifier {
    override fun verify(spkiDer: ByteArray, sigInput: ByteArray, signature: ByteArray): Boolean {
        if (!isLowS(signature)) return false
        return try {
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spkiDer))
            val ecdsa = Signature.getInstance("SHA256withECDSA")
            ecdsa.initVerify(key)
            ecdsa.update(sigInput)
            ecdsa.verify(p1363ToDer(signature))
        } catch (_: Exception) {
            false
        }
    }
}

object JvmP256 {
    fun sign(privateKey: PrivateKey, sigInput: ByteArray): ByteArray {
        val ecdsa = Signature.getInstance("SHA256withECDSA")
        ecdsa.initSign(privateKey)
        ecdsa.update(sigInput)
        return lowS(derToP1363(ecdsa.sign()))
    }
}

private fun lowS(signature: ByteArray): ByteArray {
    val r = BigInteger(1, signature.copyOfRange(0, 32))
    var s = BigInteger(1, signature.copyOfRange(32, 64))
    if (s > HALF_N) s = CURVE_N.subtract(s)
    return pad32(r) + pad32(s)
}

private fun pad32(value: BigInteger): ByteArray {
    val raw = value.toByteArray()
    val body = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size) else raw
    return ByteArray(32 - body.size) + body
}

private fun p1363ToDer(signature: ByteArray): ByteArray {
    val r = integer(signature.copyOfRange(0, 32))
    val s = integer(signature.copyOfRange(32, 64))
    val body = r + s
    return byteArrayOf(0x30, body.size.toByte()) + body
}

private fun derToP1363(der: ByteArray): ByteArray {
    var i = 2
    fun readInt(): ByteArray {
        check(der[i] == 0x02.toByte())
        val len = der[i + 1].toInt() and 0xFF
        val start = i + 2
        i = start + len
        return der.copyOfRange(start, i)
    }
    return pad32(BigInteger(1, readInt())) + pad32(BigInteger(1, readInt()))
}

private fun integer(unsigned: ByteArray): ByteArray {
    var start = 0
    while (start < unsigned.size - 1 && unsigned[start] == 0.toByte()) start++
    val mag = unsigned.copyOfRange(start, unsigned.size)
    val body = if (mag[0].toInt() and 0x80 != 0) byteArrayOf(0) + mag else mag
    return byteArrayOf(0x02, body.size.toByte()) + body
}
