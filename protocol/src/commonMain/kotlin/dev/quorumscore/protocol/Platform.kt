package dev.quorumscore.protocol

internal expect fun sha256(data: ByteArray): ByteArray

internal expect fun decodeUtf8Strict(bytes: ByteArray): String?

internal expect fun isNfc(value: String): Boolean
