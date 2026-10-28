package dev.quorumscore.protocol

/**
 * JSON values the ledger accepts. Objects, arrays, strings, and integers only.
 * Object field order is not significant; [canonicalBytes] sorts keys.
 */
sealed interface Jv {
    data class Obj(val fields: List<Pair<String, Jv>>) : Jv
    data class Arr(val values: List<Jv>) : Jv
    data class Str(val value: String) : Jv
    data class Num(val value: Long) : Jv
}

class JsonException(message: String) : IllegalArgumentException(message)

private const val JSON_INT_MAX = (1L shl 53) - 1
private const val JSON_INT_MIN = -JSON_INT_MAX

fun parseJson(text: String): Jv {
    val parser = Parser(text)
    val value = parser.parseValue()
    parser.skipWs()
    if (!parser.end()) throw JsonException("trailing")
    return value
}

fun canonicalBytes(value: Jv): ByteArray = encode(value).encodeToByteArray()

/** Parses [bytes] and accepts them only when they already are canonical UTF-8. */
fun parseCanonical(bytes: ByteArray): Jv? {
    val text = decodeUtf8Strict(bytes) ?: return null
    val value = try {
        parseJson(text)
    } catch (_: JsonException) {
        return null
    }
    return if (canonicalBytes(value).contentEquals(bytes)) value else null
}

internal fun encode(value: Jv): String = buildString { writeValue(value) }

private fun StringBuilder.writeValue(value: Jv) {
    when (value) {
        is Jv.Obj -> {
            val names = value.fields.map { it.first }
            if (names.size != names.toSet().size) throw JsonException("duplicate")
            append('{')
            value.fields.sortedBy { it.first }.forEachIndexed { index, (key, child) ->
                if (index > 0) append(',')
                writeString(key)
                append(':')
                writeValue(child)
            }
            append('}')
        }
        is Jv.Arr -> {
            append('[')
            value.values.forEachIndexed { index, child ->
                if (index > 0) append(',')
                writeValue(child)
            }
            append(']')
        }
        is Jv.Str -> writeString(value.value)
        is Jv.Num -> append(value.value.toString())
    }
}

private fun StringBuilder.writeString(value: String) {
    append('"')
    for (ch in value) {
        when (ch) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\b' -> append("\\b")
            '\u000C' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (ch.code <= 0x1F) {
                append("\\u")
                append(ch.code.toString(16).padStart(4, '0'))
            } else {
                append(ch)
            }
        }
    }
    append('"')
}

private class Parser(private val text: String) {
    private var i = 0

    fun end(): Boolean = i >= text.length

    fun skipWs() {
        while (i < text.length && text[i].isJsonWs()) i++
    }

    fun parseValue(): Jv {
        skipWs()
        if (end()) throw JsonException("eof")
        return when (text[i]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> Jv.Str(parseString())
            '-', in '0'..'9' -> parseNumber()
            't', 'f', 'n' -> throw JsonException("forbidden literal")
            else -> throw JsonException("value")
        }
    }

    private fun parseObject(): Jv.Obj {
        expect('{')
        skipWs()
        val fields = mutableListOf<Pair<String, Jv>>()
        val seen = mutableSetOf<String>()
        if (consume('}')) return Jv.Obj(fields)
        while (true) {
            skipWs()
            if (end() || text[i] != '"') throw JsonException("key")
            val key = parseString()
            if (!seen.add(key)) throw JsonException("duplicate")
            skipWs()
            expect(':')
            fields += key to parseValue()
            skipWs()
            when {
                consume(',') -> continue
                consume('}') -> break
                else -> throw JsonException("object")
            }
        }
        return Jv.Obj(fields)
    }

    private fun parseArray(): Jv.Arr {
        expect('[')
        skipWs()
        val values = mutableListOf<Jv>()
        if (consume(']')) return Jv.Arr(values)
        while (true) {
            values += parseValue()
            skipWs()
            when {
                consume(',') -> continue
                consume(']') -> break
                else -> throw JsonException("array")
            }
        }
        return Jv.Arr(values)
    }

    private fun parseString(): String {
        expect('"')
        val out = StringBuilder()
        while (i < text.length) {
            val ch = text[i++]
            when {
                ch == '"' -> return out.toString()
                ch == '\\' -> out.append(parseEscape())
                ch.code <= 0x1F -> throw JsonException("raw control")
                else -> out.append(ch)
            }
        }
        throw JsonException("string")
    }

    private fun parseEscape(): Char {
        if (i >= text.length) throw JsonException("escape")
        return when (val ch = text[i++]) {
            '"', '\\', '/' -> ch
            'b' -> '\b'
            'f' -> '\u000C'
            'n' -> '\n'
            'r' -> '\r'
            't' -> '\t'
            'u' -> parseHex4().toChar()
            else -> throw JsonException("escape")
        }
    }

    private fun parseHex4(): Int {
        if (i + 4 > text.length) throw JsonException("hex")
        var n = 0
        repeat(4) {
            n = (n shl 4) or hexValue(text[i++])
        }
        return n
    }

    private fun parseNumber(): Jv.Num {
        val start = i
        if (text[i] == '-') i++
        if (i >= text.length || !text[i].isDigit()) throw JsonException("number")
        if (text[i] == '0') {
            i++
            if (i < text.length && text[i].isDigit()) throw JsonException("leading zero")
        } else {
            while (i < text.length && text[i].isDigit()) i++
        }
        if (i < text.length && text[i] in ".eE") throw JsonException("float")
        val token = text.substring(start, i)
        val value = token.toLongOrNull() ?: throw JsonException("range")
        if (value > JSON_INT_MAX || value < JSON_INT_MIN) throw JsonException("range")
        if (value.toString() != token) throw JsonException("number")
        return Jv.Num(value)
    }

    private fun expect(ch: Char) {
        if (!consume(ch)) throw JsonException("expected $ch")
    }

    private fun consume(ch: Char): Boolean {
        if (i < text.length && text[i] == ch) {
            i++
            return true
        }
        return false
    }
}

private fun Char.isJsonWs(): Boolean = this == ' ' || this == '\n' || this == '\r' || this == '\t'

private fun hexValue(ch: Char): Int = when (ch) {
    in '0'..'9' -> ch.code - '0'.code
    in 'a'..'f' -> ch.code - 'a'.code + 10
    in 'A'..'F' -> ch.code - 'A'.code + 10
    else -> throw JsonException("hex")
}
