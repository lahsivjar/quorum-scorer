package dev.quorumscore.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CanonicalJsonTest {
    @Test
    fun sortsObjectKeysByUtf16() {
        val value = Jv.Obj(
            listOf(
                "b" to Jv.Num(1),
                "a" to Jv.Num(2),
            ),
        )
        assertEquals("""{"a":2,"b":1}""", encode(value))
    }

    @Test
    fun utf16OrderSortsASurrogatePairByItsCodeUnits() {
        val emoji = "\uD83D\uDE00"
        val replacement = "\uFFFD"
        val encoded = encode(Jv.Obj(listOf(replacement to Jv.Num(1), emoji to Jv.Num(2))))
        assertTrue(encoded.indexOf(emoji) < encoded.indexOf(replacement))
    }

    @Test
    fun rejectsNonCanonicalBytes() {
        val pretty = "{\n  \"b\": 1, \"a\": 2\n}".encodeToByteArray()
        assertNull(parseCanonical(pretty))
        val canonical = canonicalBytes(parseJson("""{"b":1,"a":2}"""))
        assertEquals(parseJson("""{"a":2,"b":1}"""), parseCanonical(canonical))
    }

    @Test
    fun rejectsForbiddenLiteralsFloatsAndDuplicates() {
        assertFailsWith<JsonException> { parseJson("true") }
        assertFailsWith<JsonException> { parseJson("null") }
        assertFailsWith<JsonException> { parseJson("1.5") }
        assertFailsWith<JsonException> { parseJson("{\"a\":1,\"a\":2}") }
        assertFailsWith<JsonException> { parseJson("01") }
        assertFailsWith<JsonException> { parseJson((JSON_INT_MAX + 1).toString()) }
    }

    @Test
    fun acceptsTheSafeIntegerEdge() {
        val edge = JSON_INT_MAX
        assertEquals(Jv.Num(edge), parseJson(edge.toString()))
        assertEquals(Jv.Num(-edge), parseJson((-edge).toString()))
    }
}

private const val JSON_INT_MAX = (1L shl 53) - 1
