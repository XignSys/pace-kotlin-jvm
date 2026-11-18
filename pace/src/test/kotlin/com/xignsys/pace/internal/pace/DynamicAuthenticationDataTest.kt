package com.xignsys.pace.internal.pace

import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/** The dynamic authentication data `7C` of General Authenticate (TR-03110 Part 3, B.1 and B.11.1). */
class DynamicAuthenticationDataTest {
    @Test
    fun encodesTheEmptyObjectOfStep1() {
        // TR-03110 Part 3, B.1, footnote 5: an empty dynamic authentication data object.
        assertThat(DynamicAuthenticationData.encode()).isEqualTo(hex("7C 00"))
    }

    @Test
    fun decodesTheResponseOfStep4OfTheWorkedExample() {
        val response = WorkedExample.PACE_MUTUAL_AUTHENTICATION_RESPONSE
        val objects = checkNotNull(DynamicAuthenticationData.decode(response.copyOfRange(0, response.size - 2)))

        assertThat(objects.map { it.first }).containsExactly(0x06, 0x07)
        assertThat(objects[0].second).isEqualTo(hex("A2 65 8C 2F 38 60 0B 0F"))
        assertThat(String(objects[1].second, Charsets.ISO_8859_1)).isEqualTo("DECVCAAT00001")
    }

    @Test
    fun encodesAndDecodesInOrder() {
        val encoded = DynamicAuthenticationData.encode(0x07 to hex("41"), 0x06 to hex("01 02"))

        assertThat(encoded).isEqualTo(hex("7C 07 87 01 41 86 02 01 02"))
        assertThat(DynamicAuthenticationData.decode(encoded)?.map { it.first }).containsExactly(0x07, 0x06)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "",
            // another outer tag: a SEQUENCE, a context-specific object, a primitive application object
            "30 03 80 01 00",
            "BC 03 80 01 00",
            "5C 03 80 01 00",
            // trailing bytes, a truncated object
            "7C 03 80 01 00 00",
            "7C 03 80 02 00",
            // inner objects that are not context-specific primitive objects
            "7C 03 04 01 00",
            "7C 05 A0 03 04 01 00",
            "7C 03 40 01 00",
            // a length that is not DER
            "7C 81 03 80 01 00",
            "7C 04 80 81 01 00",
        ],
    )
    fun refusesWhatIsNotDerDynamicAuthenticationData(encoded: String) {
        assertThat(DynamicAuthenticationData.decode(hex(encoded))).isNull()
    }
}
