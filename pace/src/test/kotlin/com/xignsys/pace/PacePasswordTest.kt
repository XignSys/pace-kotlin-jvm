package com.xignsys.pace

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/** The CAN, PIN and PUK: their rules and messages, the password references, ownership and wiping. */
class PacePasswordTest {
    @Test
    fun takesOverTheArrayOfAValidCan() {
        val characters = "123456".toCharArray()
        val can = Can(characters)

        assertThat(can.characters).isSameAs(characters)
    }

    @Test
    fun usesThePasswordReferencesOfMseSetAt() {
        // TR-03110 Part 3, B.14.1, data object 83: 01 MRZ, 02 CAN, 03 PIN, 04 PUK.
        assertThat(Can("123456".toCharArray()).reference).isEqualTo(0x02)
        assertThat(Pin("123456".toCharArray()).reference).isEqualTo(0x03)
        assertThat(Puk("1234567890".toCharArray()).reference).isEqualTo(0x04)
        assertThat(Mrz.fromMrzInformation(ICAO_MRZ_INFORMATION.toCharArray()).reference)
            .isEqualTo(0x01)
    }

    @ParameterizedTest
    @ValueSource(strings = ["12345A", "12 456", "12345\u0009", "-12345", "\uFF11\uFF12\uFF13"])
    fun refusesACanWithACharacterOtherThanADigit(value: String) {
        // ICAO 9303-5, section 3.2.3: the CAN consists solely of numerals, 0 to 9.
        val characters = value.toCharArray()

        assertThatIllegalArgumentException()
            .isThrownBy { Can(characters) }
            .withMessage("The CAN must consist of the digits 0 to 9 only.")
        assertThat(characters).containsOnly(Char.MIN_VALUE)
    }

    @Test
    fun acceptsACanOfAnyLength() {
        // TR-03110 Part 1, section 2.3: a short password, static, semi-static or dynamic, without a length. Six digits
        // on passports (ICAO 9303-4, section 4.1.1.2) and TD1 documents (ICAO 9303-5, section 3.2.3) only.
        assertThat(String(Can("1".toCharArray()).characters)).isEqualTo("1")
        assertThat(Can("12345".toCharArray()).characters).hasSize(5)
        assertThat(Can("1234567".toCharArray()).characters).hasSize(7)
        assertThat(Can("12345678".toCharArray()).characters).hasSize(8)
    }

    @Test
    fun refusesEmptyPasswords() {
        assertThatIllegalArgumentException()
            .isThrownBy { Can(CharArray(0)) }
            .withMessage("The CAN must not be empty.")
        assertThatIllegalArgumentException()
            .isThrownBy { Pin(CharArray(0)) }
            .withMessage("The PIN must not be empty.")
        assertThatIllegalArgumentException()
            .isThrownBy { Puk(CharArray(0)) }
            .withMessage("The PUK must not be empty.")
    }

    @Test
    fun acceptsEveryAssignedIso88591CharacterInAPinOrPuk() {
        // TR-03110 Part 3, D.2.1.4: the boundaries of the assigned codes 0x20 to 0x7E and 0xA0 to 0xFF.
        val value = "\u0020\u007E\u00A0\u00FF\u00E4"

        assertThat(String(Pin(value.toCharArray()).characters)).isEqualTo(value)
        assertThat(String(Puk(value.toCharArray()).characters)).isEqualTo(value)
    }

    @ParameterizedTest
    @ValueSource(strings = ["12345\u0000", "12345\u001F", "12345\u007F", "12345\u009F", "12345\u0100", "1234\u20AC"])
    fun refusesUnassignedCodesAndCharactersOutsideIso88591InAPinOrPuk(value: String) {
        // TR-03110 Part 3, D.2.1.4: 0x00 to 0x1F and 0x7F to 0x9F MUST NOT be used; ISO/IEC 8859-1 ends at 0xFF.
        val pin = value.toCharArray()
        val puk = value.toCharArray()

        assertThatIllegalArgumentException()
            .isThrownBy { Pin(pin) }
            .withMessage("The PIN must consist of ISO/IEC 8859-1 characters other than 0x00 to 0x1F and 0x7F to 0x9F.")
        assertThatIllegalArgumentException()
            .isThrownBy { Puk(puk) }
            .withMessage("The PUK must consist of ISO/IEC 8859-1 characters other than 0x00 to 0x1F and 0x7F to 0x9F.")
        assertThat(pin).containsOnly(Char.MIN_VALUE)
        assertThat(puk).containsOnly(Char.MIN_VALUE)
    }

    @Test
    fun wipingOverwritesTheCharacters() {
        val arrays = listOf("123456", "123456", "1234567890", ICAO_MRZ_INFORMATION).map { it.toCharArray() }
        val passwords = listOf(Can(arrays[0]), Pin(arrays[1]), Puk(arrays[2]), Mrz.fromMrzInformation(arrays[3]))

        passwords.forEach { it.wipe() }

        assertThat(arrays).allSatisfy { assertThat(it).containsOnly(Char.MIN_VALUE) }

        passwords.forEach { it.wipe() }

        assertThat(arrays).allSatisfy { assertThat(it).containsOnly(Char.MIN_VALUE) }
    }

    @Test
    fun showsNoCharactersInToString() {
        assertThat(Can("123456".toCharArray()).toString()).isEqualTo("Can")
        assertThat(Pin("123456".toCharArray()).toString()).isEqualTo("Pin")
        assertThat(Puk("1234567890".toCharArray()).toString()).isEqualTo("Puk")
        assertThat(Mrz.fromMrzInformation(ICAO_MRZ_INFORMATION.toCharArray()).toString())
            .isEqualTo("Mrz")
        assertThat(
            Mrz.DocumentNumber
                .of("L898902C")
                .toString(),
        ).isEqualTo("Mrz.DocumentNumber")
        assertThat(
            Mrz.Date
                .parse("690806")
                .toString(),
        ).isEqualTo("Mrz.Date")
    }

    private companion object {
        /** ICAO 9303-11, Appendix D.2, TD1 MRZ with a nine-character document number. */
        const val ICAO_MRZ_INFORMATION = "L898902C<369080619406236"
    }
}
