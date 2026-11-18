package com.xignsys.pace.apdu

import com.xignsys.pace.apdu.CommandApdu.LengthForm
import com.xignsys.pace.fixtures.IcaoExamples
import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/**
 * The command APDU cases of ISO/IEC 7816-4, section 5.1, with the vectors of ICAO Doc 9303 Parts 10 and 11 and the BSI
 * EAC2 Worked Example v1.02.
 */
class CommandApduTest {
    @Test
    fun parsesACommandWithoutLengthFields() {
        // ICAO 9303-10, Table 1: Lc, data and Le absent (case 1).
        val apdu = CommandApdu.parse(IcaoExamples.SELECT_MASTER_FILE)

        assertThat(listOf(apdu.cla, apdu.ins, apdu.p1, apdu.p2)).containsExactly(0x00, 0xA4, 0x00, 0x0C)
        assertThat(apdu.nc).isZero()
        assertThat(apdu.ne).isEqualTo(CommandApdu.NO_RESPONSE_DATA)
        assertThat(apdu.lengthForm).isEqualTo(LengthForm.SHORT)
        assertThat(apdu.encode()).isEqualTo(IcaoExamples.SELECT_MASTER_FILE)
    }

    @Test
    fun parsesAShortCommandWithLeOnly() {
        // ICAO 9303-11, Appendix D.4: READ BINARY with Le 12 (case 2).
        val apdu = CommandApdu.parse(IcaoExamples.READ_BINARY_FROM_OFFSET_4)

        assertThat(apdu.nc).isZero()
        assertThat(apdu.ne).isEqualTo(0x12)
        assertThat(apdu.lengthForm).isEqualTo(LengthForm.SHORT)
        assertThat(apdu.encode()).isEqualTo(IcaoExamples.READ_BINARY_FROM_OFFSET_4)
    }

    @Test
    fun parsesShortCommandsWithData() {
        // ICAO 9303-11, Appendix D.4 (SELECT) and G.1 (MSE:Set AT); Worked Example section 3.1 (MSE:Set AT): case 3.
        for (encoded in listOf(IcaoExamples.SELECT_EF_COM, IcaoExamples.MSE_SET_AT_ECDH, WorkedExample.MSE_SET_AT)) {
            val apdu = CommandApdu.parse(encoded)

            assertThat(apdu.data).isEqualTo(encoded.copyOfRange(5, encoded.size))
            assertThat(apdu.ne).isEqualTo(CommandApdu.NO_RESPONSE_DATA)
            assertThat(apdu.lengthForm).isEqualTo(LengthForm.SHORT)
            assertThat(apdu.encode()).isEqualTo(encoded)
        }
    }

    @Test
    fun parsesShortCommandsWithDataAndLe() {
        // ICAO 9303-11, Appendix D.4 (protected READ BINARY) and Worked Example section 3.2 (General Authenticate with
        // command chaining): case 4, Le 00 for 256.
        for (encoded in listOf(IcaoExamples.READ_BINARY_PROTECTED, WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE)) {
            val apdu = CommandApdu.parse(encoded)

            assertThat(apdu.data).isEqualTo(encoded.copyOfRange(5, encoded.size - 1))
            assertThat(apdu.ne).isEqualTo(256)
            assertThat(apdu.lengthForm).isEqualTo(LengthForm.SHORT)
            assertThat(apdu.encode()).isEqualTo(encoded)
        }

        assertThat(CommandApdu.parse(WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE).cla).isEqualTo(0x10)
    }

    @Test
    fun parsesAnExtendedCommandWithoutLe() {
        // Worked Example section 4.2, PSO:Verify Certificate, plain: 00 marker, Lc 01 66 (case 3, extended).
        val apdu = CommandApdu.parse(WorkedExample.PSO_VERIFY_CERTIFICATE_PLAIN)

        assertThat(apdu.nc).isEqualTo(0x166)
        assertThat(apdu.ne).isEqualTo(CommandApdu.NO_RESPONSE_DATA)
        assertThat(apdu.lengthForm).isEqualTo(LengthForm.EXTENDED)
        assertThat(apdu.encode()).isEqualTo(WorkedExample.PSO_VERIFY_CERTIFICATE_PLAIN)
    }

    @Test
    fun parsesAnExtendedCommandWithLe() {
        // Worked Example section 4.2, PSO:Verify Certificate, protected: Lc 01 7F and Le 00 00 for 65 536 (case 4,
        // extended); ICAO 9303-11, Figure 5: '00 00' for extended length.
        val apdu = CommandApdu.parse(WorkedExample.PSO_VERIFY_CERTIFICATE_PROTECTED)

        assertThat(apdu.cla).isEqualTo(0x0C)
        assertThat(apdu.nc).isEqualTo(0x17F)
        assertThat(apdu.ne).isEqualTo(65_536)
        assertThat(apdu.lengthForm).isEqualTo(LengthForm.EXTENDED)
        assertThat(apdu.encode()).isEqualTo(WorkedExample.PSO_VERIFY_CERTIFICATE_PROTECTED)
    }

    @ParameterizedTest
    @ValueSource(strings = ["00 B0 00 00 00 01 00", "00 B0 00 00 00 00 00"])
    fun parsesAnExtendedCommandWithLeOnly(encoded: String) {
        // ISO/IEC 7816-4, section 5.1 (case 2, extended: 00 marker and two Le bytes, 00 00 for 65 536). No published
        // vector covers this case; the expected values follow the rule for the extended Le field of case 4.
        val apdu = CommandApdu.parse(hex(encoded))

        assertThat(apdu.nc).isZero()
        assertThat(apdu.ne).isIn(256, 65_536)
        assertThat(apdu.lengthForm).isEqualTo(LengthForm.EXTENDED)
        assertThat(apdu.encode()).isEqualTo(hex(encoded))
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "00 A4 02",
            // short Lc longer or shorter than the data
            "00 A4 02 0C 03 01 1E",
            "00 A4 02 0C 01 01 1E 00 00",
            // extended: marker without both length bytes
            "00 B0 00 00 00 01",
            // extended Lc of zero
            "00 2A 00 BE 00 00 00 01",
            // extended Lc longer or shorter than the data
            "00 2A 00 BE 00 00 03 01 02",
            "00 2A 00 BE 00 00 01 01 02",
        ],
    )
    fun refusesMalformedCommands(encoded: String) {
        assertThatIllegalArgumentException().isThrownBy { CommandApdu.parse(hex(encoded)) }
    }

    @Test
    fun buildsShortCommands() {
        // ICAO 9303-11, Appendix D.4 and G.1.
        val select = CommandApdu.of(cla = 0x00, ins = 0xA4, p1 = 0x02, p2 = 0x0C, data = hex("01 1E"))
        val read = CommandApdu.of(cla = 0x00, ins = 0xB0, p1 = 0x00, p2 = 0x04, ne = 0x12)
        val protectedRead =
            CommandApdu.of(
                cla = 0x0C,
                ins = 0xB0,
                p1 = 0x00,
                p2 = 0x00,
                data = hex("97 01 04 8E 08 ED 67 05 41 7E 96 BA 55"),
                ne = 256,
            )

        assertThat(select.encode()).isEqualTo(IcaoExamples.SELECT_EF_COM)
        assertThat(read.encode()).isEqualTo(IcaoExamples.READ_BINARY_FROM_OFFSET_4)
        assertThat(protectedRead.encode()).isEqualTo(IcaoExamples.READ_BINARY_PROTECTED)
        assertThat(CommandApdu.of(0x00, 0xA4, 0x00, 0x0C).encode()).isEqualTo(IcaoExamples.SELECT_MASTER_FILE)
    }

    @Test
    fun buildsExtendedCommands() {
        // Worked Example section 4.2.
        val plain = WorkedExample.PSO_VERIFY_CERTIFICATE_PLAIN
        val protected = WorkedExample.PSO_VERIFY_CERTIFICATE_PROTECTED

        assertThat(
            CommandApdu
                .of(0x00, 0x2A, 0x00, 0xBE, plain.copyOfRange(7, plain.size), lengthForm = LengthForm.EXTENDED)
                .encode(),
        ).isEqualTo(plain)
        assertThat(
            CommandApdu
                .of(0x0C, 0x2A, 0x00, 0xBE, protected.copyOfRange(7, protected.size - 2), 65_536, LengthForm.EXTENDED)
                .encode(),
        ).isEqualTo(protected)
    }

    @Test
    fun keepsTheExtendedFormOfASmallCommand() {
        // The form is the caller's choice (TR-03110 Part 3, B.12.2); a command that would fit short stays extended.
        val apdu = CommandApdu.of(0x00, 0xB0, 0x00, 0x00, ne = 4, lengthForm = LengthForm.EXTENDED)

        assertThat(apdu.encode()).isEqualTo(hex("00 B0 00 00 00 00 04"))
        assertThat(CommandApdu.parse(apdu.encode()).lengthForm).isEqualTo(LengthForm.EXTENDED)
    }

    @Test
    fun refusesCommandsThatDoNotFitTheLengthForm() {
        assertThatIllegalArgumentException().isThrownBy { CommandApdu.of(0x100, 0xA4, 0x00, 0x00) }
        assertThatIllegalArgumentException().isThrownBy { CommandApdu.of(0x00, 0xA4, -1, 0x00) }
        assertThatIllegalArgumentException().isThrownBy { CommandApdu.of(0x00, 0xD6, 0x00, 0x00, ByteArray(256)) }
        assertThatIllegalArgumentException().isThrownBy { CommandApdu.of(0x00, 0xB0, 0x00, 0x00, ne = 257) }
        assertThatIllegalArgumentException().isThrownBy { CommandApdu.of(0x00, 0xB0, 0x00, 0x00, ne = -1) }
        assertThatIllegalArgumentException().isThrownBy {
            CommandApdu.of(0x00, 0xB0, 0x00, 0x00, ne = 65_537, lengthForm = LengthForm.EXTENDED)
        }
    }

    @Test
    fun refusesTheExtendedFormForACommandWithoutLengthFields() {
        assertThatIllegalArgumentException()
            .isThrownBy { CommandApdu.of(0x00, 0xA4, 0x00, 0x0C, lengthForm = LengthForm.EXTENDED) }
            .withMessageContaining("no length fields")
    }

    @Test
    fun copiesTheDataInAndOut() {
        val data = hex("01 1E")
        val apdu = CommandApdu.of(0x00, 0xA4, 0x02, 0x0C, data)

        data[0] = 0x7F
        apdu.data[1] = 0x7F

        assertThat(apdu.data).isEqualTo(hex("01 1E"))
    }

    @Test
    fun showsNoDataInToString() {
        assertThat(CommandApdu.parse(IcaoExamples.SELECT_EF_COM).toString())
            .isEqualTo("CommandApdu(header=00A4020C, nc=2, ne=0, SHORT)")
    }
}
