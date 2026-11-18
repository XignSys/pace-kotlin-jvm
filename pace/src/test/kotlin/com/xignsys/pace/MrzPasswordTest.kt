package com.xignsys.pace

import com.xignsys.pace.Mrz.Date
import com.xignsys.pace.Mrz.DocumentNumber
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.assertj.core.api.Assertions.assertThatIllegalStateException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
import java.time.LocalDate

/** The MRZ password: its fields, the check digits and the MRZ information. */
class MrzPasswordTest {
    @Test
    fun buildsTheMrzInformationOfIcaoAppendixD2() {
        // ICAO 9303-11, Appendix D.2, TD1 MRZ, document number 9 characters: L898902C< 3, 690806 1, 940623 6.
        val mrz = Mrz(DocumentNumber.of("L898902C"), Date.of(LocalDate.of(1969, 8, 6)), Date.of(1994, 6, 23))

        assertThat(information(mrz)).isEqualTo("L898902C<369080619406236")
    }

    @Test
    fun usesALongDocumentNumberWhole() {
        // ICAO 9303-11, Appendix D.2, TD1 MRZ, document number exceeds 9 characters: D23145890734 9, 340712 7,
        // 950712 2; the complete number, without the filler of the zone (note to Table 14).
        val mrz = Mrz(DocumentNumber.of("D23145890734"), Date.parse("340712"), Date.parse("950712"))

        assertThat(information(mrz)).isEqualTo("D23145890734934071279507122")
    }

    @Test
    fun computesTheCheckDigitsOfIcaoPart3AppendixA() {
        // ICAO 9303-3, Appendix A: example 1, 520727 gives 3; example 2, AB2134<<< gives 5. The date of expiry
        // 940623 with check digit 6 is from ICAO 9303-11, Appendix D.2.
        val mrz = Mrz(DocumentNumber.of("AB2134"), Date.parse("520727"), Date.parse("940623"))

        assertThat(information(mrz)).isEqualTo("AB2134<<<552072739406236")
    }

    @Test
    fun computesTheCheckDigitsOfTheTd1ExampleOfIcaoPart3() {
        // ICAO 9303-3, Appendix A, example 4: upper line I<YTOD231458907..., middle line 3407127M9507122...
        val mrz = Mrz(DocumentNumber.of("D23145890"), Date.of(1934, 7, 12), Date.of(1995, 7, 12))

        assertThat(information(mrz)).isEqualTo("D23145890734071279507122")
    }

    @ParameterizedTest
    @CsvSource(
        delimiter = '|',
        value = [
            // ICAO 9303-4, Appendix A, Figure A-1 (TD3), lower line.
            "L898902C36UTO7408122F3404159ZE184226B<<<<<16 | L898902C3 | 740812 | 340415",
            // ICAO 9303-6, Appendix A, Figure A-1 (TD2), lower line.
            "D231458907UTO7408122F1204159<<<<<<<6         | D23145890 | 740812 | 120415",
        ],
    )
    fun readsTheMrzInformationFromTheLowerLineOfTd3AndTd2(
        line: String,
        number: String,
        birth: String,
        expiry: String,
    ) {
        // ICAO 9303-4 and ICAO 9303-6, section 4.2.4: characters 1 to 10, 14 to 20 and 22 to 28 of the lower line.
        val information = line.substring(0, 10) + line.substring(13, 20) + line.substring(21, 28)
        val fromZone = Mrz.fromMrzInformation(information.toCharArray())
        val fromFields = Mrz(DocumentNumber.of(number), Date.parse(birth), Date.parse(expiry))

        assertThat(information(fromZone)).isEqualTo(information)
        assertThat(information(fromFields)).isEqualTo(information)
    }

    @Test
    fun convertsLowerCaseLettersOfTheDocumentNumber() {
        val mrz = Mrz(DocumentNumber.of("l898902c"), Date.parse("690806"), Date.parse("940623"))

        assertThat(information(mrz)).isEqualTo("L898902C<369080619406236")
    }

    @Test
    fun acceptsUnknownPartsOfTheDateOfBirth() {
        // ICAO 9303-3, section 4.8: unknown parts of the date of birth are fillers; section 4.9: the filler counts as
        // zero, so 6908<< gives 6*7 + 9*3 + 0*1 + 8*7 = 125, check digit 5, and <<<<<< gives 0.
        val unknownDay = Mrz(DocumentNumber.of("L898902C"), Date.parse("6908<<"), Date.parse("940623"))
        val unknownDate = Mrz(DocumentNumber.of("L898902C"), Date.parse("<<<<<<"), Date.parse("940623"))

        assertThat(information(unknownDay)).isEqualTo("L898902C<36908<<59406236")
        assertThat(information(unknownDate)).isEqualTo("L898902C<3<<<<<<09406236")
    }

    @Test
    fun refusesUnknownPartsOfTheDateOfExpiry() {
        // ICAO 9303-3, section 4.8: fillers only for an unknown date of birth.
        assertThatIllegalArgumentException()
            .isThrownBy { Mrz(DocumentNumber.of("L898902C"), Date.parse("690806"), Date.parse("9406<<")) }
            .withMessage("The date of expiry must be complete; only a date of birth may have unknown parts.")
    }

    @ParameterizedTest
    @CsvSource(
        delimiter = '|',
        quoteCharacter = '"',
        value = [
            "\"\"        | The document number must not be empty.",
            "<L898902  | The document number must not start with the filler '<'.",
            "L8989-02C | The document number must consist of the digits 0 to 9, the letters A to Z and the filler '<' only.",
            "L898 902C | The document number must consist of the digits 0 to 9, the letters A to Z and the filler '<' only.",
            "\u00C4898902C | The document number must consist of the digits 0 to 9, the letters A to Z and the filler '<' only.",
        ],
    )
    fun refusesAnInvalidDocumentNumber(value: String, message: String) {
        // ICAO 9303-3, section 4.3 and Figure 4 (characters), section 4.10 (data starts at the left).
        assertThatIllegalArgumentException()
            .isThrownBy { DocumentNumber.of(value) }
            .withMessage(message)
    }

    @ParameterizedTest
    @CsvSource(
        delimiter = '|',
        quoteCharacter = '"',
        value = [
            "52072   | A date has six characters, YYMMDD.",
            "5207270 | A date has six characters, YYMMDD.",
            "521327  | The month of a date must be 01 to 12.",
            "520700  | The day of a date must exist in its month.",
            "520732  | The day of a date must exist in its month.",
            "520431  | The day of a date must exist in its month.",
            "010229  | The day of a date must exist in its month.",
            "5<0727  | Each part of a date must be two digits, or '<<' for an unknown part of a date of birth.",
            "52A727  | Each part of a date must be two digits, or '<<' for an unknown part of a date of birth.",
            "<<1332  | The month of a date must be 01 to 12.",
        ],
    )
    fun refusesAnInvalidDate(value: String, message: String) {
        // ICAO 9303-3, section 4.8: YYMMDD, unknown parts of a date of birth as fillers.
        assertThatIllegalArgumentException()
            .isThrownBy { Date.parse(value) }
            .withMessage(message)
    }

    @ParameterizedTest
    @ValueSource(strings = ["040229", "000229", "<<0229", "69<<31", "520731"])
    fun acceptsTheLastDaysOfAMonth(value: String) {
        // Two-digit years read as 2000 to 2099: 29 February when YY is divisible by 4; with an unknown year or month
        // the longest possible month.
        Date.parse(value)
    }

    @Test
    fun checksACalendarDateWithItsFullYear() {
        assertThatIllegalArgumentException()
            .isThrownBy { Date.of(1900, 2, 29) }
            .withMessage("The day must exist in its month.")
        assertThatIllegalArgumentException()
            .isThrownBy {
                Date.of(
                    1952,
                    13,
                    1,
                )
            }.withMessage("The month must be 1 to 12.")
        assertThatIllegalArgumentException()
            .isThrownBy {
                Date.of(
                    1952,
                    0,
                    1,
                )
            }.withMessage("The month must be 1 to 12.")
        assertThatIllegalArgumentException()
            .isThrownBy {
                Date.of(
                    10000,
                    1,
                    1,
                )
            }.withMessage("The year must be 0 to 9999.")
        assertThatIllegalArgumentException().isThrownBy { Date.of(-1, 1, 1) }.withMessage("The year must be 0 to 9999.")
        assertThatIllegalArgumentException()
            .isThrownBy { Date.of(LocalDate.of(10000, 1, 1)) }
            .withMessage("The year must be 0 to 9999.")

        val leapDay = Mrz(DocumentNumber.of("L898902C"), Date.of(2000, 2, 29), Date.of(1994, 6, 23))

        assertThat(information(leapDay)).startsWith("L898902C<3000229")
    }

    @Test
    fun usesEachFieldForOnePasswordOnly() {
        val number = DocumentNumber.of("L898902C")
        val birth = Date.parse("690806")

        Mrz(number, birth, Date.parse("940623"))

        assertThatIllegalStateException()
            .isThrownBy { Mrz(number, Date.parse("690806"), Date.parse("940623")) }
            .withMessage("The document number has been wiped or already used for a password.")
        assertThatIllegalStateException()
            .isThrownBy { Mrz(DocumentNumber.of("L898902C"), birth, Date.parse("940623")) }
            .withMessage("The date has been wiped or already used for a password.")

        val same = Date.parse("690806")

        assertThatIllegalStateException()
            .isThrownBy { Mrz(DocumentNumber.of("L898902C"), same, same) }
            .withMessage("The date has been wiped or already used for a password.")
    }

    @Test
    fun refusesWipedFields() {
        val number = DocumentNumber.of("L898902C")
        val birth = Date.parse("690806")
        val expiry = Date.of(1994, 6, 23)

        number.wipe()
        number.wipe()
        birth.wipe()
        expiry.wipe()

        assertThatIllegalStateException()
            .isThrownBy { Mrz(number, Date.parse("690806"), Date.parse("940623")) }
            .withMessage("The document number has been wiped or already used for a password.")
        assertThatIllegalStateException()
            .isThrownBy { Mrz(DocumentNumber.of("L898902C"), birth, Date.parse("940623")) }
            .withMessage("The date has been wiped or already used for a password.")
        assertThatIllegalStateException()
            .isThrownBy { Mrz(DocumentNumber.of("L898902C"), Date.parse("690806"), expiry) }
            .withMessage("The date has been wiped or already used for a password.")
    }

    @Test
    fun takesOverTheMrzInformationAsItIs() {
        val characters = "L898902C<369080619406236".toCharArray()
        val mrz = Mrz.fromMrzInformation(characters)

        assertThat(mrz.characters).isSameAs(characters)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            // ICAO 9303-11, Appendix D.2.
            "L898902C<369080619406236",
            "D23145890734934071279507122",
            // ICAO 9303-3, Appendix A, example 4.
            "D23145890734071279507122",
            // Unknown parts of the date of birth, check digits as derived in acceptsUnknownPartsOfTheDateOfBirth.
            "L898902C<36908<<59406236",
            "L898902C<3<<<<<<09406236",
        ],
    )
    fun acceptsValidMrzInformation(value: String) {
        assertThat(information(Mrz.fromMrzInformation(value.toCharArray()))).isEqualTo(value)
    }

    @ParameterizedTest
    @CsvSource(
        delimiter = '|',
        quoteCharacter = '"',
        value = [
            // Each check digit of ICAO 9303-11, Appendix D.2 changed by one.
            "L898902C<469080619406236  | The check digit of the document number does not match.",
            "L898902C<369080629406236  | The check digit of the date of birth does not match.",
            "L898902C<369080619406237  | The check digit of the date of expiry does not match.",
            "L898902C<<69080619406236  | The check digit of the document number does not match.",
            "L898902C<36908061940623   | The MRZ information must have at least 24 characters.",
            "l898902C<369080619406236  | The MRZ information must consist of the digits 0 to 9, the letters A to Z and the filler '<' only.",
            "L898902C<36908061 9406236 | The MRZ information must consist of the digits 0 to 9, the letters A to Z and the filler '<' only.",
            "<898902C<369080619406236  | The document number must not start with the filler '<'.",
            "L898902C<369130619406236  | The month of a date must be 01 to 12.",
            "L898902C<369063119406236  | The day of a date must exist in its month.",
            "L898902C<36908<619406236  | Each part of a date must be two digits, or '<<' for an unknown part of a date of birth.",
            "L898902C<369080619406<<7  | The date of expiry must be complete; only a date of birth may have unknown parts.",
        ],
    )
    fun refusesInvalidMrzInformationAndOverwritesIt(value: String, message: String) {
        val characters = value.toCharArray()

        assertThatIllegalArgumentException()
            .isThrownBy { Mrz.fromMrzInformation(characters) }
            .withMessage(message)
        assertThat(characters).containsOnly(Char.MIN_VALUE)
    }

    @ParameterizedTest
    @CsvSource(
        delimiter = '|',
        value = [
            // ICAO 9303-11, Appendix D.2, TD1 MRZ, document number 9 characters, with its MRZ information.
            "I<UTOL898902C<3<<<<<<<<<<<<<<< | 6908061F9406236UTO<<<<<<<<<<<1 | ERIKSSON<<ANNA<MARIA<<<<<<<<<< " +
                "| L898902C<369080619406236",
            // ICAO 9303-11, Appendix D.2, TD1 MRZ, document number exceeds 9 characters, with its MRZ information.
            "I<UTOD23145890<7349<<<<<<<<<<< | 3407127M9507122UTO<<<<<<<<<<<2 | STEVENSON<<PETER<JOHN<<<<<<<<< " +
                "| D23145890734934071279507122",
            // ICAO 9303-5, Appendix A, Figure A-1; characters 6 to 15 of the upper line and 1 to 7 and 9 to 15 of
            // the middle line (section 4.2.4).
            "I<UTOD231458907<<<<<<<<<<<<<<< | 7408122F1204159UTO<<<<<<<<<<<6 | ERIKSSON<<ANNA<MARIA<<<<<<<<<< " +
                "| D23145890774081221204159",
        ],
    )
    fun readsTheMrzInformationFromATd1Zone(
        upper: String,
        middle: String,
        lower: String,
        information: String,
    ) {
        // ICAO 9303-5, section 4.2.2: three lines of 30 characters; here without, with LF and with CR LF line breaks,
        // also after the last line.
        for (zone in listOf(upper + middle + lower, "$upper\n$middle\n$lower", "$upper\r\n$middle\r\n$lower\r\n")) {
            val characters = zone.toCharArray()

            assertThat(information(Mrz.fromMachineReadableZone(characters))).isEqualTo(information)
            assertThat(characters).containsOnly(Char.MIN_VALUE)
        }
    }

    @Test
    fun ignoresTheZoneOutsideTheMrzInformation() {
        // The zone of ICAO 9303-11, Appendix D.2, with the document code, the issuing State, the sex, the nationality,
        // the composite check digit and the names changed, some to characters the zone does not have.
        val zone =
            "xxxxxL898902C<3<<<<<<<<<<<<<<<" + "6908061x9406236xxx<<<<<<<<<<<9" + "eriksson anna maria           "

        assertThat(information(Mrz.fromMachineReadableZone(zone.toCharArray()))).isEqualTo("L898902C<369080619406236")
    }

    @ParameterizedTest
    @CsvSource(
        delimiter = '|',
        ignoreLeadingAndTrailingWhitespace = false,
        value = [
            // ICAO 9303-11, Appendix D.2 (TD1): one character less, one more, a space inside a line, a line break
            // inside a line and before the first line ({LF} stands for the line feed).
            "I<UTOL898902C<3<<<<<<<<<<<<<<<6908061F9406236UTO<<<<<<<<<<<1ERIKSSON<<ANNA<MARIA<<<<<<<<<",
            "I<UTOL898902C<3<<<<<<<<<<<<<<<6908061F9406236UTO<<<<<<<<<<<1ERIKSSON<<ANNA<MARIA<<<<<<<<<<<",
            "I<UTOL898902C<3<<<<<<<<<<<<<<<6908061F 9406236UTO<<<<<<<<<<<1ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
            "I<UTOL898902C<3<<<<<<<<<<<<<<<6908061F{LF}9406236UTO<<<<<<<<<<<1ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
            "{LF}I<UTOL898902C<3<<<<<<<<<<<<<<<6908061F9406236UTO<<<<<<<<<<<1ERIKSSON<<ANNA<MARIA<<<<<<<<<<",
            // ICAO 9303-6, Appendix A, Figure A-1 (TD2) and ICAO 9303-4, Appendix A, Figure A-1 (TD3).
            "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<D231458907UTO7408122F1204159<<<<<<<6",
            "PPUTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F3404159ZE184226B<<<<<16",
        ],
    )
    fun refusesWhatIsNotATd1Zone(value: String) {
        val characters = value.replace("{LF}", "\n").toCharArray()

        assertThatIllegalArgumentException()
            .isThrownBy { Mrz.fromMachineReadableZone(characters) }
            .withMessage(
                "The machine readable zone must have 90 characters (TD1, three lines of 30), with or without line " +
                    "breaks between the lines.",
            )
        assertThat(characters).containsOnly(Char.MIN_VALUE)
    }

    @ParameterizedTest
    @CsvSource(
        delimiter = '|',
        value = [
            // ICAO 9303-5, note j to section 4.2.2: a filler in place of the check digit, then the remaining
            // characters, the check digit and a filler. Here: nothing, the check digit alone, and no filler.
            "I<UTOD23145890<<<<<<<<<<<<<<<<",
            "I<UTOD23145890<9<<<<<<<<<<<<<<",
            "I<UTOD23145890<734912345678901",
        ],
    )
    fun refusesATruncatedDocumentNumberWithoutItsRemainder(upper: String) {
        val characters = (upper + "3407127M9507122UTO<<<<<<<<<<<2" + "STEVENSON<<PETER<JOHN<<<<<<<<<").toCharArray()

        assertThatIllegalArgumentException()
            .isThrownBy { Mrz.fromMachineReadableZone(characters) }
            .withMessage(
                "The document number is marked as truncated, but the optional data does not hold its remaining " +
                    "characters, a check digit and a filler.",
            )
        assertThat(characters).containsOnly(Char.MIN_VALUE)
    }

    @ParameterizedTest
    @CsvSource(
        delimiter = '|',
        value = [
            // The zones of ICAO 9303-11, Appendix D.2, with one character of the MRZ information changed.
            "I<UTOL898902C<4<<<<<<<<<<<<<<< | 6908061F9406236UTO<<<<<<<<<<<1 " +
                "| The check digit of the document number does not match.",
            "I<UTOD23145890<7348<<<<<<<<<<< | 3407127M9507122UTO<<<<<<<<<<<2 " +
                "| The check digit of the document number does not match.",
            "I<UTOL898902C<3<<<<<<<<<<<<<<< | 6908062F9406236UTO<<<<<<<<<<<1 " +
                "| The check digit of the date of birth does not match.",
            "I<UTOL898902C<3<<<<<<<<<<<<<<< | 6908061F9406237UTO<<<<<<<<<<<1 " +
                "| The check digit of the date of expiry does not match.",
            "I<UTOl898902C<3<<<<<<<<<<<<<<< | 6908061F9406236UTO<<<<<<<<<<<1 " +
                "| The MRZ information must consist of the digits 0 to 9, the letters A to Z and the filler '<' only.",
            "I<UTO<898902C<3<<<<<<<<<<<<<<< | 6908061F9406236UTO<<<<<<<<<<<1 " +
                "| The document number must not start with the filler '<'.",
            "I<UTOL898902C<3<<<<<<<<<<<<<<< | 6913061F9406236UTO<<<<<<<<<<<1 | The month of a date must be 01 to 12.",
        ],
    )
    fun appliesTheRulesOfTheMrzInformationToATd1Zone(
        upper: String,
        middle: String,
        message: String,
    ) {
        val characters = (upper + middle + "ERIKSSON<<ANNA<MARIA<<<<<<<<<<").toCharArray()

        assertThatIllegalArgumentException()
            .isThrownBy { Mrz.fromMachineReadableZone(characters) }
            .withMessage(message)
        assertThat(characters).containsOnly(Char.MIN_VALUE)
    }

    private fun information(mrz: Mrz): String = String(mrz.characters)
}
