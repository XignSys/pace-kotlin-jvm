package com.xignsys.pace

import com.xignsys.pace.internal.crypto.requireOrWipe
import com.xignsys.pace.internal.crypto.wipe
import java.time.LocalDate
import java.time.YearMonth

/**
 * The MRZ password: the MRZ information, that is the document number, the date of birth and the date of expiry, each
 * followed by its check digit, as they appear in the machine readable zone (ICAO 9303-11, section 4.3.2 and Table 14).
 *
 * The constructor builds it from the three fields and computes the check digits (ICAO 9303-3, section 4.9), so the
 * caller needs no knowledge of the MRZ format. [fromMrzInformation] takes the MRZ information as it was read from the
 * zone instead and verifies its check digits. [fromMachineReadableZone] takes the whole zone of a TD1 size document,
 * such as an ID card, and reads the MRZ information from it.
 */
public class Mrz private constructor(override val characters: CharArray) : PacePassword() {
    /** `01`, the MRZ (TR-03110 Part 3, B.14.1). */
    override val reference: Int get() = 0x01

    /**
     * Builds the MRZ password from its three fields. The fields are taken over: their characters are overwritten, also
     * when the password is refused, and a field cannot be used for a second password.
     *
     * @throws IllegalArgumentException with the message "The date of expiry must be complete; only a date of birth may
     *   have unknown parts." if [dateOfExpiry] has unknown parts, which only a date of birth may have (ICAO 9303-3,
     *   section 4.8).
     * @throws IllegalStateException with the message "The document number has been wiped or already used for a
     *   password." or "The date has been wiped or already used for a password." if a field has been wiped or already
     *   used, or the same date is passed twice.
     */
    public constructor(
        documentNumber: DocumentNumber,
        dateOfBirth: Date,
        dateOfExpiry: Date,
    ) : this(mrzInformation(documentNumber, dateOfBirth, dateOfExpiry))

    override fun toString(): String = "Mrz"

    /**
     * The complete document number, for the MRZ password.
     *
     * Its characters are overwritten with `U+0000` when [Mrz] takes it over or when [wipe] is called; a value that is
     * no longer needed, for example because the user cancelled, should be wiped. [toString] never shows the characters.
     * Not thread-safe.
     */
    public class DocumentNumber private constructor(private val characters: CharArray) {
        private var isTaken = false

        /** Overwrites the characters with `U+0000`; [Mrz] then refuses the value. Can be called more than once. */
        public fun wipe() {
            characters.wipe()
        }

        /**
         * The characters of the document number, completed to the nine positions of its field, and marks the value as
         * used.
         *
         * @throws IllegalStateException if the value has been wiped or already used.
         */
        internal fun take(): CharArray {
            // The first character of a valid number is a digit or a letter, never U+0000, the value of a wiped one.
            check(!isTaken && characters[0] != Char.MIN_VALUE) {
                "The document number has been wiped or already used for a password."
            }

            isTaken = true

            return characters
        }

        override fun toString(): String = "Mrz.DocumentNumber"

        /** Factory of [DocumentNumber]. */
        public companion object {
            /**
             * The document number [value] as printed on the document, without its check digit.
             *
             * Only the characters of the machine readable zone are accepted: the digits `0` to `9`, the letters `A` to
             * `Z` and the filler `<` (ICAO 9303-3, section 4.3 and Figure 4). Lower-case letters `a` to `z` are
             * converted to upper case. The number starts with its first character, not with a filler (ICAO 9303-3,
             * section 4.10). Spaces of the printed number are given as fillers (ICAO 9303-5, section 4.2.2.1; ICAO
             * 9303-6, section 4.2.2.2), and on a passport special characters as well (ICAO 9303-4, section 4.2.2.2). A
             * number shorter than nine characters is completed with fillers to the
             * nine positions of the document number field (ICAO 9303-4 and ICAO 9303-6, section 4.2.2.2; ICAO 9303-5,
             * section 4.2.2.1). A longer number is used whole: give the complete number, not the shortened form of a
             * TD1 or TD2 zone with a filler in place of the first check digit (ICAO 9303-5, note j to section 4.2.2;
             * ICAO 9303-6, note j to section 4.2.2; ICAO 9303-11, note to Table 14); ICAO 9303-4 provides no longer
             * numbers for passports (TD3).
             *
             * The characters are copied; a `String` passed in stays in memory until it is collected.
             *
             * @throws IllegalArgumentException with the message "The document number must not be empty." if [value] is
             *   empty, "The document number must consist of the digits 0 to 9, the letters A to Z and the filler '<'
             *   only." if it contains another character, or "The document number must not start with the filler '<'."
             */
            @JvmStatic
            public fun of(value: CharSequence): DocumentNumber {
                require(value.isNotEmpty()) { "The document number must not be empty." }

                val characters = CharArray(maxOf(value.length, DOCUMENT_NUMBER_LENGTH)) { FILLER }

                for (index in value.indices) {
                    characters[index] = value[index].let { if (it in 'a'..'z') it.uppercaseChar() else it }
                }

                requireValid(characters, 0, characters.size)

                return DocumentNumber(characters)
            }

            /**
             * Checks the document number in [characters] from index [from] up to [to] (exclusive), and overwrites
             * [characters] if it is refused.
             */
            internal fun requireValid(
                characters: CharArray,
                from: Int,
                to: Int,
            ) {
                characters.requireOrWipe((from until to).all { characters[it].isMrzCharacter() }) {
                    "The document number must consist of the digits 0 to 9, the letters A to Z and the filler '<' only."
                }
                characters.requireOrWipe(characters[from] != FILLER) {
                    "The document number must not start with the filler '<'."
                }
            }
        }
    }

    /**
     * A date of the MRZ password in the form `YYMMDD` of the machine readable zone (ICAO 9303-3, section 4.8).
     *
     * Its characters are overwritten with `U+0000` when [Mrz] takes it over or when [wipe] is called; a value that is
     * no longer needed, for example because the user cancelled, should be wiped. [toString] never shows the characters.
     * Not thread-safe.
     */
    public class Date private constructor(private val characters: CharArray) {
        private var isTaken = false

        /** Overwrites the characters with `U+0000`; [Mrz] then refuses the value. Can be called more than once. */
        public fun wipe() {
            characters.wipe()
        }

        /**
         * The six characters `YYMMDD`, and marks the value as used.
         *
         * @throws IllegalStateException if the value has been wiped or already used.
         */
        internal fun take(): CharArray {
            // The first character of a valid date is a digit or the filler, never U+0000, the value of a wiped one.
            check(!isTaken && characters[0] != Char.MIN_VALUE) {
                "The date has been wiped or already used for a password."
            }

            isTaken = true

            return characters
        }

        override fun toString(): String = "Mrz.Date"

        /** Factories of [Date]. */
        public companion object {
            /** Offsets of the parts of a date `YYMMDD` (ICAO 9303-3, section 4.8). */
            private const val YEAR_OFFSET: Int = 0
            private const val MONTH_OFFSET: Int = 2
            private const val DAY_OFFSET: Int = 4

            private const val CENTURY: Int = 100

            /** Years with four digits at most, which a calendar date may have. */
            private val YEARS: IntRange = 0..9999

            private val MONTHS: IntRange = 1..12

            /** The longest month, for a date of birth with an unknown month. */
            private const val MAX_DAY: Int = 31

            /**
             * Two-digit years are read in 2000 to 2099, where every year divisible by 4 is a leap year; an unknown year
             * is read as the leap year 2000.
             */
            private const val READ_CENTURY_START: Int = 2000

            /**
             * The calendar date [date]; the zone keeps the last two digits of the year.
             *
             * @throws IllegalArgumentException with the message "The year must be 0 to 9999." if the year of [date] is
             *   not in 0 to 9999.
             */
            @JvmStatic
            public fun of(date: LocalDate): Date = of(date.year, date.monthValue, date.dayOfMonth)

            /**
             * The calendar date [day].[month].[year] in the Gregorian calendar; the zone keeps the last two digits of
             * the year.
             *
             * @throws IllegalArgumentException with the message "The year must be 0 to 9999." if [year] is not in 0 to
             *   9999, "The month must be 1 to 12." if [month] is not, or "The day must exist in its month." if [day]
             *   does not exist in that month.
             */
            @JvmStatic
            public fun of(
                year: Int,
                month: Int,
                day: Int,
            ): Date {
                require(year in YEARS) { "The year must be 0 to 9999." }
                require(month in MONTHS) { "The month must be 1 to 12." }
                require(day in 1..YearMonth.of(year, month).lengthOfMonth()) { "The day must exist in its month." }

                val characters = CharArray(DATE_LENGTH)

                putTwoDigits(characters, YEAR_OFFSET, year % CENTURY)
                putTwoDigits(characters, MONTH_OFFSET, month)
                putTwoDigits(characters, DAY_OFFSET, day)

                return Date(characters)
            }

            /**
             * The date [value] as it appears in the machine readable zone: six characters `YYMMDD` (ICAO 9303-3,
             * section 4.8). In a date of birth, an unknown year, month or day is given as two fillers `<<`; the date of
             * expiry must be complete. Two-digit years are read as 2000 to 2099, so 29 February exists when `YY` is
             * divisible by 4; with an unknown year it is accepted.
             *
             * The characters are copied; a `String` passed in stays in memory until it is collected.
             *
             * @throws IllegalArgumentException with the message "A date has six characters, YYMMDD." if [value] does
             *   not have six characters, "Each part of a date must be two digits, or '<<' for an unknown part of a date
             *   of birth." if a part is neither, "The month of a date must be 01 to 12." if the month is not, or "The
             *   day of a date must exist in its month." if the day does not exist in its month.
             */
            @JvmStatic
            public fun parse(value: CharSequence): Date {
                require(value.length == DATE_LENGTH) { "A date has six characters, YYMMDD." }

                val characters = CharArray(DATE_LENGTH) { value[it] }

                requireValid(characters, 0)

                return Date(characters)
            }

            /**
             * Checks the date `YYMMDD` in [characters] at index [from], where unknown parts are allowed, and overwrites
             * [characters] if it is refused.
             */
            internal fun requireValid(characters: CharArray, from: Int) {
                val year = part(characters, from + YEAR_OFFSET)
                val month = part(characters, from + MONTH_OFFSET)
                val day = part(characters, from + DAY_OFFSET)

                characters.requireOrWipe(month == null || month in MONTHS) { "The month of a date must be 01 to 12." }
                characters.requireOrWipe(day == null || day in 1..lastDay(year, month)) {
                    "The day of a date must exist in its month."
                }
            }

            /**
             * The value of the two digits at [from], or `null` for the two fillers of an unknown part; overwrites
             * [characters] if the part is neither.
             */
            private fun part(characters: CharArray, from: Int): Int? {
                val first = characters[from]
                val second = characters[from + 1]

                if (first == FILLER && second == FILLER) {
                    return null
                }

                characters.requireOrWipe(first.isDecimalDigit() && second.isDecimalDigit()) {
                    "Each part of a date must be two digits, or '<<' for an unknown part of a date of birth."
                }

                return first.digitValue() * DECIMAL_BASE + second.digitValue()
            }

            private fun lastDay(year: Int?, month: Int?): Int =
                if (month == null) {
                    MAX_DAY
                } else {
                    YearMonth.of(READ_CENTURY_START + (year ?: 0), month).lengthOfMonth()
                }

            private fun putTwoDigits(
                characters: CharArray,
                at: Int,
                value: Int,
            ) {
                characters[at] = '0' + value / DECIMAL_BASE
                characters[at + 1] = '0' + value % DECIMAL_BASE
            }
        }
    }

    /** Factory of [Mrz] for the MRZ information as read from the zone. */
    public companion object {
        /** The filler character of the machine readable zone (ICAO 9303-3, sections 4.9 and 4.10). */
        private const val FILLER: Char = '<'

        /** Positions of the document number field (ICAO 9303-4 and 9303-6, section 4.2.2.2; 9303-5, 4.2.2.1). */
        private const val DOCUMENT_NUMBER_LENGTH: Int = 9

        /** Length of a date `YYMMDD` (ICAO 9303-3, section 4.8). */
        private const val DATE_LENGTH: Int = 6

        /** The fields of the MRZ information, each followed by its check digit (ICAO 9303-11, section 4.3.2). */
        private const val FIELDS: Int = 3

        /** The shortest MRZ information: a nine-character document number, two dates and three check digits. */
        private const val MIN_LENGTH: Int = DOCUMENT_NUMBER_LENGTH + 2 * DATE_LENGTH + FIELDS

        /** Characters after the document number's check digit: two dates with their check digits. */
        private const val DATES_WITH_CHECK_DIGITS: Int = 2 * (DATE_LENGTH + 1)

        /** Check digits: a repeated weighting of 7, 3, 1 and modulus 10; letters count 10 to 35 (ICAO 9303-3, 4.9). */
        private val CHECK_DIGIT_WEIGHTS: IntArray = intArrayOf(7, 3, 1)
        private const val CHECK_DIGIT_MODULUS: Int = 10
        private const val FIRST_LETTER_VALUE: Int = 10

        private const val DECIMAL_BASE: Int = 10

        private const val INCOMPLETE_DATE_OF_EXPIRY: String =
            "The date of expiry must be complete; only a date of birth may have unknown parts."

        /** Characters of one line of a TD1 zone (ICAO 9303-5, section 4.2.2). */
        private const val TD1_LINE_LENGTH: Int = 30

        /** Characters of a TD1 zone: the upper, the middle and the lower line (ICAO 9303-5, section 4.2.2). */
        private const val TD1_LENGTH: Int = 3 * TD1_LINE_LENGTH

        /** Index of the document number, positions 6 to 14 of the upper line (ICAO 9303-5, section 4.2.2.1). */
        private const val TD1_DOCUMENT_NUMBER: Int = 5

        /** Index of the document number's check digit, position 15 of the upper line (ICAO 9303-5, section 4.2.4). */
        private const val TD1_DOCUMENT_NUMBER_CHECK_DIGIT: Int = TD1_DOCUMENT_NUMBER + DOCUMENT_NUMBER_LENGTH

        /** Index of the optional data elements, positions 16 to 30 of the upper line (ICAO 9303-5, section 4.2.2.1). */
        private const val TD1_OPTIONAL_DATA: Int = TD1_DOCUMENT_NUMBER_CHECK_DIGIT + 1

        /** Index of the date of birth, positions 1 to 6 of the middle line, then its check digit (4.2.2.2). */
        private const val TD1_DATE_OF_BIRTH: Int = TD1_LINE_LENGTH

        /** Index of the date of expiry, positions 9 to 14 of the middle line, then its check digit (4.2.2.2). */
        private const val TD1_DATE_OF_EXPIRY: Int = TD1_LINE_LENGTH + 8

        /** A truncated document number has at least one remaining character, then its check digit (note j). */
        private const val MIN_REMAINDER_LENGTH: Int = 2

        private const val LINE_FEED: Char = '\n'
        private const val CARRIAGE_RETURN: Char = '\r'

        private const val NOT_A_TD1_ZONE: String =
            "The machine readable zone must have 90 characters (TD1, three lines of 30), with or without line breaks " +
                "between the lines."

        private const val TRUNCATED_DOCUMENT_NUMBER: String =
            "The document number is marked as truncated, but the optional data does not hold its remaining " +
                "characters, a check digit and a filler."

        /**
         * The MRZ password from the MRZ information [value] exactly as it appears in the machine readable zone: the
         * document number with its check digit, the date of birth with its check digit and the date of expiry with its
         * check digit, without separators (ICAO 9303-11, section 4.3.2 and Appendix D.2). For a passport (TD3) or a
         * TD2 document, these are the characters 1 to 10, 14 to 20 and 22 to 28 of the lower line of the zone (ICAO
         * 9303-4 and ICAO 9303-6, section 4.2.4). For a document number longer than nine characters, the complete
         * number is given, followed by its check digit (ICAO 9303-11, note to Table 14).
         *
         * Every rule of [DocumentNumber.of] and [Date.parse] applies, except that lower-case letters are refused, and
         * every check digit is verified (ICAO 9303-3, section 4.9), so that a mistyped or misread character is found
         * before PACE.
         *
         * @param value the characters; taken over without a copy (see [PacePassword]).
         * @throws IllegalArgumentException if [value] is refused, with the first of these messages whose rule is
         *   broken: "The MRZ information must have at least 24 characters.", "The MRZ information must consist of the
         *   digits 0 to 9, the letters A to Z and the filler '<' only.", "The document number must not start with the
         *   filler '<'.", the messages of [Date.parse] about the parts, the month and the day, for the date of birth
         *   and then for the date of expiry, "The date of expiry must be complete; only a date of birth may have
         *   unknown parts.", "The check digit of the document number does not match.", "The check digit of the date of
         *   birth does not match." and "The check digit of the date of expiry does not match."
         */
        @JvmStatic
        public fun fromMrzInformation(value: CharArray): Mrz {
            value.requireOrWipe(value.size >= MIN_LENGTH) {
                "The MRZ information must have at least $MIN_LENGTH characters."
            }
            value.requireOrWipe(value.all { it.isMrzCharacter() }) {
                "The MRZ information must consist of the digits 0 to 9, the letters A to Z and the filler '<' only."
            }

            val numberEnd = value.size - DATES_WITH_CHECK_DIGITS - 1
            val birth = numberEnd + 1
            val expiry = birth + DATE_LENGTH + 1

            DocumentNumber.requireValid(value, 0, numberEnd)
            Date.requireValid(value, birth)
            Date.requireValid(value, expiry)
            value.requireOrWipe((expiry until expiry + DATE_LENGTH).none { value[it] == FILLER }) {
                INCOMPLETE_DATE_OF_EXPIRY
            }
            value.requireOrWipe(value[numberEnd] == checkDigit(value, 0, numberEnd)) {
                "The check digit of the document number does not match."
            }
            value.requireOrWipe(value[birth + DATE_LENGTH] == checkDigit(value, birth, birth + DATE_LENGTH)) {
                "The check digit of the date of birth does not match."
            }
            value.requireOrWipe(value[expiry + DATE_LENGTH] == checkDigit(value, expiry, expiry + DATE_LENGTH)) {
                "The check digit of the date of expiry does not match."
            }

            return Mrz(value)
        }

        /**
         * The MRZ password from the whole machine readable zone [value] of a TD1 size document, such as an ID card:
         * three lines of 30 characters (ICAO 9303-5, section 4.2.2), given one after the other, with or without a line
         * break (line feed, or carriage return and line feed) after each line. The zones of other formats are refused:
         * for a passport (TD3) or a TD2 document, take the MRZ information from the lower line and use
         * [fromMrzInformation].
         *
         * The MRZ information is read from the document number with its check digit (characters 6 to 15 of the upper
         * line) and the date of birth and the date of expiry with their check digits (characters 1 to 7 and 9 to 15 of
         * the middle line; ICAO 9303-5, sections 4.2.2.1, 4.2.2.2 and 4.2.4). If a filler stands in place of the
         * document number's check digit, the number has more than nine characters: its remaining characters are at the
         * beginning of the optional data (characters 16 to 30 of the upper line), followed by the check digit and a
         * filler (ICAO 9303-5, note j to section 4.2.2), and the complete number is used (ICAO 9303-11, note to Table
         * 14).
         *
         * Every rule of [fromMrzInformation] applies to these fields, and their three check digits are verified. The
         * rest of the zone is not checked: neither the other fields, such as the names, nor the composite check digit,
         * so that a character misread outside the three fields does not refuse the password.
         *
         * @param value the characters of the zone; overwritten in every case, also when the password is built (see
         *   [PacePassword]).
         * @throws IllegalArgumentException if [value] is refused, with the first of these messages whose rule is
         *   broken: "The machine readable zone must have 90 characters (TD1, three lines of 30), with or without line
         *   breaks between the lines.", "The document number is marked as truncated, but the optional data does not
         *   hold its remaining characters, a check digit and a filler.", and the messages of [fromMrzInformation]
         *   after its first.
         */
        @JvmStatic
        public fun fromMachineReadableZone(value: CharArray): Mrz {
            val zone = CharArray(TD1_LENGTH)

            try {
                value.requireOrWipe(copyLines(value, zone)) { NOT_A_TD1_ZONE }

                return fromMrzInformation(td1MrzInformation(zone))
            } finally {
                value.wipe()
                zone.wipe()
            }
        }

        /**
         * Copies the lines of a TD1 zone from [value] to [zone] without their line breaks, and returns whether
         * [value] is such a zone: 90 characters, and line breaks only after a complete line.
         */
        private fun copyLines(value: CharArray, zone: CharArray): Boolean {
            var length = 0

            for (character in value) {
                val isLineBreak = character == LINE_FEED || character == CARRIAGE_RETURN

                if (isLineBreak && (length == 0 || length % TD1_LINE_LENGTH != 0)) {
                    return false
                }

                if (!isLineBreak) {
                    if (length == zone.size) {
                        return false
                    }

                    zone[length] = character
                    length++
                }
            }

            return length == zone.size
        }

        /**
         * The MRZ information of the TD1 [zone], 90 characters without line breaks; the caller checks its fields.
         *
         * @throws IllegalArgumentException if the document number is marked as truncated and the optional data does
         *   not complete it.
         */
        private fun td1MrzInformation(zone: CharArray): CharArray {
            val isTruncated = zone[TD1_DOCUMENT_NUMBER_CHECK_DIGIT] == FILLER
            // The remaining characters of a truncated number and its check digit end before the first filler of the
            // optional data.
            val optionalData = TD1_OPTIONAL_DATA until TD1_LINE_LENGTH
            val remainderEnd = if (isTruncated) optionalData.firstOrNull { zone[it] == FILLER } else null
            val remainderLength = remainderEnd?.minus(TD1_OPTIONAL_DATA)

            require(!isTruncated || (remainderLength != null && remainderLength >= MIN_REMAINDER_LENGTH)) {
                TRUNCATED_DOCUMENT_NUMBER
            }

            // The nine characters of the field, then the check digit or the remainder that ends with it.
            val numberLength = DOCUMENT_NUMBER_LENGTH + (remainderLength ?: 1)
            val information = CharArray(numberLength + DATES_WITH_CHECK_DIGITS)
            val dateLength = DATE_LENGTH + 1

            zone.copyInto(information, 0, TD1_DOCUMENT_NUMBER, TD1_DOCUMENT_NUMBER_CHECK_DIGIT)

            if (remainderLength == null) {
                information[DOCUMENT_NUMBER_LENGTH] = zone[TD1_DOCUMENT_NUMBER_CHECK_DIGIT]
            } else {
                zone.copyInto(
                    information,
                    DOCUMENT_NUMBER_LENGTH,
                    TD1_OPTIONAL_DATA,
                    TD1_OPTIONAL_DATA + remainderLength,
                )
            }

            zone.copyInto(information, numberLength, TD1_DATE_OF_BIRTH, TD1_DATE_OF_BIRTH + dateLength)
            zone.copyInto(information, numberLength + dateLength, TD1_DATE_OF_EXPIRY, TD1_DATE_OF_EXPIRY + dateLength)

            return information
        }

        private fun mrzInformation(
            documentNumber: DocumentNumber,
            dateOfBirth: Date,
            dateOfExpiry: Date,
        ): CharArray {
            val taken = ArrayList<CharArray>(FIELDS)

            try {
                val number = documentNumber.take().also { taken.add(it) }
                val birth = dateOfBirth.take().also { taken.add(it) }
                val expiry = dateOfExpiry.take().also { taken.add(it) }

                require(FILLER !in expiry) { INCOMPLETE_DATE_OF_EXPIRY }

                val information = CharArray(number.size + birth.size + expiry.size + FIELDS)
                var position = 0

                for (field in taken) {
                    field.copyInto(information, position)
                    position += field.size
                    information[position] = checkDigit(field, 0, field.size)
                    position++
                }

                return information
            } finally {
                taken.forEach { it.wipe() }
            }
        }

        /** The check digit of [characters] from index [from] up to [to] (exclusive), ICAO 9303-3, section 4.9. */
        private fun checkDigit(
            characters: CharArray,
            from: Int,
            to: Int,
        ): Char {
            val sum =
                (from until to).sumOf {
                    characters[it].checkDigitValue() * CHECK_DIGIT_WEIGHTS[(it - from) % CHECK_DIGIT_WEIGHTS.size]
                }

            return '0' + sum % CHECK_DIGIT_MODULUS
        }

        private fun Char.isDecimalDigit(): Boolean = this in '0'..'9'

        private fun Char.digitValue(): Int = this - '0'

        /** The characters of the machine readable zone (ICAO 9303-3, section 4.3 and Figure 4). */
        private fun Char.isMrzCharacter(): Boolean = isDecimalDigit() || this in 'A'..'Z' || this == FILLER

        /** Digits count as themselves, letters `A` to `Z` as 10 to 35 and the filler as zero (ICAO 9303-3, 4.9). */
        private fun Char.checkDigitValue(): Int =
            when {
                isDecimalDigit() -> digitValue()
                this in 'A'..'Z' -> this - 'A' + FIRST_LETTER_VALUE
                else -> 0
            }
    }
}
