package com.xignsys.pace.apdu

/**
 * A command APDU: the header `CLA INS P1 P2`, an optional data field of `Nc` bytes and an optional `Le` field that
 * announces `Ne`, the maximum number of response data bytes (ISO/IEC 7816-4, section 5.1).
 *
 * The length fields have short or extended form, and one command uses one form for all of them. [parse] keeps the form
 * as received, so that a command is encoded again in the form it came in; which commands may use the extended form is
 * up to the caller (TR-03110 Part 3, B.12.2; ICAO 9303-10, section 3.6.4.2).
 *
 * The data is copied in and out; [toString] shows the header and the lengths only. Immutable and thread-safe.
 */
public class CommandApdu private constructor(
    /** The class byte. */
    public val cla: Int,
    /** The instruction byte. */
    public val ins: Int,
    /** The first parameter byte. */
    public val p1: Int,
    /** The second parameter byte. */
    public val p2: Int,
    private val dataField: ByteArray,
    /** `Ne`, the maximum number of response data bytes, or [NO_RESPONSE_DATA] if the command has no `Le` field. */
    public val ne: Int,
    /** The form of the length fields; [LengthForm.SHORT] for a command without length fields. */
    public val lengthForm: LengthForm,
) {
    /** A copy of the command data field, empty if the command has none. */
    public val data: ByteArray
        get() = dataField.copyOf()

    /** `Nc`, the number of bytes in the data field. */
    public val nc: Int
        get() = dataField.size

    /** The encoded command. */
    public fun encode(): ByteArray {
        val lc = if (dataField.isEmpty()) byteArrayOf() else lengthForm.encodeLc(dataField.size)
        val le = if (ne == NO_RESPONSE_DATA) byteArrayOf() else lengthForm.encodeLe(ne, dataField.isEmpty())

        return header() + lc + dataField + le
    }

    override fun toString(): String = "CommandApdu(header=${hex(header())}, nc=$nc, ne=$ne, $lengthForm)"

    private fun header(): ByteArray = byteArrayOf(cla.toByte(), ins.toByte(), p1.toByte(), p2.toByte())

    /** The form of the length fields `Lc` and `Le` (ISO/IEC 7816-4, section 5.1). */
    public enum class LengthForm(
        /** The largest `Nc` this form can encode. */
        public val maxNc: Int,
        /** The largest `Ne` this form can encode; the field value `0` stands for it. */
        public val maxNe: Int,
    ) {
        /** One-byte `Lc` and `Le`; `Le` `00` stands for 256. */
        SHORT(maxNc = 255, maxNe = 256),

        /**
         * `Lc` and `Le` with two bytes; `Le` `00 00` stands for 65 536 (ICAO 9303-11, Figure 5). The first length field
         * is preceded by a `00` byte, so `Le` alone is `00` and two bytes.
         */
        EXTENDED(maxNc = 65_535, maxNe = 65_536),
        ;

        internal fun encodeLc(nc: Int): ByteArray =
            when (this) {
                SHORT -> byteArrayOf(nc.toByte())
                EXTENDED -> byteArrayOf(EXTENDED_MARKER, (nc shr BYTE_BITS).toByte(), nc.toByte())
            }

        internal fun encodeLe(ne: Int, withoutLc: Boolean): ByteArray {
            // Ne equal to the maximum is encoded as zero.
            val value = if (ne == maxNe) 0 else ne

            if (this == SHORT) {
                return byteArrayOf(value.toByte())
            }

            val field = byteArrayOf((value shr BYTE_BITS).toByte(), value.toByte())

            return if (withoutLc) byteArrayOf(EXTENDED_MARKER) + field else field
        }
    }

    /** Factories of [CommandApdu]. */
    public companion object {
        /** The value of [ne] for a command without `Le` field. */
        public const val NO_RESPONSE_DATA: Int = 0

        private const val HEADER_SIZE = 4
        private const val BYTE_BITS = 8
        private const val BYTE_MAX = 0xFF
        private const val EXTENDED_MARKER: Byte = 0
        private const val EXTENDED_MARKER_SIZE = 1
        private const val EXTENDED_FIELD_SIZE = 2
        private const val HEX_DIGITS = "0123456789ABCDEF"
        private const val NIBBLE_BITS = 4
        private const val NIBBLE_MASK = 0x0F

        /**
         * The command with the given header, a copy of [data] and [ne], in [lengthForm].
         *
         * @throws IllegalArgumentException if a header byte is not in `0` to `255`, if [data] or [ne] does not fit
         *   [lengthForm], or if [lengthForm] is [LengthForm.EXTENDED] for a command without data and `Le`, which has no
         *   length fields.
         */
        @JvmStatic
        @JvmOverloads
        public fun of(
            cla: Int,
            ins: Int,
            p1: Int,
            p2: Int,
            data: ByteArray = byteArrayOf(),
            ne: Int = NO_RESPONSE_DATA,
            lengthForm: LengthForm = LengthForm.SHORT,
        ): CommandApdu {
            require(listOf(cla, ins, p1, p2).all { it in 0..BYTE_MAX }) { "A header byte must be in 0 to 255." }
            require(data.size <= lengthForm.maxNc) { "The data field does not fit the length form." }
            require(ne in NO_RESPONSE_DATA..lengthForm.maxNe) { "Ne does not fit the length form." }
            require(lengthForm == LengthForm.SHORT || data.isNotEmpty() || ne != NO_RESPONSE_DATA) {
                "A command without data and Le has no length fields and so no extended form."
            }

            return CommandApdu(cla, ins, p1, p2, data.copyOf(), ne, lengthForm)
        }

        /**
         * Decodes the command APDU [encoded] in any of the cases of ISO/IEC 7816-4, section 5.1: without length fields
         * (case 1), with `Le` only (case 2), with `Lc` and data only (case 3) or with both (case 4), each in short or
         * extended form.
         *
         * @throws IllegalArgumentException if [encoded] is not a command APDU in one of these cases, for example if a
         *   length field is zero or does not match the length of the command.
         */
        @JvmStatic
        public fun parse(encoded: ByteArray): CommandApdu {
            require(encoded.size >= HEADER_SIZE) { "A command APDU starts with a four-byte header." }

            val cla = encoded[0].toInt() and BYTE_MAX
            val ins = encoded[1].toInt() and BYTE_MAX
            val p1 = encoded[2].toInt() and BYTE_MAX
            val p2 = encoded[3].toInt() and BYTE_MAX
            val body = encoded.copyOfRange(HEADER_SIZE, encoded.size)

            if (body.isEmpty()) {
                return CommandApdu(cla, ins, p1, p2, byteArrayOf(), NO_RESPONSE_DATA, LengthForm.SHORT)
            }

            val first = body[0].toInt() and BYTE_MAX

            if (body.size == 1) {
                return CommandApdu(cla, ins, p1, p2, byteArrayOf(), shortNe(first), LengthForm.SHORT)
            }

            if (first != 0) {
                return parseShortWithData(cla, ins, p1, p2, body, nc = first)
            }

            return parseExtended(cla, ins, p1, p2, body)
        }

        private fun parseShortWithData(
            cla: Int,
            ins: Int,
            p1: Int,
            p2: Int,
            body: ByteArray,
            nc: Int,
        ): CommandApdu {
            val data = body.copyOfRange(1, minOf(1 + nc, body.size))

            return when (body.size) {
                1 + nc -> {
                    CommandApdu(cla, ins, p1, p2, data, NO_RESPONSE_DATA, LengthForm.SHORT)
                }

                1 + nc + 1 -> {
                    CommandApdu(cla, ins, p1, p2, data, shortNe(body.last().toInt() and BYTE_MAX), LengthForm.SHORT)
                }

                else -> {
                    throw IllegalArgumentException("Lc does not match the length of the command.")
                }
            }
        }

        private fun parseExtended(
            cla: Int,
            ins: Int,
            p1: Int,
            p2: Int,
            body: ByteArray,
        ): CommandApdu {
            val fieldsStart = EXTENDED_MARKER_SIZE
            val fieldsEnd = fieldsStart + EXTENDED_FIELD_SIZE

            require(body.size >= fieldsEnd) { "An extended length field has two bytes after the marker byte." }

            val value = twoByteValue(body, fieldsStart)

            if (body.size == fieldsEnd) {
                return CommandApdu(cla, ins, p1, p2, byteArrayOf(), extendedNe(value), LengthForm.EXTENDED)
            }

            require(value != 0) { "Lc must not be zero." }

            val dataEnd = fieldsEnd + value
            val data = body.copyOfRange(fieldsEnd, minOf(dataEnd, body.size))

            return when (body.size) {
                dataEnd -> {
                    CommandApdu(cla, ins, p1, p2, data, NO_RESPONSE_DATA, LengthForm.EXTENDED)
                }

                dataEnd + EXTENDED_FIELD_SIZE -> {
                    CommandApdu(cla, ins, p1, p2, data, extendedNe(twoByteValue(body, dataEnd)), LengthForm.EXTENDED)
                }

                else -> {
                    throw IllegalArgumentException("Lc does not match the length of the command.")
                }
            }
        }

        private fun twoByteValue(bytes: ByteArray, offset: Int): Int =
            ((bytes[offset].toInt() and BYTE_MAX) shl BYTE_BITS) or (bytes[offset + 1].toInt() and BYTE_MAX)

        private fun shortNe(le: Int): Int = if (le == 0) LengthForm.SHORT.maxNe else le

        private fun extendedNe(le: Int): Int = if (le == 0) LengthForm.EXTENDED.maxNe else le

        private fun hex(bytes: ByteArray): String =
            buildString {
                for (byte in bytes) {
                    append(HEX_DIGITS[(byte.toInt() shr NIBBLE_BITS) and NIBBLE_MASK])
                    append(HEX_DIGITS[byte.toInt() and NIBBLE_MASK])
                }
            }
    }
}
