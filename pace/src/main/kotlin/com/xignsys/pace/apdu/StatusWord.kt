package com.xignsys.pace.apdu

/**
 * The status word `SW1 SW2` that ends every response APDU, as an unsigned 16-bit value `SW1 * 256 + SW2` (ISO/IEC
 * 7816-4, section 5.6).
 *
 * Immutable and thread-safe.
 *
 * @throws IllegalArgumentException if [value] is not in `0` to `0xFFFF`.
 */
public class StatusWord(
    /** The value `SW1 * 256 + SW2`. */
    public val value: Int,
) {
    init {
        require(value in 0..MAX_VALUE) { "A status word has two bytes." }
    }

    /** The first byte, `SW1`. */
    public val sw1: Int
        get() = value shr BYTE_BITS

    /** The second byte, `SW2`. */
    public val sw2: Int
        get() = value and BYTE_MAX

    override fun equals(other: Any?): Boolean = other is StatusWord && other.value == value

    override fun hashCode(): Int = value

    override fun toString(): String = "StatusWord(${value.toString(HEX_RADIX).uppercase().padStart(HEX_DIGITS, '0')})"

    /** Status words and their size. */
    public companion object {
        /** Normal processing (ICAO 9303-10, section 3.6, Table 1: `9000`). */
        @JvmField
        public val NO_ERROR: StatusWord = StatusWord(0x9000)

        /** Number of bytes of a status word. */
        public const val SIZE: Int = 2

        private const val MAX_VALUE = 0xFFFF
        private const val BYTE_MAX = 0xFF
        private const val BYTE_BITS = 8
        private const val HEX_RADIX = 16
        private const val HEX_DIGITS = 4

        /**
         * The status word of the bytes [sw1] and [sw2].
         *
         * @throws IllegalArgumentException if a byte is not in `0` to `0xFF`.
         */
        @JvmStatic
        public fun of(sw1: Int, sw2: Int): StatusWord {
            require(sw1 in 0..BYTE_MAX && sw2 in 0..BYTE_MAX) { "SW1 and SW2 are bytes." }

            return StatusWord((sw1 shl BYTE_BITS) or sw2)
        }
    }
}
