package com.xignsys.pace.apdu

/**
 * A response APDU: the response data field, possibly empty, followed by the status word (ISO/IEC 7816-4, section 5.1).
 *
 * The data is copied in and out; [toString] shows its length only. Immutable and thread-safe.
 */
public class ResponseApdu private constructor(
    private val dataField: ByteArray,
    /** The status word. */
    public val statusWord: StatusWord,
) {
    /** A copy of the response data field, empty if the response has none. */
    public val data: ByteArray
        get() = dataField.copyOf()

    /** The encoded response: the data field followed by `SW1 SW2`. */
    public fun encode(): ByteArray = dataField + byteArrayOf(statusWord.sw1.toByte(), statusWord.sw2.toByte())

    override fun toString(): String = "ResponseApdu(dataLength=${dataField.size}, $statusWord)"

    /** Factories of [ResponseApdu]. */
    public companion object {
        private const val BYTE_MAX = 0xFF

        /** The response with a copy of [data] and [statusWord]. */
        @JvmStatic
        public fun of(data: ByteArray, statusWord: StatusWord): ResponseApdu = ResponseApdu(data.copyOf(), statusWord)

        /**
         * Decodes the response APDU [encoded].
         *
         * @throws IllegalArgumentException if [encoded] is shorter than a status word.
         */
        @JvmStatic
        public fun parse(encoded: ByteArray): ResponseApdu {
            require(encoded.size >= StatusWord.SIZE) { "A response APDU ends with a two-byte status word." }

            val dataLength = encoded.size - StatusWord.SIZE
            val statusWord =
                StatusWord.of(encoded[dataLength].toInt() and BYTE_MAX, encoded[dataLength + 1].toInt() and BYTE_MAX)

            return ResponseApdu(encoded.copyOfRange(0, dataLength), statusWord)
        }
    }
}
