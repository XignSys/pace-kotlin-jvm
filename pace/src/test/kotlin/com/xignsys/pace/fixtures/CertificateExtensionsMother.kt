package com.xignsys.pace.fixtures

/**
 * Certificate extensions `65` built from TR-03110 Part 3, C.3 and C.3.1, and the Authorization Extensions of TR-03110
 * Part 4, section 2 (id-eIDAccess and id-specialFunctions under id-AT `0.4.0.127.0.7.3.1.2.2`). No published example
 * contains `65`; the bit masks are put into a discretionary data object `53` (Part 3, Table 27).
 */
internal object CertificateExtensionsMother {
    /** id-eIDAccess, `0.4.0.127.0.7.3.1.2.2.1` (Part 4, section 2), DER-encoded. */
    private val EID_ACCESS_OID: ByteArray = hex("06 0A 04 00 7F 00 07 03 01 02 02 01")

    /** id-specialFunctions, `0.4.0.127.0.7.3.1.2.2.2` (Part 4, section 2), DER-encoded. */
    private val SPECIAL_FUNCTIONS_OID: ByteArray = hex("06 0A 04 00 7F 00 07 03 01 02 02 02")

    /** An eID access extension with the 48-bit mask of Part 4, Table 5: Compare DG1 only. */
    val EID_ACCESS: ByteArray = extensions(template(EID_ACCESS_OID, tlv(0x53, hex("00 00 00 00 00 01"))))

    /** Both extensions; special functions with PSC only (Part 4, Table 6). */
    val EID_ACCESS_AND_SPECIAL_FUNCTIONS: ByteArray =
        extensions(
            template(EID_ACCESS_OID, tlv(0x53, hex("00 00 00 00 00 01"))),
            template(SPECIAL_FUNCTIONS_OID, tlv(0x53, hex("80"))),
        )

    /** One eID access extension whose encoding has exactly [size] bytes, from 30 to 250. */
    fun ofSize(size: Int): ByteArray =
        (1..MAX_MASK)
            .map { extensions(template(EID_ACCESS_OID, tlv(0x53, ByteArray(it)))) }
            .first { it.size == size }

    fun extensions(vararg templates: ByteArray): ByteArray = tlv(0x65, templates.fold(byteArrayOf()) { a, b -> a + b })

    fun template(vararg objects: ByteArray): ByteArray = tlv(0x73, objects.fold(byteArrayOf()) { a, b -> a + b })

    /** A DER data object with a one-byte [tag] and a value of at most 255 bytes. */
    fun tlv(tag: Int, value: ByteArray): ByteArray {
        val length =
            if (value.size < SHORT_LENGTH_LIMIT) {
                byteArrayOf(value.size.toByte())
            } else {
                byteArrayOf(LONG_LENGTH_ONE_BYTE, value.size.toByte())
            }

        return byteArrayOf(tag.toByte()) + length + value
    }

    private const val MAX_MASK = 240
    private const val SHORT_LENGTH_LIMIT = 0x80
    private const val LONG_LENGTH_ONE_BYTE: Byte = 0x81.toByte()
}
