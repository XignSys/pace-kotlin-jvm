package com.xignsys.pace.fixtures

/** Bytes of a hexadecimal test vector; spaces and line breaks are ignored, as in the published documents. */
internal fun hex(vector: String): ByteArray {
    val digits = vector.filterNot { it.isWhitespace() }

    require(digits.length % 2 == 0) { "A hexadecimal vector has two digits per byte." }

    return ByteArray(digits.length / 2) { digits.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}
