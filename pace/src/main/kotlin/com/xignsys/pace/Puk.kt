package com.xignsys.pace

import com.xignsys.pace.internal.crypto.requireOrWipe

/**
 * The PUK, which unblocks the PIN. The same rules as for the [Pin] apply (TR-03110 Part 3, Table 5 and D.2.1.4); on a
 * German ID card it has ten digits.
 *
 * @param value the characters; taken over without a copy (see [PacePassword]).
 * @throws IllegalArgumentException with the message "The PUK must not be empty." if [value] is empty, or "The PUK
 *   must consist of ISO/IEC 8859-1 characters other than 0x00 to 0x1F and 0x7F to 0x9F." if it contains another
 *   character.
 */
public class Puk(value: CharArray) : PacePassword() {
    /** `04`, the PUK (TR-03110 Part 3, B.14.1). */
    override val reference: Int get() = 0x04

    override val characters: CharArray = value

    init {
        value.requireOrWipe(value.isNotEmpty()) { "The PUK must not be empty." }
        // The assigned codes of ISO/IEC 8859-1 (TR-03110 Part 3, D.2.1.4).
        value.requireOrWipe(value.all { it.code in 0x20..0x7E || it.code in 0xA0..0xFF }) {
            "The PUK must consist of ISO/IEC 8859-1 characters other than 0x00 to 0x1F and 0x7F to 0x9F."
        }
    }

    override fun toString(): String = "Puk"
}
