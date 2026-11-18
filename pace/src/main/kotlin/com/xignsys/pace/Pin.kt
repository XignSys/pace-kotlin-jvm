package com.xignsys.pace

import com.xignsys.pace.internal.crypto.requireOrWipe

/**
 * The PIN, a secret of the document holder. It is a character string (TR-03110 Part 3, Table 5): each character must be
 * in ISO/IEC 8859-1 and must not be one of the unassigned codes `0x00` to `0x1F` and `0x7F` to `0x9F` (TR-03110 Part 3,
 * D.2.1.4). Length and characters are not checked further; they depend on the document, for example six digits on a
 * German ID card.
 *
 * @param value the characters; taken over without a copy (see [PacePassword]).
 * @throws IllegalArgumentException with the message "The PIN must not be empty." if [value] is empty, or "The PIN
 *   must consist of ISO/IEC 8859-1 characters other than 0x00 to 0x1F and 0x7F to 0x9F." if it contains another
 *   character.
 */
public class Pin(value: CharArray) : PacePassword() {
    /** `03`, the PIN (TR-03110 Part 3, B.14.1). */
    override val reference: Int get() = 0x03

    override val characters: CharArray = value

    init {
        value.requireOrWipe(value.isNotEmpty()) { "The PIN must not be empty." }
        // The assigned codes of ISO/IEC 8859-1 (TR-03110 Part 3, D.2.1.4).
        value.requireOrWipe(value.all { it.code in 0x20..0x7E || it.code in 0xA0..0xFF }) {
            "The PIN must consist of ISO/IEC 8859-1 characters other than 0x00 to 0x1F and 0x7F to 0x9F."
        }
    }

    override fun toString(): String = "Pin"
}
