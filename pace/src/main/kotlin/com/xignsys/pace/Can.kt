package com.xignsys.pace

import com.xignsys.pace.internal.crypto.requireOrWipe

/**
 * The card access number printed or displayed on the document. It consists solely of the numerals `0` to `9`, without
 * a check digit (ICAO 9303-4, section 4.1.1.2; ICAO 9303-5, section 3.2.3), so only these digits are accepted.
 *
 * Its length is not checked. ICAO 9303 gives six digits for passports (TD3, ICAO 9303-4, section 4.1.1.2) and for TD1
 * documents such as ID cards (ICAO 9303-5, section 3.2.3), and defines no CAN for TD2 documents. TR-03110 Part 1,
 * section 2.3, defines the CAN as a short password without a length, which may be static (printed on the document),
 * semi-static (printed on a label) or dynamic (chosen by the chip and displayed on the document). A CAN of the wrong
 * length fails in PACE, and the CAN is never blocked.
 *
 * @param value the digits; taken over without a copy (see [PacePassword]).
 * @throws IllegalArgumentException with the message "The CAN must not be empty." if [value] is empty, or "The CAN must
 *   consist of the digits 0 to 9 only." if it contains another character.
 */
public class Can(value: CharArray) : PacePassword() {
    /** `02`, the CAN (TR-03110 Part 3, B.14.1). */
    override val reference: Int get() = 0x02

    override val characters: CharArray = value

    init {
        value.requireOrWipe(value.isNotEmpty()) { "The CAN must not be empty." }
        value.requireOrWipe(value.all { it in '0'..'9' }) { "The CAN must consist of the digits 0 to 9 only." }
    }

    override fun toString(): String = "Can"
}
