package com.xignsys.pace.internal.pace

import com.xignsys.pace.Can
import com.xignsys.pace.Mrz
import com.xignsys.pace.PacePassword
import com.xignsys.pace.Pin
import com.xignsys.pace.Puk
import com.xignsys.pace.internal.crypto.wipe
import org.bouncycastle.crypto.digests.SHA1Digest

/** The encoding `f(pi)` of the PACE password (TR-03110 Part 3, Table 5; ICAO 9303-11, section 4.4.1 and Table 14). */
internal object PasswordEncoding {
    /**
     * `f(pi)`: for the CAN, the PIN and the PUK their characters in ISO/IEC 8859-1, for the MRZ the SHA-1 hash of the
     * MRZ information. Every character is in ISO/IEC 8859-1, and every character of the MRZ information in US-ASCII:
     * the password types refuse anything else when they are built. Intermediate bytes are overwritten; the caller
     * overwrites the result.
     */
    fun encode(password: PacePassword): ByteArray {
        val bytes = singleBytes(password.characters)

        return when (password) {
            is Mrz -> sha1(bytes)
            is Can, is Pin, is Puk -> bytes
        }
    }

    /** Each character as the byte of its code, which is its ISO/IEC 8859-1 and, below `0x80`, its US-ASCII encoding. */
    private fun singleBytes(characters: CharArray): ByteArray =
        ByteArray(characters.size) { characters[it].code.toByte() }

    private fun sha1(input: ByteArray): ByteArray {
        val digest = SHA1Digest()
        val output = ByteArray(digest.digestSize)

        try {
            digest.update(input, 0, input.size)
            digest.doFinal(output, 0)
        } finally {
            input.wipe()
        }

        return output
    }
}
