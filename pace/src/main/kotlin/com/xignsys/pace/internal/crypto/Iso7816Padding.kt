package com.xignsys.pace.internal.crypto

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.paddings.ISO7816d4Padding

/**
 * Padding of ISO/IEC 7816-4 (the same as ISO/IEC 9797-1 padding method 2): the byte `80`, then zero
 * bytes up to the next multiple of the block size. Secure Messaging pads both the data to be
 * encrypted and the input of the MAC this way (TR-03110 Part 3, F.3.3). The padding itself is Bouncy Castle's
 * `ISO7816d4Padding`, whose check of received padding runs in constant time.
 */
internal object Iso7816Padding {
    /** Returns [data] followed by its padding to a multiple of [blockSize]; always adds at least one byte. */
    fun pad(data: ByteArray, blockSize: Int = AesCbc.BLOCK_SIZE): ByteArray {
        val padded = ByteArray((data.size / blockSize + 1) * blockSize)

        data.copyInto(padded)
        ISO7816d4Padding().addPadding(padded, data.size)

        return padded
    }

    /**
     * Returns [padded] without its padding, or `null` if the padding is not valid: [padded] is empty
     * or not whole blocks of [blockSize], or its end is not `80` followed by fewer than [blockSize]
     * zero bytes.
     */
    fun unpad(padded: ByteArray, blockSize: Int = AesCbc.BLOCK_SIZE): ByteArray? {
        if (padded.isEmpty() || padded.size % blockSize != 0) {
            return null
        }

        val padding =
            try {
                ISO7816d4Padding().padCount(padded)
            } catch (_: InvalidCipherTextException) {
                return null
            }

        return if (padding <= blockSize) padded.copyOf(padded.size - padding) else null
    }
}
