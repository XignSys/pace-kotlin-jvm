package com.xignsys.pace.internal.pace

import com.xignsys.pace.internal.crypto.AesCbc
import com.xignsys.pace.internal.crypto.Iso7816Padding
import com.xignsys.pace.internal.crypto.wipe

/**
 * The Encrypted Chip Authentication Data `A_IC = E(KS_Enc, CA_IC)` of PACE with Chip Authentication Mapping (ICAO
 * 9303-11, section 4.4.3.5): AES-CBC with `KS_Enc` and the IV `E(KS_Enc, -1)`, `-1` being the 128-bit block with every
 * bit set (section 4.4.3.5.4), over `FE2OS(CA_IC)` padded with ISO/IEC 9797-1 padding method 2 (sections 4.4.3.5.3 and
 * 4.4.5.6). The cipher and the padding are Bouncy Castle's, through `internal.crypto`.
 */
internal object EncryptedChipAuthenticationData {
    /** The block `-1` whose encryption is the IV (ICAO 9303-11, section 4.4.3.5.4). */
    private val ALL_ONES: ByteArray = ByteArray(AesCbc.BLOCK_SIZE) { BYTE_ALL_ONES }

    private const val BYTE_ALL_ONES: Byte = -1

    /**
     * Decrypts [encrypted] with [encryption], the cipher with `KS_Enc`, and returns `CA_IC` as an octet string of
     * [orderLength] bytes, or `null` if [encrypted] is not whole blocks, the padding is wrong, or the length is not
     * [orderLength]: FE2OS encodes `CA_IC` with as many octets as the group order, leading zeros included (section
     * 4.4.5.6).
     */
    fun decrypt(
        encryption: AesCbc,
        encrypted: ByteArray,
        orderLength: Int,
    ): ByteArray? {
        if (encrypted.isEmpty() || encrypted.size % AesCbc.BLOCK_SIZE != 0) {
            return null
        }

        val padded = encryption.decrypt(encryption.encryptBlock(ALL_ONES), encrypted)

        try {
            val data = Iso7816Padding.unpad(padded) ?: return null

            if (data.size != orderLength) {
                data.wipe()

                return null
            }

            return data
        } finally {
            padded.wipe()
        }
    }
}
