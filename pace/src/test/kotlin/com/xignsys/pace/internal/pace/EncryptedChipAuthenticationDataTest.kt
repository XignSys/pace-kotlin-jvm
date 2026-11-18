package com.xignsys.pace.internal.pace

import com.xignsys.pace.fixtures.IcaoCamExample
import com.xignsys.pace.internal.crypto.AesCbc
import com.xignsys.pace.internal.crypto.AesKey
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** The decryption of the Encrypted Chip Authentication Data (ICAO 9303-11, section 4.4.3.5), on Appendix I.1. */
class EncryptedChipAuthenticationDataTest {
    private val cipher = AesCbc(AesKey.takeOver(IcaoCamExample.ENCRYPTION_KEY.copyOf()))

    @Test
    fun usesTheIvOfAppendixI1() {
        // Section 4.4.3.5.4: IV = E(KS_Enc, -1).
        assertThat(cipher.encryptBlock(ByteArray(16) { -1 })).isEqualTo(IcaoCamExample.CHIP_AUTHENTICATION_IV)
    }

    @Test
    fun decryptsTheChipAuthenticationDataOfAppendixI1() {
        assertThat(
            EncryptedChipAuthenticationData.decrypt(cipher, IcaoCamExample.ENCRYPTED_CHIP_AUTHENTICATION_DATA, 32),
        ).isEqualTo(IcaoCamExample.CHIP_AUTHENTICATION_DATA)
    }

    @Test
    fun refusesWhatIsNotFe2osOfTheOrderLength() {
        val encrypted = IcaoCamExample.ENCRYPTED_CHIP_AUTHENTICATION_DATA

        // Section 4.4.5.6: as many octets as the group order; 32 bytes, not 31 or 33.
        assertThat(EncryptedChipAuthenticationData.decrypt(cipher, encrypted, 31)).isNull()
        assertThat(EncryptedChipAuthenticationData.decrypt(cipher, encrypted, 33)).isNull()
        // Not whole blocks, no data, no padding in the last block.
        assertThat(EncryptedChipAuthenticationData.decrypt(cipher, encrypted.copyOf(47), 32)).isNull()
        assertThat(EncryptedChipAuthenticationData.decrypt(cipher, byteArrayOf(), 32)).isNull()
        assertThat(EncryptedChipAuthenticationData.decrypt(cipher, encrypted.copyOf(32), 32)).isNull()
    }
}
