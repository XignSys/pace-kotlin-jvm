package com.xignsys.pace.internal.pace

import com.xignsys.pace.Can
import com.xignsys.pace.Mrz
import com.xignsys.pace.Pin
import com.xignsys.pace.Puk
import com.xignsys.pace.fixtures.IcaoPaceExample
import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import com.xignsys.pace.internal.crypto.AesCmac
import com.xignsys.pace.internal.crypto.AesKey
import com.xignsys.pace.internal.crypto.KeyDerivation
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** The password encoding `f(pi)` of TR-03110 Part 3, Table 5, and ICAO 9303-11, Table 14. */
class PasswordEncodingTest {
    @Test
    fun hashesTheMrzInformationOfIcaoAppendixG() {
        val encoded = PasswordEncoding.encode(Mrz.fromMrzInformation(IcaoPaceExample.MRZ_INFORMATION.toCharArray()))

        assertThat(encoded).isEqualTo(IcaoPaceExample.ENCODED_PASSWORD)
        assertThat(keyOf(encoded)).isEqualTo(macWith(IcaoPaceExample.PASSWORD_KEY))
    }

    @Test
    fun encodesThePinAsItsCharacters() {
        // Worked Example section 3: K_pi of the PIN 123456.
        val encoded = PasswordEncoding.encode(Pin("123456".toCharArray()))

        assertThat(encoded).isEqualTo(hex("31 32 33 34 35 36"))
        assertThat(keyOf(encoded)).isEqualTo(macWith(WorkedExample.PACE_PASSWORD_KEY))
    }

    @Test
    fun encodesTheCanAndThePukAsTheirCharacters() {
        // TR-03110 Part 3, Table 5: the CAN and the PUK are character strings like the PIN.
        assertThat(PasswordEncoding.encode(Can("123456".toCharArray()))).isEqualTo(hex("31 32 33 34 35 36"))
        assertThat(PasswordEncoding.encode(Puk("1234567890".toCharArray())))
            .isEqualTo(hex("31 32 33 34 35 36 37 38 39 30"))
    }

    @Test
    fun encodesEachCharacterAsOneIso88591Byte() {
        // TR-03110 Part 3, D.2.1.4: a character string is encoded in ISO/IEC 8859-1, one byte per character.
        val characters = charArrayOf('1', Char(0xA0), Char(0xE4), Char(0xFF))

        assertThat(PasswordEncoding.encode(Pin(characters))).isEqualTo(hex("31 A0 E4 FF"))
    }

    private fun keyOf(encoded: ByteArray): ByteArray =
        AesCmac(KeyDerivation.passwordKey(encoded, AesKey.Size.AES_128)).mac(ByteArray(16))

    // AesKey does not expose its bytes; the MAC over a fixed block identifies the key.
    private fun macWith(key: ByteArray): ByteArray = AesCmac(AesKey.takeOver(key.copyOf())).mac(ByteArray(16))
}
