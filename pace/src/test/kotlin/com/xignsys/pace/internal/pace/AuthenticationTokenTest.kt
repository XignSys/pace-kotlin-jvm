package com.xignsys.pace.internal.pace

import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.fixtures.IcaoPaceExample
import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import com.xignsys.pace.internal.crypto.AesCmac
import com.xignsys.pace.internal.crypto.AesKey
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** The PACE authentication token over the public key data object `7F49` (TR-03110 Part 3, A.2.4 and D.3.4). */
class AuthenticationTokenTest {
    private val protocol = PaceProtocol.ECDH_GM_AES_CBC_CMAC_128

    @Test
    fun encodesThePublicKeyDataObjectOfIcaoAppendixG1() {
        // ICAO 9303-11, Appendix G.1: the input data for T_IFD.
        assertThat(AuthenticationToken.publicKeyDataObject(protocol, IcaoPaceExample.CHIP_PUBLIC_KEY))
            .isEqualTo(hex("7F 49 4F 06 0A 04 00 7F 00 07 02 02 04 02 02 86 41") + IcaoPaceExample.CHIP_PUBLIC_KEY)
    }

    @Test
    fun computesAndVerifiesTheTokensOfIcaoAppendixG1() {
        val mac = AesCmac(AesKey.takeOver(IcaoPaceExample.MAC_KEY.copyOf()))

        // ICAO 9303-11, Appendix G.1: T_IFD C2B0BD78 D94BA866 and T_IC 3ABB9674 BCE93C08.
        assertThat(AuthenticationToken.compute(mac, protocol, IcaoPaceExample.CHIP_PUBLIC_KEY))
            .isEqualTo(hex("C2B0BD78 D94BA866"))
        assertThat(
            AuthenticationToken.verify(mac, hex("3ABB9674 BCE93C08"), protocol, IcaoPaceExample.TERMINAL_PUBLIC_KEY),
        ).isTrue()
        assertThat(
            AuthenticationToken.verify(mac, hex("3ABB9674 BCE93C09"), protocol, IcaoPaceExample.TERMINAL_PUBLIC_KEY),
        ).isFalse()
    }

    @Test
    fun computesTheTokensOfTheWorkedExample() {
        val mac = AesCmac(AesKey.takeOver(WorkedExample.PACE_MAC_KEY.copyOf()))
        val chipKey = WorkedExample.PACE_KEY_AGREEMENT_RESPONSE.copyOfRange(4, 4 + 65)
        val terminalKey = WorkedExample.PACE_KEY_AGREEMENT.copyOfRange(9, 9 + 65)

        // Worked Example section 3.5: the terminal sends A2 7A ..., the chip answers A2 65 ... (the labels T_PICC and
        // T_PCD of the example are swapped against the APDUs).
        assertThat(AuthenticationToken.compute(mac, protocol, chipKey)).isEqualTo(hex("A2 7A E7 B3 65 73 C1 D9"))
        assertThat(AuthenticationToken.compute(mac, protocol, terminalKey)).isEqualTo(hex("A2 65 8C 2F 38 60 0B 0F"))
    }
}
