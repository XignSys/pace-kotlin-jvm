package com.xignsys.pace.internal.pace

import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.fixtures.CertificateExtensionsMother
import com.xignsys.pace.fixtures.IcaoPaceExample
import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test

/** MSE:Set AT and General Authenticate for PACE (TR-03110 Part 3, B.1, B.13 and B.14.1). */
class PaceCommandsTest {
    private val protocol = PaceProtocol.ECDH_GM_AES_CBC_CMAC_128

    @Test
    fun buildsMseSetAtWithoutChat() {
        // ICAO 9303-11, Appendix G.1, with 84 01 0D added.
        assertThat(PaceCommands.mseSetAt(protocol, 0x01, 13, null, null).encode())
            .isEqualTo(IcaoPaceExample.MSE_SET_AT_WITH_DOMAIN_PARAMETER_REFERENCE)
    }

    @Test
    fun buildsMseSetAtWithChat() {
        // Worked Example section 3.1 with the PIN, password reference 03. The Worked Example puts 84 after the CHAT;
        // TR-03110 Part 3, B.1, and ICAO 9303-11, section 4.4.4.1, list it before the CHAT.
        val example = WorkedExample.MSE_SET_AT
        val untilPasswordReference = example.copyOfRange(0, 20)
        val chat = example.copyOfRange(20, example.size - 3)
        val domainParameterReference = example.copyOfRange(example.size - 3, example.size)

        assertThat(chat).isEqualTo(WorkedExample.PACE_CHAT)
        assertThat(domainParameterReference).isEqualTo(hex("84 01 0D"))
        assertThat(PaceCommands.mseSetAt(protocol, 0x03, 13, WorkedExample.PACE_CHAT, null).encode())
            .isEqualTo(untilPasswordReference + domainParameterReference + chat)
    }

    @Test
    fun appendsTheCertificateExtensionsAfterTheChat() {
        // TR-03110 Part 3, B.1: 80, 83, 84, 7F4C, 65.
        val extensions = CertificateExtensionsMother.EID_ACCESS_AND_SPECIAL_FUNCTIONS
        val data =
            hex("80 0A 04 00 7F 00 07 02 02 04 02 02 83 01 03 84 01 0D") + WorkedExample.PACE_CHAT + extensions

        assertThat(PaceCommands.mseSetAt(protocol, 0x03, 13, WorkedExample.PACE_CHAT, extensions).encode())
            .isEqualTo(hex("00 22 C1 A4") + byteArrayOf(data.size.toByte()) + data)
    }

    @Test
    fun keepsMseSetAtShortAlsoWhenProtected() {
        // TR-03110 Part 3, B.12.2: MSE:Set AT never uses extended length. 18 bytes of 80, 83 and 84 and the 21 bytes of
        // the CHAT leave 200 bytes for the extensions: 239 plain bytes pad to 240, so 87 81 F1 01 with the cryptogram
        // (244 bytes) and 8E 08 with the MAC (10) give 254; one more plain byte pads to 256 (F.3, F.4).
        val chat = WorkedExample.PACE_CHAT

        assertThat(PaceCommands.mseSetAtFitsShortLength(protocol, 13, chat, CertificateExtensionsMother.ofSize(200)))
            .isTrue()
        assertThat(PaceCommands.mseSetAtFitsShortLength(protocol, 13, chat, CertificateExtensionsMother.ofSize(201)))
            .isFalse()
        assertThat(PaceCommands.mseSetAtFitsShortLength(protocol, 13, null, null)).isTrue()
    }

    @Test
    fun putsTheObjectIdentifierOfTheProtocolIntoTheMechanismReference() {
        // TR-03110 Part 3, A.1.1.1: id-PACE-ECDH-IM-AES-CBC-CMAC-256 is 0.4.0.127.0.7.2.2.4.4.4.
        assertThat(PaceCommands.mseSetAt(PaceProtocol.ECDH_IM_AES_CBC_CMAC_256, 0x02, 13, null, null).encode())
            .isEqualTo(hex("00 22 C1 A4 12 80 0A 04 00 7F 00 07 02 02 04 04 04 83 01 02 84 01 0D"))
    }

    @Test
    fun refusesReferencesLongerThanOneByte() {
        assertThatIllegalArgumentException().isThrownBy { PaceCommands.mseSetAt(protocol, 0x100, 13, null, null) }
        assertThatIllegalArgumentException().isThrownBy { PaceCommands.mseSetAt(protocol, 0x02, 256, null, null) }
        assertThatIllegalArgumentException().isThrownBy { PaceCommands.mseSetAt(protocol, 0x02, -1, null, null) }
    }

    @Test
    fun chainsEveryGeneralAuthenticateButTheLast() {
        val empty = DynamicAuthenticationData.encode()
        val token =
            DynamicAuthenticationData.encode(DynamicAuthenticationData.TERMINAL_TOKEN to hex("C2B0BD78 D94BA866"))

        // ICAO 9303-11, Appendix G.1: CLA 10 for steps 1 to 3, CLA 00 for step 4, Le 00 for every step.
        assertThat(PaceCommands.generalAuthenticate(empty, isLast = false).encode())
            .isEqualTo(IcaoPaceExample.ENCRYPTED_NONCE)
        assertThat(PaceCommands.generalAuthenticate(token, isLast = true).encode())
            .isEqualTo(IcaoPaceExample.MUTUAL_AUTHENTICATION)
    }
}
