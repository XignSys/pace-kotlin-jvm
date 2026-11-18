package com.xignsys.pace.internal.securemessaging

import com.xignsys.pace.SecureMessagingResult.Refused
import com.xignsys.pace.apdu.CommandApdu
import com.xignsys.pace.apdu.StatusWord
import com.xignsys.pace.fixtures.SimulatedSecureMessagingCard
import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import com.xignsys.pace.internal.crypto.AesCbc
import com.xignsys.pace.internal.crypto.AesCmac
import com.xignsys.pace.internal.crypto.AesKey
import com.xignsys.pace.internal.pace.PaceSessionKeys
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.assertj.core.api.Assertions.assertThatIllegalStateException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/**
 * PACE Secure Messaging (TR-03110 Part 3, F) on the protected APDUs of the BSI EAC2 Worked Example v1.02, sections 4.1,
 * 4.2, 4.6, 5.1 and 5.2 (keys of section 3.4), the other command cases against [SimulatedSecureMessagingCard], and every
 * way a response can fail.
 */
class SecureMessagingTest {
    @Test
    fun protectsAndUnprotectsTheFirstExchangeAfterPace() {
        // Section 4.1: the first command after PACE, so SSC 1 for the command and 2 for the response (F.5).
        val sm = SecureMessaging(keys())

        assertThat(sm.protect(CommandApdu.parse(WorkedExample.SM_MSE_SET_DST)).encode())
            .isEqualTo(WorkedExample.SM_MSE_SET_DST_PROTECTED)

        val response = sm.unprotect(WorkedExample.SM_MSE_SET_DST_RESPONSE_PROTECTED)

        assertThat(response?.data).isEmpty()
        assertThat(response?.statusWord).isEqualTo(StatusWord.NO_ERROR)
        assertThat(sm.ssc).isEqualTo(2)
    }

    @Test
    fun protectsAnExtendedCommandInExtendedLength() {
        // Section 4.2, PSO:Verify Certificate, the second command after PACE (SSC 3 and 4): extended Lc 00 01 66 becomes
        // 00 01 7F, and the new Le is 00 00 (ICAO 9303-11, Figure 5). The published protected command encrypts another
        // certificate than the plain dump shows: the same for the first 43 data bytes, then another public key and
        // signature; its MAC verifies at SSC 3. The protected command is the reference, so the plain command is built
        // from its decrypted data.
        val published = WorkedExample.PSO_VERIFY_CERTIFICATE_PROTECTED
        val plain = WorkedExample.PSO_VERIFY_CERTIFICATE_PLAIN
        val decryptedData = decryptedCryptogram(published, ssc = 3, dataLength = plain.size - 7)
        val command = CommandApdu.parse(plain.copyOf(7) + decryptedData)
        val sm = SecureMessaging(keys(), 2)

        assertThat(decryptedData.copyOf(43)).isEqualTo(plain.copyOfRange(7, 7 + 43))
        assertThat(command.lengthForm).isEqualTo(CommandApdu.LengthForm.EXTENDED)
        assertThat(sm.protect(command).encode()).isEqualTo(published)
        assertThat(sm.unprotect(WorkedExample.SM_PSO_VERIFY_CERTIFICATE_RESPONSE_PROTECTED)?.statusWord)
            .isEqualTo(StatusWord.NO_ERROR)
    }

    @Test
    fun protectsACommandWithOnlyLeAndDecryptsItsResponse() {
        // Section 4.6, Get Challenge: DO 97 with Le 08, a response with DO 87.
        val sm = SecureMessaging(keys(), GET_CHALLENGE_SSC)

        assertThat(sm.protect(CommandApdu.parse(WorkedExample.SM_GET_CHALLENGE)).encode())
            .isEqualTo(WorkedExample.SM_GET_CHALLENGE_PROTECTED)
        assertThat(sm.unprotect(WorkedExample.SM_GET_CHALLENGE_RESPONSE_PROTECTED)?.data)
            .isEqualTo(WorkedExample.SM_GET_CHALLENGE_RESPONSE_DATA)
    }

    @Test
    fun protectsAndUnprotectsTheChipAuthenticationExchanges() {
        // Sections 5.1 and 5.2: the MACs verify with SSC 39 to 42.
        val sm = SecureMessaging(keys(), WorkedExample.SM_SSC_BEFORE_CHIP_AUTHENTICATION)

        assertThat(sm.protect(CommandApdu.parse(WorkedExample.SM_CA_MSE_SET_AT)).encode())
            .isEqualTo(WorkedExample.SM_CA_MSE_SET_AT_PROTECTED)

        val mseResponse = sm.unprotect(WorkedExample.SM_CA_MSE_SET_AT_RESPONSE_PROTECTED)

        assertThat(sm.protect(CommandApdu.parse(WorkedExample.SM_CA_GENERAL_AUTHENTICATE)).encode())
            .isEqualTo(WorkedExample.SM_CA_GENERAL_AUTHENTICATE_PROTECTED)

        val gaResponse = sm.unprotect(WorkedExample.SM_CA_GENERAL_AUTHENTICATE_RESPONSE_PROTECTED)

        assertThat(mseResponse?.data).isEmpty()
        assertThat(mseResponse?.statusWord).isEqualTo(StatusWord.NO_ERROR)
        assertThat(gaResponse?.data).isEqualTo(WorkedExample.SM_CA_GENERAL_AUTHENTICATE_RESPONSE_DATA)
        assertThat(gaResponse?.statusWord).isEqualTo(StatusWord.NO_ERROR)
        assertThat(sm.ssc).isEqualTo(WorkedExample.SM_SSC_BEFORE_CHIP_AUTHENTICATION + 4)
    }

    @Test
    fun protectsACommandWithoutDataAndLe() {
        // F.3.1 case 1: only DO 8E (Figure 5).
        val protectedCommand = SecureMessaging(keys(), SSC).protect(CommandApdu.of(0x00, 0x84, 0x00, 0x00)).encode()
        val received = card().receive(protectedCommand)

        assertThat(protectedCommand).hasSize(4 + 1 + 10 + 1).startsWith(0x0C, 0x84, 0x00, 0x00, 0x0A, 0x8E, 0x08)
        assertThat(received.data).isEmpty()
        assertThat(received.ne).isZero()
    }

    @Test
    fun keepsShortLengthWithTheNewLe() {
        val command = CommandApdu.of(0x00, 0xB0, 0x00, 0x00, ne = 223)
        val protectedCommand = SecureMessaging(keys(), SSC).protect(command)
        val received = card().receive(protectedCommand.encode())

        assertThat(protectedCommand.lengthForm).isEqualTo(CommandApdu.LengthForm.SHORT)
        assertThat(protectedCommand.ne).isEqualTo(256)
        assertThat(received.ne).isEqualTo(223)
        assertThat(received.extended).isFalse()
    }

    @Test
    fun keepsExtendedLengthWithTheNewLeAndProtectedLe() {
        // ICAO 9303-11, Figure 5: new Le 00 00 for extended length; DO 97 carries both Le bytes.
        val command =
            CommandApdu.of(0x00, 0xB0, 0x00, 0x00, ne = 65_536, lengthForm = CommandApdu.LengthForm.EXTENDED)
        val protectedCommand = SecureMessaging(keys(), SSC).protect(command)
        val received = card().receive(protectedCommand.encode())

        assertThat(protectedCommand.encode()).endsWith(0x00, 0x00)
        assertThat(received.extended).isTrue()
        assertThat(received.ne).isEqualTo(65_536)
    }

    @Test
    fun protectsExtendedDataInExtendedLength() {
        val data = ByteArray(240) { 0x5A }
        val command = CommandApdu.of(0x00, 0x2A, 0x00, 0xBE, data = data, lengthForm = CommandApdu.LengthForm.EXTENDED)
        val received = card().receive(SecureMessaging(keys(), SSC).protect(command).encode())

        assertThat(received.data).isEqualTo(data)
        assertThat(received.extended).isTrue()
    }

    @Test
    fun refusesAShortCommandWhoseProtectedFormNeedsExtendedLength() {
        // 240 data bytes need Lc' 4 + 1 + 256 + 10 = 271 once protected (87 with a three-byte length, the indicator, the
        // padded data, 8E): more than short length allows. The caller
        // that built the command chooses the length form (TR-03110 Part 3, B.12.2), so it is refused with that length.
        val sm = SecureMessaging(keys(), SSC)
        val command = CommandApdu.of(0x00, 0x2A, 0x00, 0xBE, data = ByteArray(240))

        assertThat(sm.refusal(command)).isEqualTo(Refused.TooLongForShortLength(271))
        assertThatIllegalArgumentException().isThrownBy { sm.protect(command) }
        assertThat(sm.ssc).isEqualTo(SSC)
    }

    @Test
    fun protectsTheLargestShortCommandThatStillFits() {
        // 239 bytes: 3 + 1 + 240 + 10 = 254; with Le the protected Le 97 01 00 adds 3, which no longer fits.
        val sm = SecureMessaging(keys(), SSC)

        assertThat(sm.refusal(CommandApdu.of(0x00, 0x2A, 0x00, 0xBE, data = ByteArray(239)))).isNull()
        assertThat(sm.refusal(CommandApdu.of(0x00, 0x2A, 0x00, 0xBE, data = ByteArray(239), ne = 256)))
            .isEqualTo(Refused.TooLongForShortLength(257))
    }

    @Test
    fun keepsTheChainingBitAndTheLogicalChannel() {
        val sm = SecureMessaging(keys(), SSC)

        assertThat(sm.protect(CommandApdu.of(0x11, 0x2A, 0x00, 0x00, data = byteArrayOf(1))).cla).isEqualTo(0x1D)
    }

    @ParameterizedTest
    @ValueSource(ints = [0x0C, 0x04, 0x08, 0x80, 0x40, 0xFF])
    fun refusesClassBytesOutsideTheFirstInterindustryClass(cla: Int) {
        val sm = SecureMessaging(keys(), SSC)

        assertThat(sm.refusal(CommandApdu.of(cla, 0xB0, 0x00, 0x00, ne = 1))).isEqualTo(Refused.UnsupportedClass)
    }

    @Test
    fun refusesOddInstructions() {
        // TR-03110 Part 3, F.3 covers even INS only.
        assertThat(SecureMessaging(keys(), SSC).refusal(CommandApdu.of(0x00, 0xB1, 0x00, 0x00, ne = 1)))
            .isEqualTo(Refused.OddInstruction)
    }

    @Test
    fun rejectsAChangedMacProcessingStatusOrCryptogram() {
        assertRejected(changed(WorkedExample.SM_CA_MSE_SET_AT_RESPONSE_PROTECTED, 8))
        assertRejected(changed(WorkedExample.SM_CA_MSE_SET_AT_RESPONSE_PROTECTED, 3))

        val sm = SecureMessaging(keys(), WorkedExample.SM_SSC_BEFORE_CHIP_AUTHENTICATION + 3)

        assertThat(sm.unprotect(changed(WorkedExample.SM_CA_GENERAL_AUTHENTICATE_RESPONSE_PROTECTED, 10))).isNull()
    }

    @Test
    fun rejectsAResponseForAnotherCounter() {
        val sm = SecureMessaging(keys(), WorkedExample.SM_SSC_BEFORE_CHIP_AUTHENTICATION + 2)

        assertThat(sm.unprotect(WorkedExample.SM_CA_MSE_SET_AT_RESPONSE_PROTECTED)).isNull()
    }

    @Test
    fun rejectsAStatusWordOutsideTheMacThatDiffersFromTheProtectedOne() {
        val response = WorkedExample.SM_CA_MSE_SET_AT_RESPONSE_PROTECTED.copyOf()

        response[response.size - 2] = 0x6A
        response[response.size - 1] = 0x82.toByte()

        assertRejected(response)
    }

    @ParameterizedTest
    @ValueSource(strings = ["6987", "6988", "6A82", "9000", "", "90"])
    fun rejectsPlainResponses(response: String) {
        // TR-03110 Part 3, F.6 and ICAO 9303-11, 9.8.5: a card that aborts Secure Messaging answers without it.
        assertRejected(hex(response))
    }

    @Test
    fun rejectsMissingExtraReorderedAndTrailingDataObjects() {
        assertRejected(hex("990290009000"))
        assertRejected(hex("8E08283CF667655C33A6990290009000"))
        assertRejected(hex("990290008E08283CF667655C33A6" + "8001009000"))
        assertRejected(hex("990290008E08283CF667655C33A6" + "009000"))
        assertRejected(hex("990290008E07283CF667655C33" + "9000"))
        assertRejected(hex("9981029000" + "8E08283CF667655C33A69000"))
    }

    @Test
    fun rejectsWrongPaddingAndIndicatorBehindAValidMac() {
        assertRejected(responseCard().respondRaw(ByteArray(16) { 0x11 }, 0x01, 0x9000))
        assertRejected(responseCard().respondRaw(ByteArray(16), 0x01, 0x9000))
        assertRejected(responseCard().respondRaw(hex("41" + "80" + "00".repeat(30)), 0x01, 0x9000))
        assertRejected(responseCard().respondRaw(hex("41800000000000000000000000000000"), 0x02, 0x9000))
    }

    @Test
    fun acceptsAResponseOfTheSimulatedCard() {
        val response = SecureMessaging(keys(), SSC + 1).unprotect(responseCard().respond(hex("0102030405"), 0x6282))

        assertThat(response?.data).containsExactly(1, 2, 3, 4, 5)
        assertThat(response?.statusWord).isEqualTo(StatusWord(0x6282))
    }

    @Test
    fun refusesWorkAfterDestroyAndShowsOnlyTheCounter() {
        val sm = SecureMessaging(keys(), SSC)

        sm.destroy()

        assertThat(sm).hasToString("SecureMessaging(ssc=$SSC)")
        assertThatIllegalStateException().isThrownBy { sm.protect(CommandApdu.parse(WorkedExample.SM_CA_MSE_SET_AT)) }
    }

    @Test
    fun rejectsANegativeCounter() {
        assertThatIllegalArgumentException().isThrownBy { SecureMessaging(keys(), -1) }
    }

    /**
     * The first [dataLength] bytes of the plain data in the cryptogram of the extended protected command [command]
     * (`87 82 01 71 01` at offset 7), decrypted with the IV of [ssc].
     */
    private fun decryptedCryptogram(
        command: ByteArray,
        ssc: Int,
        dataLength: Int,
    ): ByteArray {
        val encryption = AesCbc(AesKey.takeOver(WorkedExample.PACE_ENCRYPTION_KEY.copyOf()))
        val counter = ByteArray(16).also { it[15] = ssc.toByte() }
        val cryptogramLength = (command[9].toInt() and 0xFF shl 8 or (command[10].toInt() and 0xFF)) - 1

        return encryption
            .decrypt(encryption.encryptBlock(counter), command.copyOfRange(12, 12 + cryptogramLength))
            .copyOf(dataLength)
    }

    private fun assertRejected(response: ByteArray) {
        assertThat(SecureMessaging(keys(), SSC + 1).unprotect(response)).isNull()
    }

    private companion object {
        /** The counter before MSE:Set AT of section 5.1; [card] and [responseCard] start from it. */
        const val SSC = WorkedExample.SM_SSC_BEFORE_CHIP_AUTHENTICATION

        /** Before Get Challenge of section 4.6, the sixth command after PACE: five commands and responses before it. */
        const val GET_CHALLENGE_SSC = 10L

        fun keys(): PaceSessionKeys =
            PaceSessionKeys(
                AesCbc(AesKey.takeOver(WorkedExample.PACE_ENCRYPTION_KEY.copyOf())),
                AesCmac(AesKey.takeOver(WorkedExample.PACE_MAC_KEY.copyOf())),
            )

        /** The card's side of a command, for a [SecureMessaging] at [SSC]. */
        fun card() = SimulatedSecureMessagingCard(WorkedExample.PACE_ENCRYPTION_KEY, WorkedExample.PACE_MAC_KEY, SSC)

        /** The card's side of a response, for a [SecureMessaging] at [SSC] + 1. */
        fun responseCard() =
            SimulatedSecureMessagingCard(WorkedExample.PACE_ENCRYPTION_KEY, WorkedExample.PACE_MAC_KEY, SSC + 1)

        fun changed(bytes: ByteArray, index: Int): ByteArray =
            bytes.copyOf().also { it[index] = (it[index].toInt() xor 0x01).toByte() }
    }
}
