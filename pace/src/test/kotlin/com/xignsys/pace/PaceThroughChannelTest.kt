package com.xignsys.pace

import com.xignsys.pace.PaceResult.Established
import com.xignsys.pace.PaceResult.Failed
import com.xignsys.pace.PaceResult.Failed.PasswordNotUsable
import com.xignsys.pace.apdu.CommandApdu
import com.xignsys.pace.apdu.StatusWord
import com.xignsys.pace.cardaccess.CardAccess
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.fixtures.CertificateExtensionsMother
import com.xignsys.pace.fixtures.IcaoPaceExample
import com.xignsys.pace.fixtures.SimulatedSecureMessagingCard
import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import com.xignsys.pace.internal.crypto.AesCbc
import com.xignsys.pace.internal.crypto.AesCmac
import com.xignsys.pace.internal.crypto.AesKey
import com.xignsys.pace.internal.pace.PaceSessionKeys
import com.xignsys.pace.internal.securemessaging.SecureMessaging
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalStateException
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.bouncycastle.util.test.FixedSecureRandom
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.io.IOException

/**
 * A second PACE run through the channel of a first one, as TR-03110 Part 2, sections 2.4.1 and 3.2.2, uses it to
 * resume a suspended PIN. No published example covers it, so two are combined: the session keys of ICAO 9303-11,
 * Appendix G.1, are the first run's channel, and the BSI EAC2 Worked Example v1.02, section 3 (PIN, CHAT), is the second
 * run, whose commands and responses the simulated card protects with the first run's keys (TR-03110 Part 3, F.5: the
 * commands of the key agreement are protected with the old keys and the old send sequence counter). Section 4.1 then
 * shows that the new channel uses the Worked Example's keys with the send sequence counter 0.
 */
class PaceThroughChannelTest {
    private val card = SimulatedSecureMessagingCard(IcaoPaceExample.ENCRYPTION_KEY, IcaoPaceExample.MAC_KEY, ssc = 0)
    private val script = ArrayDeque<(ByteArray) -> ByteArray>()
    private val outer =
        SecureMessagingChannel(
            { command -> script.removeFirstOrNull()?.invoke(command) ?: throw AssertionError("unexpected command") },
            SecureMessaging(
                PaceSessionKeys(
                    AesCbc(AesKey.takeOver(IcaoPaceExample.ENCRYPTION_KEY.copyOf())),
                    AesCmac(AesKey.takeOver(IcaoPaceExample.MAC_KEY.copyOf())),
                ),
            ),
        )

    @Test
    fun runsPaceWithTheOldKeysAndSwitchesToTheNewOnes() {
        val exchanges = workedExampleExchanges()

        exchanges.forEach { (command, response) -> script.add(protectedStep(command, response)) }
        // Section 4.1: the first command after PACE, protected with the new keys and SSC 0, sent as it is.
        script.add { command ->
            assertThat(command).isEqualTo(WorkedExample.SM_MSE_SET_DST_PROTECTED)
            WorkedExample.SM_MSE_SET_DST_RESPONSE_PROTECTED
        }

        val password = "123456".toCharArray()
        val result = establish(Pin(password))

        assertThat(result).isInstanceOf(Established::class.java)
        result as Established
        assertThat(result.channel).isNotSameAs(outer)
        assertThat(result.certificationAuthorityReferences).containsExactly("DECVCAAT00001".toByteArray())
        assertThat(outer.isOpen).isFalse()
        assertThat(card.ssc).isEqualTo(2L * exchanges.size)
        assertThat(result.channel.secureMessaging.ssc).isZero()
        assertThat(result.channel.transceive(CommandApdu.parse(WorkedExample.SM_MSE_SET_DST)))
            .isInstanceOf(SecureMessagingResult.Response::class.java)
        assertThat(script).isEmpty()
        assertThat(password).containsOnly(Char.MIN_VALUE)
    }

    @Test
    fun keepsTheOldChannelWhenTheCardRefuses() {
        // TR-03110 Part 2, section 3.2.2: if the second run fails, Secure Messaging goes on with the old keys.
        val exchanges = workedExampleExchanges()

        exchanges.dropLast(1).forEach { (command, response) -> script.add(protectedStep(command, response)) }
        script.add(protectedStep(exchanges.last().first, hex("63 C2")))
        script.add(protectedStep(WorkedExample.SM_MSE_SET_DST, hex("90 00")))

        assertThat(establish(Pin("123456".toCharArray())))
            .isEqualTo(Failed.AuthenticationFailed(PaceStep.MUTUAL_AUTHENTICATION, 2))
        assertThat(outer.isOpen).isTrue()
        assertThat(outer.transceive(CommandApdu.parse(WorkedExample.SM_MSE_SET_DST)))
            .isInstanceOf(SecureMessagingResult.Response::class.java)
        assertThat(script).isEmpty()
    }

    @Test
    fun goesOnAfterTheSuspendedWarningOfMseSetAt() {
        // TR-03110 Part 3, B.14.1: X of 63 CX is the number of tries left. Part 2, section 2.2.3: it stays 1 until the
        // suspended password has been entered correctly, so a card whose PIN the first run has temporarily resumed
        // (section 2.4.1) still answers MSE:Set AT with 63 C1.
        val exchanges = workedExampleExchanges()

        script.add(protectedStep(exchanges.first().first, hex("63 C1")))
        exchanges.drop(1).forEach { (command, response) -> script.add(protectedStep(command, response)) }

        assertThat(establish(Pin("123456".toCharArray()))).isInstanceOf(Established::class.java)
        assertThat(outer.isOpen).isFalse()
        assertThat(script).isEmpty()
    }

    @Test
    fun reportsAPasswordTheCardHasNotResumed() {
        // TR-03110 Part 3, B.14.2: a card that has not resumed the password refuses General Authenticate with 69 85.
        val exchanges = workedExampleExchanges()

        script.add(protectedStep(exchanges[0].first, hex("63 C1")))
        script.add(protectedStep(exchanges[1].first, hex("69 85")))

        assertThat(establish(Pin("123456".toCharArray())))
            .isEqualTo(PasswordNotUsable(PaceStep.ENCRYPTED_NONCE, PasswordNotUsable.State.SUSPENDED))
        assertThat(outer.isOpen).isTrue()
        assertThat(script).isEmpty()
    }

    @ParameterizedTest
    @CsvSource(
        // TR-03110 Part 3, B.14.1: a blocked or deactivated password ends the run through a channel as well.
        "63 C0, BLOCKED",
        "62 83, DEACTIVATED",
    )
    fun stopsAtMseSetAtForABlockedOrDeactivatedPassword(statusWord: String, state: PasswordNotUsable.State) {
        script.add(protectedStep(workedExampleExchanges().first().first, hex(statusWord)))

        assertThat(establish(Pin("123456".toCharArray())))
            .isEqualTo(PasswordNotUsable(PaceStep.SET_AUTHENTICATION_TEMPLATE, state))
        assertThat(outer.isOpen).isTrue()
        assertThat(script).isEmpty()
    }

    @Test
    fun protectsTheLongestMseSetAtInShortLength() {
        // TR-03110 Part 3, B.12.2: MSE:Set AT stays short. With the Worked Example CHAT, 200 bytes of certificate
        // extensions are the most that PaceParameters accepts; protected, the data field has 254 bytes.
        val extensions = CertificateExtensionsMother.ofSize(200)
        val plain = workedExampleExchanges().first().first
        val data = plain.copyOfRange(5, plain.size) + extensions
        var protectedLength = 0

        script.add { command ->
            protectedLength = command.size
            protectedStep(hex("00 22 C1 A4") + byteArrayOf(data.size.toByte()) + data, hex("6A 80"))(command)
        }

        val result =
            Pace.establish(
                outer,
                CardAccess.parse(WorkedExample.EF_CARD_ACCESS),
                PaceParameters(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 13, WorkedExample.PACE_CHAT, extensions),
                Pin("123456".toCharArray()),
            )

        assertThat(result).isEqualTo(Failed.CardError(PaceStep.SET_AUTHENTICATION_TEMPLATE, StatusWord(0x6A80)))
        // Header, Lc, 254 data bytes, Le.
        assertThat(protectedLength).isEqualTo(4 + 1 + 254 + 1)
        assertThat(outer.isOpen).isTrue()
    }

    @Test
    fun closesTheOldChannelWhenAResponseFailsSecureMessaging() {
        // TR-03110 Part 3, F.6: a card that has aborted Secure Messaging answers without it, here 69 88.
        script.add { command ->
            card.receive(command)
            hex("69 88")
        }

        assertThat(establish(Pin("123456".toCharArray())))
            .isEqualTo(Failed.SecureMessagingFailed(PaceStep.SET_AUTHENTICATION_TEMPLATE))
        assertThat(outer.isOpen).isFalse()
    }

    @Test
    fun closesTheOldChannelWhenTheTransportFails() {
        val password = "123456".toCharArray()

        script.add { throw IOException("The connection to the card was lost.") }

        assertThatThrownBy { establish(Pin(password)) }.isInstanceOf(IOException::class.java)
        assertThat(outer.isOpen).isFalse()
        assertThat(password).containsOnly(Char.MIN_VALUE)
    }

    @Test
    fun refusesAChannelThatIsNoLongerOpen() {
        val password = "123456".toCharArray()

        outer.close()

        assertThatIllegalStateException()
            .isThrownBy { establish(Pin(password)) }
            .withMessage("The Secure Messaging channel has been closed or handed over.")
        assertThat(password).containsOnly(Char.MIN_VALUE)
        assertThat(card.ssc).isZero()
    }

    private fun establish(password: PacePassword): PaceResult =
        Pace.establish(
            outer,
            CardAccess.parse(WorkedExample.EF_CARD_ACCESS),
            PaceParameters(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 13, WorkedExample.PACE_CHAT),
            password,
            FixedSecureRandom(WorkedExample.PACE_MAPPING_PRIVATE_KEY + WorkedExample.PACE_AGREEMENT_PRIVATE_KEY),
        )

    /**
     * Expects [plainCommand] protected with the first run's keys and answers with [plainResponse], data and status
     * word, protected the same way.
     */
    private fun protectedStep(plainCommand: ByteArray, plainResponse: ByteArray): (ByteArray) -> ByteArray =
        { command ->
            val expected = CommandApdu.parse(plainCommand)
            val received = card.receive(command)

            assertThat(received.header)
                .isEqualTo(
                    byteArrayOf(
                        (expected.cla or SECURE_MESSAGING_CLA).toByte(),
                        expected.ins.toByte(),
                        expected.p1.toByte(),
                        expected.p2.toByte(),
                    ),
                )
            assertThat(received.data).isEqualTo(expected.data)
            assertThat(received.ne).isEqualTo(expected.ne)

            val dataLength = plainResponse.size - StatusWord.SIZE
            val statusWord =
                (plainResponse[dataLength].toInt() and BYTE_MAX shl Byte.SIZE_BITS) or
                    (plainResponse[dataLength + 1].toInt() and BYTE_MAX)

            card.respond(plainResponse.copyOf(dataLength), statusWord)
        }

    /** The PACE exchanges of the Worked Example, section 3, with `84` where the library sends it (see `PaceTest`). */
    private fun workedExampleExchanges(): List<Pair<ByteArray, ByteArray>> =
        listOf(
            WorkedExample.MSE_SET_AT.copyOfRange(0, 20) + hex("84 01 0D") + WorkedExample.PACE_CHAT to hex("90 00"),
            WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE to WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE_RESPONSE,
            WorkedExample.PACE_MAP_NONCE to WorkedExample.PACE_MAP_NONCE_RESPONSE,
            WorkedExample.PACE_KEY_AGREEMENT to WorkedExample.PACE_KEY_AGREEMENT_RESPONSE,
            WorkedExample.PACE_MUTUAL_AUTHENTICATION to WorkedExample.PACE_MUTUAL_AUTHENTICATION_RESPONSE,
        )

    private companion object {
        /** The Secure Messaging bits of the class byte (TR-03110 Part 3, F.3). */
        const val SECURE_MESSAGING_CLA = 0x0C
        const val BYTE_MAX = 0xFF
    }
}
