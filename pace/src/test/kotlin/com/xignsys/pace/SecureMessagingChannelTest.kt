package com.xignsys.pace

import com.xignsys.pace.SecureMessagingResult.Refused
import com.xignsys.pace.apdu.CommandApdu
import com.xignsys.pace.apdu.StatusWord
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
import org.junit.jupiter.api.Test
import java.io.IOException

/**
 * The Secure Messaging channel: what it sends, when it ends, and what remains of the keys. The exchanges are those of
 * the BSI EAC2 Worked Example v1.02, section 4.1.
 */
class SecureMessagingChannelTest {
    private val sent = mutableListOf<ByteArray>()

    @Test
    fun sendsTheProtectedCommandAndReturnsTheCheckedResponse() {
        val channel = channel { WorkedExample.SM_MSE_SET_DST_RESPONSE_PROTECTED }

        val result = channel.transceive(CommandApdu.parse(WorkedExample.SM_MSE_SET_DST))

        assertThat(sent).containsExactly(WorkedExample.SM_MSE_SET_DST_PROTECTED)
        assertThat(result).isInstanceOf(SecureMessagingResult.Response::class.java)
        assertThat((result as SecureMessagingResult.Response).response.statusWord).isEqualTo(StatusWord.NO_ERROR)
        assertThat(channel.isOpen).isTrue()
    }

    @Test
    fun refusesWithoutSendingAndStaysOpen() {
        val channel = channel { throw AssertionError("nothing must be sent") }

        assertThat(channel.transceive(CommandApdu.of(0x00, 0xB1, 0x00, 0x00, ne = 1))).isEqualTo(Refused.OddInstruction)
        assertThat(
            channel.transceive(CommandApdu.of(0x80, 0xB0, 0x00, 0x00, ne = 1)),
        ).isEqualTo(Refused.UnsupportedClass)
        assertThat(channel.transceive(CommandApdu.of(0x00, 0x2A, 0x00, 0xBE, data = ByteArray(240))))
            .isEqualTo(Refused.TooLongForShortLength(271))
        assertThat(sent).isEmpty()
        assertThat(channel.isOpen).isTrue()
        assertThat(channel.secureMessaging.ssc).isZero()
    }

    @Test
    fun closesAndOverwritesTheKeysWhenAResponseFails() {
        // TR-03110 Part 3, F.6: the card answers 69 88 without Secure Messaging when it has aborted it.
        val channel = channel { hex("69 88") }

        assertThat(channel.transceive(CommandApdu.parse(WorkedExample.SM_MSE_SET_DST)))
            .isEqualTo(SecureMessagingResult.Failed)
        assertThat(channel.isOpen).isFalse()
        assertKeysOverwritten(channel)
        assertThatIllegalStateException().isThrownBy {
            channel.transceive(
                CommandApdu.parse(WorkedExample.SM_MSE_SET_DST),
            )
        }
        assertThatIllegalStateException().isThrownBy { channel.handOver() }
    }

    @Test
    fun closesAndOverwritesTheKeysWhenTheTransportFails() {
        val channel = channel { throw IOException("The connection to the card was lost.") }

        assertThatThrownBy { channel.transceive(CommandApdu.parse(WorkedExample.SM_MSE_SET_DST)) }
            .isInstanceOf(IOException::class.java)
        assertThat(channel.isOpen).isFalse()
        assertKeysOverwritten(channel)
    }

    @Test
    fun handsOverTheTransportWithoutSendingAnything() {
        val transport = CardTransport { throw AssertionError("nothing must be sent") }
        val channel = SecureMessagingChannel(transport, SecureMessaging(keys()))

        assertThat(channel.handOver()).isSameAs(transport)
        assertThat(channel.isOpen).isFalse()
        assertKeysOverwritten(channel)
        assertThatIllegalStateException().isThrownBy { channel.handOver() }
        assertThatIllegalStateException().isThrownBy {
            channel.transceive(
                CommandApdu.parse(WorkedExample.SM_MSE_SET_DST),
            )
        }

        channel.close()

        assertThat(channel.toString()).isEqualTo("SecureMessagingChannel(HANDED_OVER)")
    }

    @Test
    fun closingOverwritesTheKeysOnce() {
        val channel = channel { throw AssertionError("nothing must be sent") }

        channel.close()
        channel.close()

        assertThat(channel.isOpen).isFalse()
        assertKeysOverwritten(channel)
        assertThat(channel.toString()).isEqualTo("SecureMessagingChannel(CLOSED)")
    }

    @Test
    fun namesTheRefusalsAndTheFailure() {
        assertThat(Refused.TooLongForShortLength(271))
            .isEqualTo(Refused.TooLongForShortLength(271))
            .hasSameHashCodeAs(Refused.TooLongForShortLength(271))
            .isNotEqualTo(Refused.TooLongForShortLength(272))
            .hasToString("TooLongForShortLength(protectedDataLength=271)")
        assertThat(Refused.OddInstruction.toString()).isEqualTo("OddInstruction")
        assertThat(Refused.UnsupportedClass.toString()).isEqualTo("UnsupportedClass")
        assertThat(SecureMessagingResult.Failed.toString()).isEqualTo("Failed")
    }

    private fun channel(respond: (ByteArray) -> ByteArray): SecureMessagingChannel =
        SecureMessagingChannel(
            CardTransport { command ->
                sent.add(command.copyOf())
                respond(command)
            },
            SecureMessaging(keys()),
        )

    private fun assertKeysOverwritten(channel: SecureMessagingChannel) {
        val keys = channel.secureMessaging.keys

        assertThatIllegalStateException().isThrownBy { keys.mac.mac(ByteArray(16)) }
        assertThatIllegalStateException().isThrownBy { keys.encryption.encryptBlock(ByteArray(16)) }
    }

    private fun keys(): PaceSessionKeys =
        PaceSessionKeys(
            AesCbc(AesKey.takeOver(WorkedExample.PACE_ENCRYPTION_KEY.copyOf())),
            AesCmac(AesKey.takeOver(WorkedExample.PACE_MAC_KEY.copyOf())),
        )
}
