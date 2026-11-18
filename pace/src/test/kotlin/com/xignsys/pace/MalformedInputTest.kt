package com.xignsys.pace

import com.xignsys.pace.cardaccess.CardAccess
import com.xignsys.pace.cardaccess.MalformedCardAccessException
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.fixtures.CardAccessMother
import com.xignsys.pace.fixtures.CertificateExtensionsMother
import com.xignsys.pace.fixtures.IcaoPaceExample
import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import com.xignsys.pace.internal.crypto.AesCbc
import com.xignsys.pace.internal.crypto.AesCmac
import com.xignsys.pace.internal.crypto.AesKey
import com.xignsys.pace.internal.pace.CertificateExtensions
import com.xignsys.pace.internal.pace.CertificateHolderAuthorizationTemplate
import com.xignsys.pace.internal.pace.DynamicAuthenticationData
import com.xignsys.pace.internal.pace.ImplementedPace
import com.xignsys.pace.internal.pace.PaceSessionKeys
import com.xignsys.pace.internal.securemessaging.SecureMessaging
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatCode
import org.junit.jupiter.api.Test
import java.util.Random

/**
 * Bytes that come from the card or the caller may be anything: every parser must answer malformed input with its
 * documented result, never with another exception. Each test feeds one parser valid inputs changed at random (bytes
 * replaced, removed, inserted, the input cut off, lengths changed) and random bytes, from a fixed seed, so that a
 * failure can be repeated.
 */
class MalformedInputTest {
    @Test
    fun cardAccessIsParsedOrRefusedAsMalformed() {
        val valid =
            listOf(
                WorkedExample.EF_CARD_ACCESS,
                CardAccessMother.cardAccess(
                    CardAccessMother.paceInfo(parameterId = 32),
                    CardAccessMother.paceDomainParameterInfo(),
                    CardAccessMother.terminalAuthenticationInfo(),
                ),
            )

        forEachMutation(valid) { input ->
            try {
                // Explicit domain parameters are read when PACE runs, so they are read here as well.
                CardAccess.parse(input).paceDomainParameterInfos.forEach { ImplementedPace.explicitDomain(it) }
            } catch (_: MalformedCardAccessException) {
                // The documented result.
            }
        }
    }

    @Test
    fun dynamicAuthenticationDataIsDecodedOrRefused() {
        val valid =
            listOf(
                WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE_RESPONSE.dropLast(2).toByteArray(),
                WorkedExample.PACE_MAP_NONCE_RESPONSE.dropLast(2).toByteArray(),
                WorkedExample.PACE_MUTUAL_AUTHENTICATION_RESPONSE.dropLast(2).toByteArray(),
            )

        forEachMutation(valid) { input -> DynamicAuthenticationData.decode(input) }
    }

    @Test
    fun aProtectedResponseIsUnprotectedOrRefused() {
        val secureMessaging =
            SecureMessaging(
                PaceSessionKeys(
                    AesCbc(AesKey.takeOver(IcaoPaceExample.ENCRYPTION_KEY.copyOf())),
                    AesCmac(AesKey.takeOver(IcaoPaceExample.MAC_KEY.copyOf())),
                ),
            )
        val valid =
            listOf(
                WorkedExample.SM_MSE_SET_DST_RESPONSE_PROTECTED,
                WorkedExample.SM_GET_CHALLENGE_RESPONSE_PROTECTED,
                // Constructed data objects, whose content a parser may read late.
                hex("A7 06 30 04 02 02 00 01 99 02 90 00 8E 08 01 02 03 04 05 06 07 08 90 00"),
                hex("B9 04 30 02 05 00 AE 0A 30 08 01 02 03 04 05 06 07 08 90 00"),
            )

        forEachMutation(valid) { input -> secureMessaging.unprotect(input) }
    }

    @Test
    fun theChatAndTheCertificateExtensionsAreAcceptedOrRefused() {
        val valid =
            listOf(
                WorkedExample.PACE_CHAT,
                CertificateExtensionsMother.EID_ACCESS,
                CertificateExtensionsMother.EID_ACCESS_AND_SPECIAL_FUNCTIONS,
            )

        forEachMutation(valid) { input ->
            CertificateHolderAuthorizationTemplate.isOneDataObject(input)
            CertificateExtensions.isValid(input)
        }
    }

    @Test
    fun paceEndsWithAFailureWhateverTheCardAnswers() {
        val cardAccess = CardAccess.parse(WorkedExample.EF_CARD_ACCESS)
        val parameters = PaceParameters(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 13)
        val answers =
            listOf(
                hex("90 00"),
                WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE_RESPONSE,
                WorkedExample.PACE_MAP_NONCE_RESPONSE,
                WorkedExample.PACE_KEY_AGREEMENT_RESPONSE,
                WorkedExample.PACE_MUTUAL_AUTHENTICATION_RESPONSE,
            )
        val random = Random(SEED)

        repeat(PACE_RUNS) {
            // The answers of a real run up to a random step, then a changed one, then anything.
            val intact = random.nextInt(answers.size)
            var step = 0
            val transport =
                CardTransport { _ ->
                    val answer = answers.getOrElse(step) { byteArrayOf() }

                    if (step++ < intact) answer else mutate(answer, random)
                }

            assertThat(Pace.establish(transport, cardAccess, parameters, Can("123456".toCharArray())))
                .isInstanceOf(PaceResult.Failed::class.java)
        }
    }

    /** Calls [parse] with every input of [valid] changed at random, many times, and with random bytes. */
    private fun forEachMutation(valid: List<ByteArray>, parse: (ByteArray) -> Unit) {
        val random = Random(SEED)

        valid.forEach { input -> assertThatCode { parse(input) }.doesNotThrowAnyException() }

        repeat(MUTATIONS) {
            val input = mutate(valid[random.nextInt(valid.size)], random)

            assertThatCode { parse(input) }
                .describedAs("input %s", input.joinToString("") { "%02X".format(it) })
                .doesNotThrowAnyException()
        }
    }

    /** [input] with one to three random changes: a byte replaced, removed or inserted, the input cut off or replaced. */
    private fun mutate(input: ByteArray, random: Random): ByteArray {
        var bytes = input.toList()

        repeat(1 + random.nextInt(MAX_CHANGES)) {
            val at = if (bytes.isEmpty()) 0 else random.nextInt(bytes.size)
            val byte = INTERESTING_BYTES[random.nextInt(INTERESTING_BYTES.size)] ?: random.nextInt().toByte()

            bytes =
                when (random.nextInt(CHANGES)) {
                    0 -> bytes.take(at) + byte + bytes.drop(at + 1)
                    1 -> bytes.take(at) + bytes.drop(at + 1)
                    2 -> bytes.take(at) + byte + bytes.drop(at)
                    3 -> bytes.take(at)
                    else -> List(random.nextInt(MAX_RANDOM_LENGTH)) { random.nextInt().toByte() }
                }
        }

        return bytes.toByteArray()
    }

    private companion object {
        /** A fixed seed, so that every run tries the same inputs. */
        const val SEED = 20261118L
        const val MUTATIONS = 20_000
        const val PACE_RUNS = 300
        const val MAX_CHANGES = 3
        const val CHANGES = 5
        const val MAX_RANDOM_LENGTH = 64

        /**
         * Bytes that change the structure of a data object more often than a random byte does: lengths of zero and
         * of the long forms, the tags of SEQUENCE, SET, INTEGER and OBJECT IDENTIFIER and constructed
         * context-specific and application tags; `null` stands for a random byte.
         */
        val INTERESTING_BYTES: List<Byte?> =
            listOf(0x00, 0x80, 0x81, 0x82, 0x84, 0xFF, 0x30, 0x31, 0x02, 0x06, 0xA0, 0xA7, 0x7C, 0x7F)
                .map { it.toByte() } + listOf(null, null, null, null)
    }
}
