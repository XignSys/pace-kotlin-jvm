package com.xignsys.pace

import com.xignsys.pace.PaceResult.Established
import com.xignsys.pace.PaceResult.Failed
import com.xignsys.pace.PaceResult.Failed.PasswordNotUsable
import com.xignsys.pace.apdu.CommandApdu
import com.xignsys.pace.apdu.StatusWord
import com.xignsys.pace.cardaccess.CardAccess
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.fixtures.CardAccessMother
import com.xignsys.pace.fixtures.CertificateExtensionsMother
import com.xignsys.pace.fixtures.FakeCardTransport
import com.xignsys.pace.fixtures.FakeCardTransport.Exchange
import com.xignsys.pace.fixtures.IcaoExamples
import com.xignsys.pace.fixtures.IcaoPaceExample
import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import com.xignsys.pace.internal.crypto.AesCbc
import com.xignsys.pace.internal.crypto.AesCmac
import com.xignsys.pace.internal.crypto.AesKey
import com.xignsys.pace.internal.pace.PaceSessionKeys
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalStateException
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.bouncycastle.util.test.FixedSecureRandom
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
import java.io.IOException

/**
 * PACE as the terminal, replayed on the published examples: ICAO 9303-11 Appendix G.1 (MRZ, no CHAT) and the BSI EAC2
 * Worked Example v1.02 section 3 (PIN, CHAT). The terminal's private keys of the examples are fed to the key pair
 * generator through Bouncy Castle's `FixedSecureRandom`.
 */
class PaceTest {
    private val icaoCardAccess = CardAccess.parse(CardAccessMother.cardAccess(IcaoExamples.PACE_INFO_ECDH_GM))
    private val icaoParameters = PaceParameters(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 13)

    @Test
    fun runsTheEcdhExampleOfIcaoAppendixG1() {
        val transport = FakeCardTransport(*icaoExchanges())
        val characters = IcaoPaceExample.MRZ_INFORMATION.toCharArray()

        val result = run(transport, Mrz.fromMrzInformation(characters))

        assertThat(result).isInstanceOf(Established::class.java)
        result as Established
        assertThat(result.chipEphemeralPublicKey).isEqualTo(IcaoPaceExample.CHIP_PUBLIC_KEY)
        assertThat(result.certificationAuthorityReferences).isEmpty()
        assertSessionKeys(result.channel.secureMessaging.keys, IcaoPaceExample.ENCRYPTION_KEY, IcaoPaceExample.MAC_KEY)
        assertThat(transport.isExhausted).isTrue()
        assertThat(characters).containsOnly(Char.MIN_VALUE)
    }

    @Test
    fun runsTheWorkedExampleWithThePinAndAChat() {
        // The Worked Example puts 84 after the CHAT; the library sends the data objects in the order TR-03110 Part 3,
        // B.1, and ICAO 9303-11, section 4.4.4.1, list them: 80, 83, 84, 7F4C. Every other byte is the example's.
        val example = WorkedExample.MSE_SET_AT
        val mseSetAt = example.copyOfRange(0, 20) + hex("84 01 0D") + WorkedExample.PACE_CHAT
        val transport =
            FakeCardTransport(
                Exchange.Respond(mseSetAt, hex("90 00")),
                Exchange.Respond(
                    WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE,
                    WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE_RESPONSE,
                ),
                Exchange.Respond(WorkedExample.PACE_MAP_NONCE, WorkedExample.PACE_MAP_NONCE_RESPONSE),
                Exchange.Respond(WorkedExample.PACE_KEY_AGREEMENT, WorkedExample.PACE_KEY_AGREEMENT_RESPONSE),
                Exchange.Respond(
                    WorkedExample.PACE_MUTUAL_AUTHENTICATION,
                    WorkedExample.PACE_MUTUAL_AUTHENTICATION_RESPONSE,
                ),
                // Section 4.1: the first command on the channel, with the session keys of PACE and SSC 0 before it.
                Exchange.Respond(
                    WorkedExample.SM_MSE_SET_DST_PROTECTED,
                    WorkedExample.SM_MSE_SET_DST_RESPONSE_PROTECTED,
                ),
            )
        val random =
            FixedSecureRandom(WorkedExample.PACE_MAPPING_PRIVATE_KEY + WorkedExample.PACE_AGREEMENT_PRIVATE_KEY)

        assertThat(example.copyOfRange(20, 20 + WorkedExample.PACE_CHAT.size)).isEqualTo(WorkedExample.PACE_CHAT)
        assertThat(mseSetAt).hasSameSizeAs(example)

        val result =
            Pace.establish(
                transport,
                CardAccess.parse(WorkedExample.EF_CARD_ACCESS),
                PaceParameters(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 13, WorkedExample.PACE_CHAT),
                Pin("123456".toCharArray()),
                random,
            )

        assertThat(result).isInstanceOf(Established::class.java)
        result as Established
        assertThat(result.certificationAuthorityReferences).containsExactly("DECVCAAT00001".toByteArray())
        assertThat(
            result.chipEphemeralPublicKey,
        ).isEqualTo(WorkedExample.PACE_KEY_AGREEMENT_RESPONSE.copyOfRange(4, 69))
        assertSessionKeys(
            result.channel.secureMessaging.keys,
            WorkedExample.PACE_ENCRYPTION_KEY,
            WorkedExample.PACE_MAC_KEY,
        )
        assertThat(result.channel.transceive(CommandApdu.parse(WorkedExample.SM_MSE_SET_DST)))
            .isInstanceOf(SecureMessagingResult.Response::class.java)
        assertThat(transport.isExhausted).isTrue()
    }

    @Test
    fun sendsTheCertificateExtensionsAfterTheChat() {
        // TR-03110 Part 3, B.1 and B.14.1: 65 follows the CHAT. The Worked Example has no 65; its responses do not
        // depend on MSE:Set AT, so the run completes.
        val extensions = CertificateExtensionsMother.EID_ACCESS_AND_SPECIAL_FUNCTIONS
        val data = WorkedExample.MSE_SET_AT.copyOfRange(5, 20) + hex("84 01 0D") + WorkedExample.PACE_CHAT + extensions
        val transport =
            FakeCardTransport(
                Exchange.Respond(hex("00 22 C1 A4") + byteArrayOf(data.size.toByte()) + data, hex("90 00")),
                Exchange.Respond(
                    WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE,
                    WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE_RESPONSE,
                ),
                Exchange.Respond(WorkedExample.PACE_MAP_NONCE, WorkedExample.PACE_MAP_NONCE_RESPONSE),
                Exchange.Respond(WorkedExample.PACE_KEY_AGREEMENT, WorkedExample.PACE_KEY_AGREEMENT_RESPONSE),
                Exchange.Respond(
                    WorkedExample.PACE_MUTUAL_AUTHENTICATION,
                    WorkedExample.PACE_MUTUAL_AUTHENTICATION_RESPONSE,
                ),
            )

        val result =
            Pace.establish(
                transport,
                CardAccess.parse(WorkedExample.EF_CARD_ACCESS),
                PaceParameters(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 13, WorkedExample.PACE_CHAT, extensions),
                Pin("123456".toCharArray()),
                FixedSecureRandom(WorkedExample.PACE_MAPPING_PRIVATE_KEY + WorkedExample.PACE_AGREEMENT_PRIVATE_KEY),
            )

        assertThat(result).isInstanceOf(Established::class.java)
        assertThat(transport.isExhausted).isTrue()
    }

    @Test
    fun overwritesThePasswordWhateverTheOutcome() {
        val succeeding = IcaoPaceExample.MRZ_INFORMATION.toCharArray()
        val refused = IcaoPaceExample.MRZ_INFORMATION.toCharArray()
        val notSupported = IcaoPaceExample.MRZ_INFORMATION.toCharArray()
        val lost = IcaoPaceExample.MRZ_INFORMATION.toCharArray()

        run(FakeCardTransport(*icaoExchanges()), Mrz.fromMrzInformation(succeeding))
        run(failingAt(0, hex("6A 80")), Mrz.fromMrzInformation(refused))
        Pace.establish(
            FakeCardTransport(),
            icaoCardAccess,
            PaceParameters(PaceProtocol.ECDH_IM_AES_CBC_CMAC_128, 13),
            Mrz.fromMrzInformation(notSupported),
        )
        runCatching {
            run(
                FakeCardTransport(Exchange.Fail(IcaoPaceExample.MSE_SET_AT_WITH_DOMAIN_PARAMETER_REFERENCE)),
                Mrz.fromMrzInformation(lost),
            )
        }

        assertThat(succeeding).containsOnly(Char.MIN_VALUE)
        assertThat(refused).containsOnly(Char.MIN_VALUE)
        assertThat(notSupported).containsOnly(Char.MIN_VALUE)
        assertThat(lost).containsOnly(Char.MIN_VALUE)
    }

    @Test
    fun refusesAPasswordThatHasBeenUsedBefore() {
        // A used PIN must not reach the card: every failed attempt decreases its retry counter (TR-03110 Part 2,
        // sections 2.2.1 and 2.2.3).
        val password = Mrz.fromMrzInformation(IcaoPaceExample.MRZ_INFORMATION.toCharArray())
        val transport = FakeCardTransport()

        run(failingAt(0, hex("6A 80")), password)

        assertThatIllegalStateException()
            .isThrownBy { run(transport, password) }
            .withMessage("The password has been wiped or already used for PACE.")
        assertThat(transport.commands).isEmpty()
    }

    @Test
    fun refusesAWipedPasswordWithoutSendingAnything() {
        val characters = IcaoPaceExample.MRZ_INFORMATION.toCharArray()
        val password = Mrz.fromMrzInformation(characters)
        val transport = FakeCardTransport()

        password.wipe()

        assertThat(characters).containsOnly(Char.MIN_VALUE)
        assertThatIllegalStateException()
            .isThrownBy { run(transport, password) }
            .withMessage("The password has been wiped or already used for PACE.")
        assertThat(transport.commands).isEmpty()
    }

    @Test
    fun reportsTheStatusWordOfEveryStep() {
        // TR-03110 Part 3, B.14.1 and B.14.2: 6A 80, incorrect parameters, and 69 82, which may stand for a password
        // that cannot be used but also for a terminal that is not authorized, have no meaning of their own here.
        for ((index, step) in PaceStep.entries.withIndex()) {
            assertThat(run(failingAt(index, hex("6A 80")), icaoPassword()))
                .isEqualTo(Failed.CardError(step, StatusWord(0x6A80)))
            assertThat(run(failingAt(index, hex("69 82")), icaoPassword()))
                .isEqualTo(Failed.CardError(step, StatusWord(0x6982)))
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["63 C2", "63 C3", "63 CF"])
    fun goesOnAfterTheRetryCounterWarningOfMseSetAt(statusWord: String) {
        // TR-03110 Part 3, B.14.1: with 63 CX the password has been selected; X tries are left. X = 1 and X = 0 are
        // the suspended and the blocked password, tested below.
        val exchanges = icaoExchanges()
        val transport =
            FakeCardTransport(Exchange.Respond(exchanges[0].command, hex(statusWord)), *exchanges.copyOfRange(1, 5))

        assertThat(run(transport, icaoPassword())).isInstanceOf(Established::class.java)
        assertThat(transport.isExhausted).isTrue()
    }

    @ParameterizedTest
    @CsvSource(
        // TR-03110 Part 3, B.14.1: 63 C1 suspended, 63 C0 blocked, 62 83 deactivated. Without a channel of an earlier
        // run, nothing has resumed a suspended password, so the run ends at 63 C1 as well.
        "63 C1, SUSPENDED",
        "63 C0, BLOCKED",
        "62 83, DEACTIVATED",
    )
    fun stopsAtMseSetAtForAPasswordThatCannotBeUsed(statusWord: String, state: PasswordNotUsable.State) {
        val transport = failingAt(0, hex(statusWord))

        assertThat(run(transport, icaoPassword()))
            .isEqualTo(PasswordNotUsable(PaceStep.SET_AUTHENTICATION_TEMPLATE, state))
        assertThat(transport.commands).hasSize(1)
    }

    @ParameterizedTest
    @CsvSource(
        // TR-03110 Part 3, B.14.2: 63 00 without, 63 CX with the number of tries left.
        "63 00,",
        "63 C2, 2",
        "63 C1, 1",
        "63 C0, 0",
    )
    fun reportsAFailedAuthenticationInEveryGeneralAuthenticateStep(statusWord: String, remainingTries: Int?) {
        for ((index, step) in PaceStep.entries.withIndex().drop(1)) {
            assertThat(run(failingAt(index, hex(statusWord)), icaoPassword()))
                .isEqualTo(Failed.AuthenticationFailed(step, remainingTries))
        }
    }

    @ParameterizedTest
    @CsvSource(
        // TR-03110 Part 3, B.14.2: 69 85 suspended, 69 83 blocked, 69 84 deactivated.
        "69 85, SUSPENDED",
        "69 83, BLOCKED",
        "69 84, DEACTIVATED",
    )
    fun reportsAPasswordThatCannotBeUsedInEveryGeneralAuthenticateStep(
        statusWord: String,
        state: PasswordNotUsable.State,
    ) {
        for ((index, step) in PaceStep.entries.withIndex().drop(1)) {
            assertThat(run(failingAt(index, hex(statusWord)), icaoPassword())).isEqualTo(PasswordNotUsable(step, state))
        }
    }

    @Test
    fun keepsTheStatusWordsOfOneCommandToThatCommand() {
        // B.14.1 lists 63 00 and the 69 8X words for General Authenticate only, B.14.2 lists 62 83 for MSE:Set AT only.
        for (value in listOf(0x6300, 0x6983, 0x6984, 0x6985)) {
            val statusWord = StatusWord(value)
            val response = byteArrayOf(statusWord.sw1.toByte(), statusWord.sw2.toByte())

            assertThat(run(failingAt(0, response), icaoPassword()))
                .isEqualTo(Failed.CardError(PaceStep.SET_AUTHENTICATION_TEMPLATE, statusWord))
        }

        assertThat(run(failingAt(1, hex("62 83")), icaoPassword()))
            .isEqualTo(Failed.CardError(PaceStep.ENCRYPTED_NONCE, StatusWord(0x6283)))
    }

    @Test
    fun refusesMalformedResponses() {
        val step1 = PaceStep.ENCRYPTED_NONCE

        // No status word.
        assertThat(run(failingAt(0, hex("90")), icaoPassword()))
            .isEqualTo(Failed.MalformedResponse(PaceStep.SET_AUTHENTICATION_TEMPLATE))
        // Step 1: an empty nonce, one that is not whole blocks, another tag, no data at all.
        assertThat(
            run(failingAt(1, hex("7C 02 80 00 90 00")), icaoPassword()),
        ).isEqualTo(Failed.MalformedResponse(step1))
        assertThat(run(failingAt(1, hex("7C 0A 80 08 01 02 03 04 05 06 07 08 90 00")), icaoPassword()))
            .isEqualTo(Failed.MalformedResponse(step1))
        assertThat(run(failingAt(1, hex("7C 13 80 11") + ByteArray(17) + hex("90 00")), icaoPassword()))
            .isEqualTo(Failed.MalformedResponse(step1))
        assertThat(run(failingAt(1, hex("7C 12 81 10") + ByteArray(16) + hex("90 00")), icaoPassword()))
            .isEqualTo(Failed.MalformedResponse(step1))
        assertThat(run(failingAt(1, hex("90 00")), icaoPassword())).isEqualTo(Failed.MalformedResponse(step1))
        // Step 2: two objects instead of one.
        assertThat(run(failingAt(2, hex("7C 06 82 01 04 82 01 04 90 00")), icaoPassword()))
            .isEqualTo(Failed.MalformedResponse(PaceStep.MAP_NONCE))
        // Step 3: not 7C, and 7C with a length that is not DER.
        assertThat(run(failingAt(3, hex("30 00 90 00")), icaoPassword()))
            .isEqualTo(Failed.MalformedResponse(PaceStep.KEY_AGREEMENT))
        assertThat(
            run(
                failingAt(3, hex("7C 81 43") + IcaoPaceExample.KEY_AGREEMENT_RESPONSE.copyOfRange(2, 71)),
                icaoPassword(),
            ),
        ).isEqualTo(Failed.MalformedResponse(PaceStep.KEY_AGREEMENT))
        // Step 4: 88 without 87, 87 before 86, and a third CA reference (TR-03110 Part 3, B.1 and B.1.4).
        val token = hex("86 08 3A BB 96 74 BC E9 3C 08")

        assertThat(run(failingAt(4, hex("7C 0D") + token + hex("88 01 41 90 00")), icaoPassword()))
            .isEqualTo(Failed.MalformedResponse(PaceStep.MUTUAL_AUTHENTICATION))
        assertThat(run(failingAt(4, hex("7C 0D 87 01 41") + token + hex("90 00")), icaoPassword()))
            .isEqualTo(Failed.MalformedResponse(PaceStep.MUTUAL_AUTHENTICATION))
        assertThat(run(failingAt(4, hex("7C 13") + token + hex("87 01 41 88 01 42 88 01 43 90 00")), icaoPassword()))
            .isEqualTo(Failed.MalformedResponse(PaceStep.MUTUAL_AUTHENTICATION))
    }

    @Test
    fun returnsTheCaReferencesAsTheOctetsTheChipSent() {
        // TR-03110 Part 3, B.1.4: the values of 87 and 88 in card order. They are neither decoded nor checked: A0 is
        // a character of ISO/IEC 8859-1 that UTF-8 would change, 1F and 7F are unassigned codes (D.2, Table 27 and
        // D.2.1.4), and the second value is longer than the 16 characters of a reference.
        val token = hex("86 08 3A BB 96 74 BC E9 3C 08")
        val first = hex("A0 1F 7F 41")
        val second = ByteArray(17) { 0x42 }
        val response = hex("7C 23") + token + hex("87 04") + first + hex("88 11") + second + hex("90 00")
        val result = run(failingAt(4, response), icaoPassword()) as Established

        assertThat(result.certificationAuthorityReferences).containsExactly(first, second)

        result.certificationAuthorityReferences[0][0] = 0

        assertThat(result.certificationAuthorityReferences[0]).isEqualTo(first)
    }

    @Test
    fun acceptsANonceOfTwoBlocks() {
        // TR-03110 Part 3, A.3.3, and ICAO 9303-11, section 4.4.3.3: the nonce is a multiple of the block size. The map
        // nonce command depends on the terminal's mapping key only, so a run with another nonce reaches step 2.
        val transport =
            FakeCardTransport(
                icaoExchanges()[0],
                Exchange.Respond(IcaoPaceExample.ENCRYPTED_NONCE, encryptedNonceResponse(32)),
                Exchange.Respond(IcaoPaceExample.MAP_NONCE, hex("6A 80")),
            )

        assertThat(run(transport, icaoPassword())).isEqualTo(Failed.CardError(PaceStep.MAP_NONCE, StatusWord(0x6A80)))
    }

    @ParameterizedTest
    @ValueSource(ints = [48, 64])
    fun refusesANonceLongerThanTheGroupOrder(length: Int) {
        // A.3.3 sets no upper bound, but Bouncy Castle's constant-time multiplication refuses scalars longer than the
        // group order, 32 bytes for brainpoolP256r1.
        val transport =
            FakeCardTransport(
                icaoExchanges()[0],
                Exchange.Respond(IcaoPaceExample.ENCRYPTED_NONCE, encryptedNonceResponse(length)),
            )

        assertThat(run(transport, icaoPassword())).isEqualTo(Failed.MalformedResponse(PaceStep.ENCRYPTED_NONCE))
    }

    @Test
    fun refusesInvalidChipKeys() {
        val mapping = IcaoPaceExample.MAP_NONCE_RESPONSE
        val agreement = IcaoPaceExample.KEY_AGREEMENT_RESPONSE

        // TR-03110 Part 3, A.2.2.1 and D.2.1.2: a point that is not on the curve, a compressed point.
        assertThat(run(failingAt(2, mapping.withByte(68, mapping[68].toInt() xor 1)), icaoPassword()))
            .isEqualTo(Failed.InvalidChipKey(PaceStep.MAP_NONCE))
        assertThat(run(failingAt(2, hex("7C 23 82 21 02") + mapping.copyOfRange(5, 37) + hex("90 00")), icaoPassword()))
            .isEqualTo(Failed.InvalidChipKey(PaceStep.MAP_NONCE))
        assertThat(run(failingAt(3, agreement.withByte(34, agreement[34].toInt() xor 1)), icaoPassword()))
            .isEqualTo(Failed.InvalidChipKey(PaceStep.KEY_AGREEMENT))
        // TR-03110 Part 2, section 3.2.1; ICAO 9303-11, section 4.4.1 d): the terminal's own key sent back.
        assertThat(
            run(failingAt(3, hex("7C 43 84 41") + IcaoPaceExample.TERMINAL_PUBLIC_KEY + hex("90 00")), icaoPassword()),
        ).isEqualTo(Failed.InvalidChipKey(PaceStep.KEY_AGREEMENT))
    }

    @Test
    fun refusesEncryptedChipAuthenticationDataWithGenericMapping() {
        // ICAO 9303-11, section 4.4.4: 8A MUST NOT be present without Chip Authentication Mapping.
        val response = hex("7C 0E 86 08 3A BB 96 74 BC E9 3C 08 8A 02 00 00 90 00")

        assertThat(run(failingAt(4, response), icaoPassword()))
            .isEqualTo(Failed.MalformedResponse(PaceStep.MUTUAL_AUTHENTICATION))
    }

    @Test
    fun refusesAWrongChipToken() {
        val response = IcaoPaceExample.MUTUAL_AUTHENTICATION_RESPONSE

        assertThat(run(failingAt(4, response.withByte(11, response[11].toInt() xor 1)), icaoPassword()))
            .isEqualTo(Failed.InvalidChipToken)
    }

    @Test
    fun passesTheTransportFailureOn() {
        val exchanges = icaoExchanges()
        val transport = FakeCardTransport(exchanges[0], exchanges[1], Exchange.Fail(IcaoPaceExample.MAP_NONCE))

        assertThatThrownBy { run(transport, icaoPassword()) }.isInstanceOf(IOException::class.java)
        assertThat(transport.isExhausted).isTrue()
    }

    @Test
    fun sendsNothingForParametersTheLibraryDoesNotImplement() {
        // ICAO 9303-11, Appendix G.2 offers DH with the 1024-bit MODP group, ID 0; Integrated Mapping and ID 19 (RFU, Table 4) are not
        // implemented either.
        val cardAccess =
            CardAccess.parse(
                CardAccessMother.cardAccess(
                    IcaoExamples.PACE_INFO_ECDH_GM,
                    IcaoExamples.PACE_INFO_DH_GM,
                    CardAccessMother
                        .paceInfo(
                            CardAccessMother.ECDH_GM_AES_128,
                            parameterId = 19,
                        ).toASN1Primitive()
                        .encoded,
                    CardAccessMother.paceInfo(CardAccessMother.ECDH_IM_AES_256).toASN1Primitive().encoded,
                ),
            )

        for (parameters in listOf(
            PaceParameters(PaceProtocol.DH_GM_AES_CBC_CMAC_128, 0),
            PaceParameters(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 19),
            PaceParameters(PaceProtocol.ECDH_IM_AES_CBC_CMAC_256, 13),
        )) {
            val transport = FakeCardTransport()

            assertThat(Pace.establish(transport, cardAccess, parameters, icaoPassword()))
                .isEqualTo(Failed.ParametersNotSupported)
            assertThat(transport.commands).isEmpty()
        }
    }

    @Test
    fun sendsNothingForAPaceInfoOfAnotherVersion() {
        // ICAO 9303-11, section 9.2.1: the version MUST be 2.
        val cardAccess = CardAccess.parse(CardAccessMother.cardAccess(CardAccessMother.paceInfo(version = 1)))
        val transport = FakeCardTransport()

        assertThat(Pace.establish(transport, cardAccess, icaoParameters, icaoPassword()))
            .isEqualTo(Failed.ParametersNotSupported)
        assertThat(transport.commands).isEmpty()
    }

    @Test
    fun sendsNothingForParametersTheCardDoesNotOffer() {
        // ICAO 9303-11, Appendix I.1: Chip Authentication Mapping on ID 13 only.
        val cardAccess = CardAccess.parse(CardAccessMother.cardAccess(IcaoExamples.PACE_INFO_ECDH_CAM))
        val transport = FakeCardTransport()

        assertThat(Pace.establish(transport, cardAccess, icaoParameters, icaoPassword()))
            .isEqualTo(Failed.ParametersNotOffered)
        assertThat(transport.commands).isEmpty()
    }

    @Test
    fun closingTheChannelOverwritesTheSessionKeys() {
        val result = run(FakeCardTransport(*icaoExchanges()), icaoPassword()) as Established

        result.channel.close()

        assertThatIllegalStateException().isThrownBy {
            result.channel.secureMessaging.keys.mac
                .mac(ByteArray(16))
        }
        assertThatIllegalStateException().isThrownBy {
            result.channel.secureMessaging.keys.encryption
                .encryptBlock(ByteArray(16))
        }
    }

    @Test
    fun returnsACopyOfTheChipKey() {
        val result = run(FakeCardTransport(*icaoExchanges()), icaoPassword()) as Established

        result.chipEphemeralPublicKey.fill(0)

        assertThat(result.chipEphemeralPublicKey).isEqualTo(IcaoPaceExample.CHIP_PUBLIC_KEY)
        assertThat(result.toString())
            .isEqualTo("Established(certificationAuthorityReferences=0, chipAuthentication=false)")
        assertThat(result.chipAuthentication).isNull()
    }

    private fun run(transport: FakeCardTransport, password: PacePassword): PaceResult =
        Pace.establish(transport, icaoCardAccess, icaoParameters, password, icaoRandom())

    /** The ICAO example until the exchange at [index], which the card answers with [response]. */
    private fun failingAt(index: Int, response: ByteArray): FakeCardTransport {
        val exchanges = icaoExchanges()

        return FakeCardTransport(*exchanges.copyOfRange(0, index), Exchange.Respond(exchanges[index].command, response))
    }

    /** A response to step 1 with a nonce of [length] bytes, encrypted with the `K_pi` of the ICAO example. */
    private fun encryptedNonceResponse(length: Int): ByteArray {
        val encryptedNonce =
            AesCbc(AesKey.takeOver(IcaoPaceExample.PASSWORD_KEY.copyOf()))
                .encrypt(ByteArray(16), ByteArray(length) { (it + 1).toByte() })

        return hex("7C") + byteArrayOf((length + 2).toByte(), 0x80.toByte(), length.toByte()) + encryptedNonce +
            hex("90 00")
    }

    private fun icaoExchanges(): Array<Exchange> =
        arrayOf(
            Exchange.Respond(IcaoPaceExample.MSE_SET_AT_WITH_DOMAIN_PARAMETER_REFERENCE, hex("90 00")),
            Exchange.Respond(IcaoPaceExample.ENCRYPTED_NONCE, IcaoPaceExample.ENCRYPTED_NONCE_RESPONSE),
            Exchange.Respond(IcaoPaceExample.MAP_NONCE, IcaoPaceExample.MAP_NONCE_RESPONSE),
            Exchange.Respond(IcaoPaceExample.KEY_AGREEMENT, IcaoPaceExample.KEY_AGREEMENT_RESPONSE),
            Exchange.Respond(IcaoPaceExample.MUTUAL_AUTHENTICATION, IcaoPaceExample.MUTUAL_AUTHENTICATION_RESPONSE),
        )

    private fun icaoRandom(): FixedSecureRandom =
        FixedSecureRandom(IcaoPaceExample.MAPPING_PRIVATE_KEY + IcaoPaceExample.AGREEMENT_PRIVATE_KEY)

    private fun icaoPassword(): PacePassword = Mrz.fromMrzInformation(IcaoPaceExample.MRZ_INFORMATION.toCharArray())

    /** The session keys are the expected ones if they encrypt and MAC a fixed block as keys of those values do. */
    private fun assertSessionKeys(
        keys: PaceSessionKeys,
        encryptionKey: ByteArray,
        macKey: ByteArray,
    ) {
        val block = ByteArray(16)

        assertThat(keys.mac.mac(block)).isEqualTo(AesCmac(AesKey.takeOver(macKey.copyOf())).mac(block))
        assertThat(keys.encryption.encryptBlock(block))
            .isEqualTo(AesCbc(AesKey.takeOver(encryptionKey.copyOf())).encryptBlock(block))
    }

    private fun ByteArray.withByte(index: Int, value: Int): ByteArray = copyOf().also { it[index] = value.toByte() }
}
