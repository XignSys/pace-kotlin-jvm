package com.xignsys.pace

import com.xignsys.pace.PaceResult.Established
import com.xignsys.pace.PaceResult.Failed
import com.xignsys.pace.apdu.CommandApdu
import com.xignsys.pace.cardaccess.CardAccess
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.fixtures.CardAccessMother
import com.xignsys.pace.fixtures.SimulatedPaceCard
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.security.SecureRandom

/**
 * Every implemented PACE variant end to end against a simulated card written from TR-03110 Part 3 (A.2.3, A.2.4,
 * A.3.3, A.3.4.1, B.1, F) and ICAO 9303-11 (section 4.4.3.5): ECDH, Generic Mapping or Chip Authentication Mapping
 * and AES-128, AES-192 and AES-256 on every standardized ECDH domain
 * parameter ID (Table 4). Published examples cover only AES-128 on brainpoolP256r1, which `PaceTest` and
 * `ChipAuthenticationMappingTest` run on the ICAO 9303-11 and Worked Example vectors.
 */
class PaceVariantsTest {
    @ParameterizedTest(name = "{0} on ID {1}, nonce of {2} bytes")
    @MethodSource("variants")
    fun establishesPaceAndSecureMessaging(
        protocol: PaceProtocol,
        id: Int,
        nonceLength: Int,
    ) {
        val card = card(protocol, id, nonceLength)

        val result = establish(card, protocol, id)

        assertThat(result).isInstanceOf(Established::class.java)
        result as Established
        assertThat(result.chipEphemeralPublicKey).isEqualTo(card.chipKey)

        if (protocol.mapping == PaceProtocol.Mapping.CHIP_AUTHENTICATION) {
            // ICAO 9303-11, section 4.4.3.5.2: PK_Map,IC = KA(CA_IC, PK_IC); another chip's key does not verify.
            val chipAuthentication = checkNotNull(result.chipAuthentication)

            assertThat(chipAuthentication.verify(card.staticPublicKey)).isTrue()
            assertThat(chipAuthentication.verify(checkNotNull(card.chipKey))).isFalse()
        } else {
            assertThat(result.chipAuthentication).isNull()
        }
        // TR-03110 Part 3, F: the card checks the protected command with its own session keys and SSC 0.
        assertThat(result.channel.transceive(CommandApdu.of(0x00, 0xB0, 0x81, 0x00, ne = 4)))
            .isInstanceOf(SecureMessagingResult.Response::class.java)
    }

    @ParameterizedTest(name = "{0} on ID {1}, nonce of {2} bytes")
    @MethodSource("tooLongNonces")
    fun refusesANonceLongerThanTheGroupOrder(
        protocol: PaceProtocol,
        id: Int,
        nonceLength: Int,
    ) {
        // A.3.3 sets no upper bound; the constant-time multiplication of Bouncy Castle refuses scalars with more bits
        // than the group order, so the library refuses such a nonce (a documented deviation).
        assertThat(establish(card(protocol, id, nonceLength), protocol, id))
            .isEqualTo(Failed.MalformedResponse(PaceStep.ENCRYPTED_NONCE))
    }

    private fun establish(
        card: SimulatedPaceCard,
        protocol: PaceProtocol,
        id: Int,
    ): PaceResult =
        Pace.establish(
            card,
            CardAccess.parse(
                CardAccessMother.cardAccess(
                    CardAccessMother.paceInfo(ASN1ObjectIdentifier(protocol.oid), parameterId = id.toLong()),
                ),
            ),
            PaceParameters(protocol, id),
            Can("123456".toCharArray()),
            SecureRandom(),
        )

    private fun card(
        protocol: PaceProtocol,
        id: Int,
        nonceLength: Int,
    ): SimulatedPaceCard =
        SimulatedPaceCard(
            checkNotNull(ECNamedCurveTable.getByOID(CURVES.getValue(id))),
            protocol.oid,
            KEY_LENGTHS.getValue(protocol),
            // TR-03110 Part 3, Table 5 and D.2.1.4: the CAN as an ISO/IEC 8859-1 character string.
            "123456".toByteArray(Charsets.ISO_8859_1),
            ByteArray(nonceLength) { (it * 7 + 1).toByte() },
            protocol.mapping == PaceProtocol.Mapping.CHIP_AUTHENTICATION,
        )

    private companion object {
        /** TR-03110 Part 3, Table 4: the ECDH IDs and their curves of RFC 5639 and RFC 5114. */
        val CURVES: Map<Int, ASN1ObjectIdentifier> =
            mapOf(
                8 to SECObjectIdentifiers.secp192r1,
                10 to SECObjectIdentifiers.secp224r1,
                12 to SECObjectIdentifiers.secp256r1,
                15 to SECObjectIdentifiers.secp384r1,
                18 to SECObjectIdentifiers.secp521r1,
                9 to TeleTrusTObjectIdentifiers.brainpoolP192r1,
                11 to TeleTrusTObjectIdentifiers.brainpoolP224r1,
                13 to TeleTrusTObjectIdentifiers.brainpoolP256r1,
                14 to TeleTrusTObjectIdentifiers.brainpoolP320r1,
                16 to TeleTrusTObjectIdentifiers.brainpoolP384r1,
                17 to TeleTrusTObjectIdentifiers.brainpoolP512r1,
            )

        /** The order of each curve in bytes. */
        val ORDER_LENGTHS: Map<Int, Int> =
            mapOf(
                8 to 24,
                9 to 24,
                10 to 28,
                11 to 28,
                12 to 32,
                13 to 32,
                14 to 40,
                15 to 48,
                16 to 48,
                17 to 64,
                18 to 66,
            )

        val KEY_LENGTHS: Map<PaceProtocol, Int> =
            mapOf(
                PaceProtocol.ECDH_GM_AES_CBC_CMAC_128 to 16,
                PaceProtocol.ECDH_GM_AES_CBC_CMAC_192 to 24,
                PaceProtocol.ECDH_GM_AES_CBC_CMAC_256 to 32,
                PaceProtocol.ECDH_CAM_AES_CBC_CMAC_128 to 16,
                PaceProtocol.ECDH_CAM_AES_CBC_CMAC_192 to 24,
                PaceProtocol.ECDH_CAM_AES_CBC_CMAC_256 to 32,
            )

        /** Every variant with every nonce of whole AES blocks up to the length of the group order. */
        @JvmStatic
        fun variants(): List<Arguments> =
            KEY_LENGTHS.keys.flatMap { protocol ->
                CURVES.keys.flatMap { id ->
                    (16..ORDER_LENGTHS.getValue(id) step 16).map { Arguments.of(protocol, id, it) }
                }
            }

        /** One block more than the group order allows, on each curve. */
        @JvmStatic
        fun tooLongNonces(): List<Arguments> =
            CURVES.keys.map { id ->
                Arguments.of(PaceProtocol.ECDH_GM_AES_CBC_CMAC_256, id, (ORDER_LENGTHS.getValue(id) / 16 + 1) * 16)
            }
    }
}
