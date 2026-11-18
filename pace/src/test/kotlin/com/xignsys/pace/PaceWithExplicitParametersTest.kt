package com.xignsys.pace

import com.xignsys.pace.PaceResult.Established
import com.xignsys.pace.PaceResult.Failed
import com.xignsys.pace.cardaccess.CardAccess
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.fixtures.CardAccessMother
import com.xignsys.pace.fixtures.FakeCardTransport
import com.xignsys.pace.fixtures.FakeCardTransport.Exchange
import com.xignsys.pace.fixtures.IcaoPaceExample
import com.xignsys.pace.fixtures.SimulatedPaceCard
import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.util.test.FixedSecureRandom
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * PACE on explicit domain parameters of EF.CardAccess (TR-03110 Part 3, A.1.1.1, A.2.1 and A.2.1.3; ICAO 9303-11,
 * sections 9.2.1, 9.2.2 and 9.5.2): a local ID of 32 or more, a `PACEDomainParameterInfo` with it, and parameters that
 * are one of the library's standardized curves.
 */
class PaceWithExplicitParametersTest {
    private val protocol = PaceProtocol.ECDH_GM_AES_CBC_CMAC_128

    @Test
    fun runsTheIcaoExampleOnItsCurveGivenExplicitly() {
        // ICAO 9303-11, Appendix G.1, with brainpoolP256r1 as the explicit parameters the appendix prints, under the
        // local ID 32 (0x20) in 84; every other byte is the example's.
        val exchanges = icaoExchanges(hex("00 22 C1 A4 12 80 0A 04 00 7F 00 07 02 02 04 02 02 83 01 01 84 01 20"))
        val transport = FakeCardTransport(*exchanges)
        val cardAccess = cardAccess(paceInfo(32), CardAccessMother.paceDomainParameterInfo(parameterId = 32))

        val result = establish(transport, cardAccess, 32)

        assertThat(result).isInstanceOf(Established::class.java)
        assertThat((result as Established).chipEphemeralPublicKey).isEqualTo(IcaoPaceExample.CHIP_PUBLIC_KEY)
        assertThat(transport.isExhausted).isTrue()
    }

    @Test
    fun runsChipAuthenticationMappingOnExplicitParameters() {
        // ICAO 9303-11, section 9.2.2: a PACEDomainParameterInfo of id-PACE-ECDH-CAM.
        val camProtocol = PaceProtocol.ECDH_CAM_AES_CBC_CMAC_256
        val card =
            SimulatedPaceCard(
                checkNotNull(TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256r1)),
                camProtocol.oid,
                32,
                "123456".toByteArray(Charsets.ISO_8859_1),
                ByteArray(16) { (it + 1).toByte() },
                chipAuthenticationMapping = true,
            )
        val cardAccess =
            cardAccess(
                CardAccessMother.paceInfo(ASN1ObjectIdentifier(camProtocol.oid), parameterId = 40),
                CardAccessMother.paceDomainParameterInfo(parameterId = 40, family = CardAccessMother.ECDH_CAM),
            )

        val result =
            Pace.establish(
                card,
                cardAccess,
                PaceParameters(camProtocol, 40),
                Can("123456".toCharArray()),
                SecureRandom(),
            )

        assertThat(result).isInstanceOf(Established::class.java)
        assertThat(checkNotNull((result as Established).chipAuthentication).verify(card.staticPublicKey)).isTrue()
    }

    @Test
    fun sendsNothingForExplicitParametersThatAreNotKnown() {
        // TR-03110 Part 3, A.2.1.3: terminals MUST NOT use unverified domain parameters; a named curve (ICAO 9303-11,
        // section 9.5.2) is refused as well.
        val named = AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, TeleTrusTObjectIdentifiers.brainpoolP256r1)
        val twisted =
            AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey,
                TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256t1),
            )

        for (algorithmIdentifier in listOf<ASN1Encodable>(named, twisted)) {
            val transport = FakeCardTransport()
            val cardAccess =
                cardAccess(
                    paceInfo(32),
                    CardAccessMother.paceDomainParameterInfo(
                        parameterId = 32,
                        algorithmIdentifier = algorithmIdentifier,
                    ),
                )

            assertThat(establish(transport, cardAccess, 32)).isEqualTo(Failed.ParametersNotSupported)
            assertThat(transport.commands).isEmpty()
        }
    }

    @Test
    fun sendsNothingForAnIdThatDoesNotFitOneByte() {
        // TR-03110 Part 3, B.14.1, does not say how 84 encodes an ID above 255.
        val transport = FakeCardTransport()
        val cardAccess = cardAccess(paceInfo(256), CardAccessMother.paceDomainParameterInfo(parameterId = 256))

        assertThat(establish(transport, cardAccess, 256)).isEqualTo(Failed.ParametersNotSupported)
        assertThat(transport.commands).isEmpty()
    }

    @Test
    fun sendsNothingWithoutTheParametersOfTheId() {
        // A PACEInfo with ID 32 but no PACEDomainParameterInfo with it, and a PACEInfo without an ID (ICAO 9303-11,
        // section 9.2.1, allows that for a single explicit set), which PaceParameters cannot name.
        val offers =
            listOf(
                cardAccess(paceInfo(32), CardAccessMother.paceDomainParameterInfo(parameterId = 33)),
                cardAccess(paceInfo(32)),
                cardAccess(paceInfo(null), CardAccessMother.paceDomainParameterInfo(parameterId = null)),
            )

        for (cardAccess in offers) {
            val transport = FakeCardTransport()

            assertThat(establish(transport, cardAccess, 32)).isEqualTo(Failed.ParametersNotOffered)
            assertThat(transport.commands).isEmpty()
        }
    }

    @Test
    fun neverChoosesExplicitParametersByDefault() {
        // TR-03110 Part 3, A.2.1.1: standardized domain parameters SHOULD be used.
        val cardAccess = cardAccess(paceInfo(32), CardAccessMother.paceDomainParameterInfo(parameterId = 32))

        assertThat(PaceParameters.defaultFor(cardAccess)).isNull()
    }

    private fun establish(
        transport: FakeCardTransport,
        cardAccess: CardAccess,
        id: Int,
    ): PaceResult =
        Pace.establish(
            transport,
            cardAccess,
            PaceParameters(protocol, id),
            Mrz.fromMrzInformation(IcaoPaceExample.MRZ_INFORMATION.toCharArray()),
            FixedSecureRandom(IcaoPaceExample.MAPPING_PRIVATE_KEY + IcaoPaceExample.AGREEMENT_PRIVATE_KEY),
        )

    private fun paceInfo(id: Long?): ASN1Encodable =
        CardAccessMother.paceInfo(CardAccessMother.ECDH_GM_AES_128, parameterId = id)

    private fun cardAccess(vararg securityInfos: ASN1Encodable): CardAccess =
        CardAccess.parse(CardAccessMother.cardAccess(*securityInfos))

    private fun icaoExchanges(mseSetAt: ByteArray): Array<Exchange> =
        arrayOf(
            Exchange.Respond(mseSetAt, hex("90 00")),
            Exchange.Respond(IcaoPaceExample.ENCRYPTED_NONCE, IcaoPaceExample.ENCRYPTED_NONCE_RESPONSE),
            Exchange.Respond(IcaoPaceExample.MAP_NONCE, IcaoPaceExample.MAP_NONCE_RESPONSE),
            Exchange.Respond(IcaoPaceExample.KEY_AGREEMENT, IcaoPaceExample.KEY_AGREEMENT_RESPONSE),
            Exchange.Respond(IcaoPaceExample.MUTUAL_AUTHENTICATION, IcaoPaceExample.MUTUAL_AUTHENTICATION_RESPONSE),
        )
}
