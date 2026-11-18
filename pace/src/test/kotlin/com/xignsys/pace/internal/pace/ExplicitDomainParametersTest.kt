package com.xignsys.pace.internal.pace

import com.xignsys.pace.cardaccess.CardAccess
import com.xignsys.pace.cardaccess.PaceDomainParameterInfo
import com.xignsys.pace.fixtures.CardAccessMother
import com.xignsys.pace.internal.crypto.EcDomain
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.asn1.x9.X9ECPoint
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.math.ec.ECCurve
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.math.BigInteger

/**
 * Explicit domain parameters of a `PACEDomainParameterInfo` (TR-03110 Part 3, A.2.1.2 and A.2.1.3; ICAO 9303-11,
 * sections 9.2.2 and 9.5.2): used only if they are one of the library's standardized curves.
 */
class ExplicitDomainParametersTest {
    @Test
    fun recognizesTheExplicitBrainpoolP256r1OfIcaoAppendixG1() {
        // ICAO 9303-11, Appendix G.1, prints brainpoolP256r1 as id-ecPublicKey with explicit ECParameters.
        assertThat(ImplementedPace.explicitDomain(info(CardAccessMother.paceDomainParameterInfo())))
            .isSameAs(ImplementedPace.domain(13))
    }

    @ParameterizedTest
    @ValueSource(ints = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18])
    fun recognizesEveryStandardizedCurveGivenExplicitly(id: Int) {
        val domain = checkNotNull(ImplementedPace.domain(id))

        assertThat(ImplementedPace.explicitDomain(info(explicit(domain)))).isSameAs(domain)
        // ECParameters may leave the cofactor out (ANSI X9.62).
        assertThat(ImplementedPace.explicitDomain(info(explicit(domain, cofactor = null)))).isSameAs(domain)
    }

    @Test
    fun refusesParametersThatAreNotOneOfTheCurves() {
        val domain = EcDomain.BRAINPOOL_P256R1
        val p = domain.parameters

        // Another coefficient b, another generator (2G), the twisted curve brainpoolP256t1 (RFC 5639, section 3.4),
        // a cofactor of 2.
        val otherB = ECCurve.Fp(p.curve.field.characteristic, p.curve.a.toBigInteger(), BigInteger.ONE, p.n, p.h)

        assertThat(
            recognize(
                X9ECParameters(otherB, X9ECPoint(otherB.createPoint(BigInteger.ONE, BigInteger.TWO), false), p.n, p.h),
            ),
        ).isNull()
        assertThat(recognize(X9ECParameters(p.curve, X9ECPoint(p.g.twice().normalize(), false), p.n, p.h))).isNull()
        assertThat(recognize(TeleTrusTNamedCurves.getByOID(TeleTrusTObjectIdentifiers.brainpoolP256t1))).isNull()
        assertThat(recognize(X9ECParameters(p.curve, X9ECPoint(p.g, false), p.n, BigInteger.TWO))).isNull()
    }

    @Test
    fun refusesAGeneratorThatIsNotUncompressed() {
        // ICAO 9303-11, sections 4.4.3.2 and 9.4.1: only uncompressed points; TR-03111, section 3.2.1: 02 or 03
        // compressed, 06 or 07 hybrid.
        val p = EcDomain.BRAINPOOL_P256R1.parameters
        val uncompressed = p.g.getEncoded(false)
        val hybrid =
            uncompressed.copyOf().also {
                it[0] = (if (p.g.affineYCoord.testBitZero()) 0x07 else 0x06).toByte()
            }

        assertThat(recognize(X9ECParameters(p.curve, X9ECPoint(p.g, true), p.n, p.h))).isNull()
        assertThat(recognize(X9ECParameters(p.curve, X9ECPoint(p.curve, hybrid), p.n, p.h))).isNull()
        assertThat(recognize(X9ECParameters(p.curve, X9ECPoint(p.curve, uncompressed), p.n, p.h)))
            .isSameAs(ImplementedPace.domain(13))
    }

    @Test
    fun refusesAGeneratorThatIsNotOnItsCurve() {
        // TR-03110 Part 3, A.2.1.3: explicit parameters come from the unprotected EF.CardAccess and may be anything.
        // Bouncy Castle decodes the generator only when it is read and then throws; the parameters are refused.
        val p = EcDomain.BRAINPOOL_P256R1.parameters
        val notOnTheCurve = p.g.getEncoded(false).also { it[it.lastIndex] = (it.last() + 1).toByte() }

        assertThat(recognize(X9ECParameters(p.curve, X9ECPoint(p.curve, notOnTheCurve), p.n, p.h))).isNull()
    }

    @Test
    fun ignoresElementsAfterTheCofactor() {
        // TR-03111, section 5.1.1: ECParameters ends with an extension marker, so later elements may follow.
        val p = EcDomain.BRAINPOOL_P256R1.parameters
        val elements = ASN1EncodableVector()

        (X9ECParameters(p.curve, X9ECPoint(p.g, false), p.n, p.h).toASN1Primitive() as ASN1Sequence).forEach {
            elements.add(it)
        }
        elements.add(ASN1Integer(BigInteger.TWO))

        assertThat(
            ImplementedPace.explicitDomain(
                info(
                    CardAccessMother.paceDomainParameterInfo(
                        algorithmIdentifier =
                            AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, DERSequence(elements)),
                    ),
                ),
            ),
        ).isSameAs(ImplementedPace.domain(13))
    }

    @Test
    fun refusesNamedCurvesAndOtherAlgorithms() {
        val explicit =
            X9ECParameters(
                EcDomain.BRAINPOOL_P256R1.parameters.curve,
                X9ECPoint(EcDomain.BRAINPOOL_P256R1.generator, false),
                EcDomain.BRAINPOOL_P256R1.parameters.n,
                BigInteger.ONE,
            )
        // ICAO 9303-11, section 9.5.2: named curves and implicit domain parameters MUST NOT be used.
        val named = AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, TeleTrusTObjectIdentifiers.brainpoolP256r1)
        val implicit = AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, DERNull.INSTANCE)
        // dhpublicnumber (TR-03110 Part 3, A.2.1.2) with EC parameters, and ECDH parameters declared as DH.
        val dhAlgorithm = AlgorithmIdentifier(ASN1ObjectIdentifier("1.2.840.10046.2.1"), explicit)
        val ecdh = AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, explicit)

        assertThat(
            ImplementedPace.explicitDomain(info(CardAccessMother.paceDomainParameterInfo(algorithmIdentifier = named))),
        ).isNull()
        assertThat(
            ImplementedPace.explicitDomain(
                info(CardAccessMother.paceDomainParameterInfo(algorithmIdentifier = implicit)),
            ),
        ).isNull()
        assertThat(
            ImplementedPace.explicitDomain(
                info(CardAccessMother.paceDomainParameterInfo(algorithmIdentifier = dhAlgorithm)),
            ),
        ).isNull()
        assertThat(
            ImplementedPace.explicitDomain(
                info(CardAccessMother.paceDomainParameterInfo(family = DH_GM, algorithmIdentifier = ecdh)),
            ),
        ).isNull()
        // The same parameters as ECDH, with Generic and with Chip Authentication Mapping (ICAO 9303-11, section 9.2.2).
        assertThat(
            ImplementedPace.explicitDomain(info(CardAccessMother.paceDomainParameterInfo(algorithmIdentifier = ecdh))),
        ).isSameAs(ImplementedPace.domain(13))
        assertThat(
            ImplementedPace.explicitDomain(
                info(
                    CardAccessMother.paceDomainParameterInfo(
                        family = CardAccessMother.ECDH_CAM,
                        algorithmIdentifier = ecdh,
                    ),
                ),
            ),
        ).isSameAs(ImplementedPace.domain(13))
    }

    private fun recognize(parameters: X9ECParameters): EcDomain? =
        ImplementedPace.explicitDomain(
            info(
                CardAccessMother.paceDomainParameterInfo(
                    algorithmIdentifier = AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, parameters),
                ),
            ),
        )

    private fun explicit(domain: EcDomain, cofactor: BigInteger? = BigInteger.ONE): ASN1Encodable =
        CardAccessMother.paceDomainParameterInfo(
            algorithmIdentifier =
                AlgorithmIdentifier(
                    X9ObjectIdentifiers.id_ecPublicKey,
                    X9ECParameters(
                        domain.parameters.curve,
                        X9ECPoint(domain.generator, false),
                        domain.parameters.n,
                        cofactor,
                    ),
                ),
        )

    private fun info(encodable: ASN1Encodable): PaceDomainParameterInfo =
        CardAccess.parse(CardAccessMother.cardAccess(encodable)).paceDomainParameterInfos.single()

    private companion object {
        /** `id-PACE-DH-GM` (TR-03110 Part 3, A.1.1.1). */
        val DH_GM: ASN1ObjectIdentifier = ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.1")
    }
}
