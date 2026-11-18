package com.xignsys.pace.internal.pace

import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.fixtures.CurveVectors
import com.xignsys.pace.fixtures.hex
import com.xignsys.pace.internal.crypto.AesKey
import com.xignsys.pace.internal.crypto.EcDomain
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.util.BigIntegers
import org.bouncycastle.util.test.FixedSecureRandom
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.math.BigInteger

/**
 * The implemented PACE variants: the standardized domain parameters with the Brainpool curves (TR-03110 Part 3, Table
 * 4; ICAO 9303-11, section 9.5.1) against RFC 5639 and RFC 7027, the AES key sizes, and the order of the default choice.
 */
class ImplementedPaceTest {
    @ParameterizedTest(name = "ID {0}: {1}")
    @MethodSource("curves")
    internal fun mapsTheStandardizedIdsToTheirCurves(
        id: Int,
        curve: CurveVectors.Curve,
        maxScalarLength: Int,
    ) {
        val domain = checkNotNull(ImplementedPace.domain(id))
        val parameters = domain.parameters

        assertThat(parameters.curve.field.characteristic).isEqualTo(number(curve.p))
        assertThat(parameters.curve.a.toBigInteger()).isEqualTo(number(curve.a))
        assertThat(parameters.curve.b.toBigInteger()).isEqualTo(number(curve.b))
        assertThat(domain.generator.affineXCoord.toBigInteger()).isEqualTo(number(curve.x))
        assertThat(domain.generator.affineYCoord.toBigInteger()).isEqualTo(number(curve.y))
        assertThat(parameters.n).isEqualTo(number(curve.q))
        assertThat(parameters.h).isEqualTo(BigInteger.ONE)
        // The longest nonce PACE accepts on the curve (see PaceTerminal): at most the length of the group order.
        assertThat(domain.maxScalarLength).isEqualTo(maxScalarLength)
    }

    @Test
    fun keepsBrainpoolP256r1AtId13() {
        // TR-03110 Part 3, Table 4: ID 13; its parameters are checked against RFC 5639, section 3.4, in EcDomainTest.
        assertThat(ImplementedPace.domain(13)?.parameters).isEqualTo(EcDomain.BRAINPOOL_P256R1.parameters)
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyAgreements")
    internal fun computesTheRfc7027SharedSecrets(id: Int, vector: CurveVectors.KeyAgreement) {
        // RFC 7027, Appendix A.2 and A.3, and RFC 5114, Appendix A.4 to A.8: key pairs from dA and dB, both sides obtain
        // x_Z.
        val domain = checkNotNull(ImplementedPace.domain(id))
        val a = domain.generateKeyPair(FixedSecureRandom(hex(vector.dA)))
        val b = domain.generateKeyPair(FixedSecureRandom(hex(vector.dB)))
        val publicA = (a.public as ECPublicKeyParameters).q
        val publicB = (b.public as ECPublicKeyParameters).q

        assertThat(publicA).isEqualTo(domain.decodePoint(hex("04 ${vector.xQA} ${vector.yQA}")))
        assertThat(publicB).isEqualTo(domain.decodePoint(hex("04 ${vector.xQB} ${vector.yQB}")))
        assertThat(domain.sharedSecret(a.private as ECPrivateKeyParameters, publicB)).isEqualTo(hex(vector.xZ))
        assertThat(domain.sharedSecret(b.private as ECPrivateKeyParameters, publicA)).isEqualTo(hex(vector.xZ))
    }

    @Test
    fun implementsGenericAndChipAuthenticationMappingWithAesOnTheBrainpoolIds() {
        // TR-03110 Part 3, A.1.1.1 and Table 4: every ECDH ID, 8 to 18; ICAO 9303-11, section 4.4.3.2. DH, Integrated Mapping
        // and 3DES are not implemented.
        val protocols =
            listOf(
                PaceProtocol.ECDH_GM_AES_CBC_CMAC_128,
                PaceProtocol.ECDH_GM_AES_CBC_CMAC_192,
                PaceProtocol.ECDH_GM_AES_CBC_CMAC_256,
                PaceProtocol.ECDH_CAM_AES_CBC_CMAC_128,
                PaceProtocol.ECDH_CAM_AES_CBC_CMAC_192,
                PaceProtocol.ECDH_CAM_AES_CBC_CMAC_256,
            )

        for (protocol in PaceProtocol.entries) {
            for (id in 0..31) {
                assertThat(ImplementedPace.supports(protocol, id))
                    .`as`("$protocol, ID $id")
                    .isEqualTo(protocol in protocols && id in 8..18)
            }
        }
    }

    @Test
    fun derivesKeysOfTheSizeOfTheProtocol() {
        // TR-03110 Part 3, A.1.1.1 and A.2.3.2.
        assertThat(ImplementedPace.keySize(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128)).isEqualTo(AesKey.Size.AES_128)
        assertThat(ImplementedPace.keySize(PaceProtocol.ECDH_GM_AES_CBC_CMAC_192)).isEqualTo(AesKey.Size.AES_192)
        assertThat(ImplementedPace.keySize(PaceProtocol.ECDH_GM_AES_CBC_CMAC_256)).isEqualTo(AesKey.Size.AES_256)
        assertThat(ImplementedPace.keySize(PaceProtocol.ECDH_CAM_AES_CBC_CMAC_128)).isEqualTo(AesKey.Size.AES_128)
        assertThat(ImplementedPace.keySize(PaceProtocol.ECDH_CAM_AES_CBC_CMAC_192)).isEqualTo(AesKey.Size.AES_192)
        assertThat(ImplementedPace.keySize(PaceProtocol.ECDH_CAM_AES_CBC_CMAC_256)).isEqualTo(AesKey.Size.AES_256)
    }

    @Test
    fun prefersTheBaselineThenGenericMappingThenLongerKeysThenLargerCurves() {
        // The baseline of BSI TR-03116-2 first; IDs 8 and 9 are deprecated (TR-03110 Part 3, note to Table 4) and never
        // chosen.
        val ids = listOf(18, 17, 16, 15, 14, 13, 12, 11, 10)
        val expected =
            listOf(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128 to 13) +
                listOf(
                    PaceProtocol.ECDH_GM_AES_CBC_CMAC_256,
                    PaceProtocol.ECDH_GM_AES_CBC_CMAC_192,
                    PaceProtocol.ECDH_GM_AES_CBC_CMAC_128,
                    PaceProtocol.ECDH_CAM_AES_CBC_CMAC_256,
                    PaceProtocol.ECDH_CAM_AES_CBC_CMAC_192,
                    PaceProtocol.ECDH_CAM_AES_CBC_CMAC_128,
                ).flatMap { protocol -> ids.map { protocol to it } }
                    .filter { it != (PaceProtocol.ECDH_GM_AES_CBC_CMAC_128 to 13) }

        assertThat(ImplementedPace.VARIANTS).containsExactlyElementsOf(expected)
    }

    private fun number(value: String): BigInteger = BigIntegers.fromUnsignedByteArray(hex(value))

    private companion object {
        @JvmStatic
        fun curves(): List<Arguments> =
            listOf(
                Arguments.of(8, CurveVectors.NIST_P192, 24),
                Arguments.of(9, CurveVectors.BRAINPOOL_P192R1, 24),
                Arguments.of(10, CurveVectors.NIST_P224, 28),
                Arguments.of(11, CurveVectors.BRAINPOOL_P224R1, 28),
                Arguments.of(12, CurveVectors.NIST_P256, 32),
                Arguments.of(14, CurveVectors.BRAINPOOL_P320R1, 40),
                Arguments.of(15, CurveVectors.NIST_P384, 48),
                Arguments.of(16, CurveVectors.BRAINPOOL_P384R1, 48),
                Arguments.of(17, CurveVectors.BRAINPOOL_P512R1, 64),
                Arguments.of(18, CurveVectors.NIST_P521, 66),
            )

        @JvmStatic
        fun keyAgreements(): List<Arguments> =
            listOf(
                Arguments.of(16, CurveVectors.RFC_7027_A2),
                Arguments.of(17, CurveVectors.RFC_7027_A3),
                Arguments.of(8, CurveVectors.RFC_5114_A4),
                Arguments.of(10, CurveVectors.RFC_5114_A5),
                Arguments.of(12, CurveVectors.RFC_5114_A6),
                Arguments.of(15, CurveVectors.RFC_5114_A7),
                Arguments.of(18, CurveVectors.RFC_5114_A8),
            )
    }
}
