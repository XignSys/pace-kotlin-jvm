package com.xignsys.pace.internal.crypto

import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.BigIntegers
import org.bouncycastle.util.test.FixedSecureRandom
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.math.BigInteger

/**
 * brainpoolP256r1 and the elliptic curve operations of BSI TR-03111 that PACE with ECDH needs. Fixed private keys of the
 * published examples are fed to Bouncy Castle's key pair generator through its `FixedSecureRandom`.
 */
class EcDomainTest {
    private val domain = EcDomain.BRAINPOOL_P256R1

    @Test
    fun hasTheRfc5639DomainParameters() {
        val parameters = domain.parameters

        // RFC 5639, section 3.4: brainpoolP256r1.
        assertThat(parameters.curve.field.characteristic).isEqualTo(number(RFC_5639_P))
        assertThat(parameters.curve.a.toBigInteger()).isEqualTo(number(RFC_5639_A))
        assertThat(parameters.curve.b.toBigInteger()).isEqualTo(number(RFC_5639_B))
        assertThat(domain.generator.affineXCoord.toBigInteger()).isEqualTo(number(RFC_5639_X))
        assertThat(domain.generator.affineYCoord.toBigInteger()).isEqualTo(number(RFC_5639_Y))
        assertThat(parameters.n).isEqualTo(number(RFC_5639_Q))
        assertThat(parameters.h).isEqualTo(BigInteger.ONE)
    }

    @Test
    fun encodesPointsAndSharedSecretsWithTheLengthsOfA256BitCurve() {
        // TR-03111, 3.1.3 and 3.2.1: l = ceil(log256 p) = 32; an uncompressed point is 04 || X || Y, 65 bytes.
        val pair = keyPair(domain, RFC_7027_D_A)

        assertThat(domain.encodePoint(publicKey(pair))).hasSize(65).startsWith(EcDomain.UNCOMPRESSED_POINT)
        assertThat(domain.sharedSecret(privateKey(pair), point(RFC_7027_X_QB, RFC_7027_Y_QB))).hasSize(32)
    }

    @Test
    fun generatesTheRfc7027KeyPairsFromTheirPrivateKeys() {
        // RFC 7027, Appendix A.1: the public keys of A and B.
        assertThat(publicKey(keyPair(domain, RFC_7027_D_A))).isEqualTo(point(RFC_7027_X_QA, RFC_7027_Y_QA))
        assertThat(publicKey(keyPair(domain, RFC_7027_D_B))).isEqualTo(point(RFC_7027_X_QB, RFC_7027_Y_QB))
    }

    @Test
    fun computesTheRfc7027SharedSecretOnBothSides() {
        // RFC 7027, Appendix A.1: both sides obtain the shared secret x_Z.
        val a = privateKey(keyPair(domain, RFC_7027_D_A))
        val b = privateKey(keyPair(domain, RFC_7027_D_B))

        assertThat(domain.sharedSecret(a, point(RFC_7027_X_QB, RFC_7027_Y_QB))).isEqualTo(hex(RFC_7027_X_Z))
        assertThat(domain.sharedSecret(b, point(RFC_7027_X_QA, RFC_7027_Y_QA))).isEqualTo(hex(RFC_7027_X_Z))
        assertThat(domain.sharedPoint(a, point(RFC_7027_X_QB, RFC_7027_Y_QB))?.affineXCoord?.encoded)
            .isEqualTo(hex(RFC_7027_X_Z))
    }

    @Test
    fun reproducesTheEllipticCurveStepsOfTheIcaoPaceExample() {
        // ICAO 9303-11, Appendix G.1 (PACE with ECDH and Generic Mapping on brainpoolP256r1).
        val mapping = keyPair(domain, "7F4EF07B 9EA82FD7 8AD689B3 8D0BC78C F21F249D 953BC46F 4C6E1925 9C010F99")
        val chipMappingKey =
            point(
                "824FBA91 C9CBE26B EF53A0EB E7342A3B F178CEA9 F45DE0B7 0AA60165 1FBA3F57",
                "30D8C879 AAA9C9F7 3991E61B 58F4D52E B87A0A0C 709A49DC 63719363 CCD13C54",
            )

        assertThat(publicKey(mapping)).isEqualTo(
            point(
                "7ACF3EFC 982EC455 65A4B155 129EFBC7 4650DCBF A6362D89 6FC70262 E0C2CC5E",
                "544552DC B6725218 799115B5 5C9BAA6D 9F6BC3A9 618E70C2 5AF71777 A9C4922D",
            ),
        )

        // The shared secret point H of the anonymous key agreement, the full point.
        val h = checkNotNull(domain.sharedPoint(privateKey(mapping), chipMappingKey))

        assertThat(h).isEqualTo(
            point(
                "60332EF2 450B5D24 7EF6D386 8397D398 852ED6E8 CAF6FFEE F6BF85CA 57057FD5",
                "0840CA74 15BAF3E4 3BD414D3 5AA4608B 93A2CAF3 A4E3EA4E 82C9C13D 03EB7181",
            ),
        )

        // The mapped generator s * G + H (TR-03110 Part 3, A.3.4.1) with the decrypted nonce s.
        val sTimesG = checkNotNull(domain.multiplySecret(domain.generator, hex("3F00C4D3 9D153F2B 2A214A07 8D899B22")))
        val mappedGenerator = checkNotNull(domain.add(sTimesG, h))

        assertThat(mappedGenerator).isEqualTo(
            point(
                "8CED63C9 1426D4F0 EB1435E7 CB1D74A4 6723A0AF 21C89634 F65A9AE8 7A9265E2",
                "8C879506 743F8611 AC33645C 5B985C80 B5F09A0B 83407C1B 6A4D857A E76FE522",
            ),
        )

        // The key agreement on the ephemeral domain parameters and its shared secret value.
        val ephemeral = domain.withGenerator(mappedGenerator)
        val agreement = keyPair(ephemeral, "A73FB703 AC1436A1 8E0CFA5A BB3F7BEC 7A070E7A 6788486B EE230C4A 22762595")
        val chipAgreementKey =
            point(
                "9E880F84 2905B8B3 181F7AF7 CAA9F0EF B743847F 44A306D2 D28C1D9E C65DF6DB",
                "7764B222 77A2EDDC 3C265A9F 018F9CB8 52E111B7 68B32690 4B59A019 3776F094",
            )

        assertThat(publicKey(agreement)).isEqualTo(
            point(
                "2DB7A64C 0355044E C9DF1905 14C625CB A2CEA487 54887122 F3A5EF0D 5EDD301C",
                "3556F3B3 B186DF10 B857B58F 6A7EB80F 20BA5DC7 BE1D43D9 BF850149 FBB36462",
            ),
        )
        assertThat(ephemeral.sharedSecret(privateKey(agreement), chipAgreementKey))
            .isEqualTo(hex("28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925"))
    }

    @Test
    fun theSharedSecretKeepsLeadingZeroBytes() {
        // TR-03111, 3.1.3: FE2OS always gives l bytes. Find a scalar k whose product kG has an x-coordinate below 2^248.
        val k =
            generateSequence(BigInteger.ONE) { it.add(BigInteger.ONE) }
                .first {
                    domain.generator
                        .multiply(it)
                        .normalize()
                        .affineXCoord
                        .toBigInteger()
                        .bitLength() <= 248
                }
        val secret = checkNotNull(domain.sharedSecret(ECPrivateKeyParameters(k, domain.parameters), domain.generator))

        assertThat(secret).hasSize(32)
        assertThat(secret[0]).isZero()
    }

    @Test
    fun decodesAndEncodesUncompressedPoints() {
        val encoded = hex("04 $RFC_7027_X_QA $RFC_7027_Y_QA")
        val decoded = checkNotNull(domain.decodePoint(encoded))

        assertThat(domain.encodePoint(decoded)).isEqualTo(encoded)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            // the point at infinity (TR-03111, 3.2)
            "00",
            // compressed encodings (TR-03110 Part 3, D.2.1.2 requires the uncompressed format)
            "02 $RFC_7027_X_QA",
            "03 $RFC_7027_X_QA",
            // another first byte
            "06 $RFC_7027_X_QA $RFC_7027_Y_QA",
            // wrong lengths
            "04 $RFC_7027_X_QA",
            "04 $RFC_7027_X_QA $RFC_7027_Y_QA 00",
            // not on the curve (last byte of y changed)
            "04 $RFC_7027_X_QA 8AB4846F 11CACCB7 3CE49CBD D120F5A9 00A69FD3 2C272223 F789EF10 EB089BDD",
            // coordinate not below p
            "04 $RFC_5639_P $RFC_7027_Y_QA",
            "",
        ],
    )
    fun rejectsInvalidPoints(encoded: String) {
        assertThat(domain.decodePoint(hex(encoded))).isNull()
    }

    @Test
    fun doesNotEncodeThePointAtInfinity() {
        assertThatIllegalArgumentException().isThrownBy { domain.encodePoint(domain.parameters.curve.infinity) }
    }

    @Test
    fun drawsPrivateKeysFromTheRangeOneToNMinusOne() {
        // TR-03111, 4.1.3: d is drawn from {1, ..., n - 1}; the generator skips 0 and n and draws again.
        val bytes = ByteArray(32) + BigIntegers.asUnsignedByteArray(32, domain.parameters.n) + hex(RFC_7027_D_A)
        val pair = domain.generateKeyPair(FixedSecureRandom(bytes))

        assertThat(privateKey(pair).d).isEqualTo(number(RFC_7027_D_A))
    }

    @Test
    fun reportsThePointAtInfinityAsNull() {
        val g = domain.generator

        assertThat(domain.add(g, g.negate())).isNull()
        assertThat(domain.multiplySecret(g, BigIntegers.asUnsignedByteArray(32, domain.parameters.n))).isNull()
    }

    @Test
    fun reducesScalarsModuloTheGroupOrder() {
        // A 32-byte PACE nonce s can be n or larger; [s]G is the same point as [s mod n]G.
        val g = domain.generator
        val nPlusTwo = domain.parameters.n.add(BigInteger.TWO)

        assertThat(
            domain.multiplySecret(g, BigIntegers.asUnsignedByteArray(32, nPlusTwo)),
        ).isEqualTo(g.twice().normalize())
    }

    @Test
    fun refusesSecretScalarsLongerThanTheGroupOrder() {
        // Bouncy Castle's constant-time multiplier refuses scalars with more bits than n; a 33-byte scalar is refused
        // before it reaches Bouncy Castle, a 32-byte one of 256 bits is accepted.
        val g = domain.generator

        assertThat(domain.maxScalarLength).isEqualTo(32)
        assertThat(domain.multiplySecret(g, ByteArray(32) { -1 })).isNotNull()
        assertThatIllegalArgumentException().isThrownBy { domain.multiplySecret(g, ByteArray(33) { 1 }) }
    }

    @Test
    fun rejectsTheInfiniteGenerator() {
        assertThatIllegalArgumentException().isThrownBy { domain.withGenerator(domain.parameters.curve.infinity) }
    }

    private fun keyPair(on: EcDomain, privateKey: String): AsymmetricCipherKeyPair =
        on.generateKeyPair(FixedSecureRandom(hex(privateKey)))

    private fun publicKey(pair: AsymmetricCipherKeyPair): ECPoint = (pair.public as ECPublicKeyParameters).q

    private fun privateKey(pair: AsymmetricCipherKeyPair): ECPrivateKeyParameters =
        pair.private as ECPrivateKeyParameters

    private fun point(x: String, y: String): ECPoint = checkNotNull(domain.decodePoint(hex("04 $x $y")))

    private fun number(value: String): BigInteger = BigIntegers.fromUnsignedByteArray(hex(value))

    private companion object {
        // RFC 5639, section 3.4: brainpoolP256r1.
        const val RFC_5639_P = "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"
        const val RFC_5639_A = "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"
        const val RFC_5639_B = "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"
        const val RFC_5639_X = "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"
        const val RFC_5639_Y = "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"
        const val RFC_5639_Q = "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"

        // RFC 7027, Appendix A.1: ECDH on brainpoolP256r1.
        const val RFC_7027_D_A = "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D"
        const val RFC_7027_X_QA = "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5"
        const val RFC_7027_Y_QA = "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC"
        const val RFC_7027_D_B = "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3"
        const val RFC_7027_X_QB = "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B"
        const val RFC_7027_Y_QB = "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A"
        const val RFC_7027_X_Z = "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B"
    }
}
