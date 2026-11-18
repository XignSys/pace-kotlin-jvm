package com.xignsys.pace.internal.crypto

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.math.ec.ECAlgorithms
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.BigIntegers
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Elliptic curve domain parameters `(p, a, b, G, n, h)` and the operations PACE with ECDH needs, all done by Bouncy
 * Castle: point decoding, key pair generation (`ECKeyPairGenerator`), the key agreement (`ECDHBasicAgreement`) and
 * multiplications with secret scalars (`ECAlgorithms.multiplySecret`, Bouncy Castle's multiplication for secrets,
 * which is written to run in constant time). The library relies on Bouncy Castle for this: on a JVM, where the
 * just-in-time compiler and the garbage collector decide what runs when, constant time is best effort and not
 * guaranteed.
 *
 * Only curves with cofactor 1, such as the Brainpool curves of RFC 5639 and the NIST curves of RFC 5114, are supported:
 * on them the key agreement ECKA of BSI TR-03111, section 4.3.1, is the plain product of the private key and the other
 * side's public key, and every point on the curve other than the point at infinity has the order `n`.
 *
 * Private keys are Bouncy Castle [ECPrivateKeyParameters]; their `BigInteger` value cannot be overwritten.
 */
internal class EcDomain private constructor(
    /** The domain parameters as Bouncy Castle uses them. */
    val parameters: ECDomainParameters,
) {
    init {
        require(parameters.h == BigInteger.ONE) { "Only curves with cofactor 1 are supported." }
    }

    /** The base point `G`. */
    val generator: ECPoint
        get() = parameters.g

    /**
     * The length in bytes of the longest secret scalar [multiplySecret] accepts, the length of the group order `n`: 32
     * for brainpoolP256r1. Bouncy Castle's multiplication for secrets refuses scalars with more bits than `n`.
     */
    val maxScalarLength: Int
        get() = (parameters.n.bitLength() + Byte.SIZE_BITS - 1) / Byte.SIZE_BITS

    /**
     * The same domain parameters with another base point, for example the mapped generator of the PACE Generic Mapping
     * (TR-03110 Part 3, A.3.4.1).
     *
     * @throws IllegalArgumentException if [newGenerator] is not a finite point on the curve.
     */
    fun withGenerator(newGenerator: ECPoint): EcDomain =
        EcDomain(ECDomainParameters(parameters.curve, newGenerator, parameters.n, parameters.h))

    /**
     * Decodes a point received from the card, or returns `null` if it is not valid.
     *
     * Only the uncompressed encoding is accepted (TR-03110 Part 3, D.2.1.2); Bouncy Castle checks the length, that both
     * coordinates are field elements and that the point lies on the curve (TR-03111, sections 3.2.1 and 4.3), which
     * validates an ephemeral public key as TR-03110 Part 3, A.2.2.1, requires.
     */
    fun decodePoint(encoded: ByteArray): ECPoint? {
        if (encoded.isEmpty() || encoded[0] != UNCOMPRESSED_POINT) {
            return null
        }

        return try {
            parameters.curve.decodePoint(encoded)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /**
     * Encodes a finite point in uncompressed encoding (TR-03111, section 3.2.1).
     *
     * @throws IllegalArgumentException if [point] is the point at infinity.
     */
    fun encodePoint(point: ECPoint): ByteArray {
        require(!point.isInfinity) { "The point at infinity has no uncompressed encoding." }

        return point.getEncoded(false)
    }

    /** Generates a key pair with Bouncy Castle's `ECKeyPairGenerator`: `d` from `{1, ..., n - 1}`, `P = [d]G`. */
    fun generateKeyPair(random: SecureRandom): AsymmetricCipherKeyPair {
        val generator = ECKeyPairGenerator()

        generator.init(ECKeyGenerationParameters(parameters, random))

        return generator.generateKeyPair()
    }

    /**
     * The shared secret point `[d]Q` of the own [privateKey] and the other side's [publicKey], computed with Bouncy
     * Castle's multiplication for secrets, or `null` if it is the point at infinity. PACE's Generic Mapping needs this
     * whole point (TR-03110 Part 3, A.3.4.1); where only the shared secret value is needed, use [sharedSecret].
     *
     * [publicKey] must come from [decodePoint], which checks that it lies on the curve.
     */
    fun sharedPoint(privateKey: ECPrivateKeyParameters, publicKey: ECPoint): ECPoint? {
        val point = ECAlgorithms.multiplySecret(publicKey, privateKey.d, parameters.n).normalize()

        return if (point.isInfinity) null else point
    }

    /**
     * The shared secret value `Z_AB = FE2OS(x)` of Bouncy Castle's `ECDHBasicAgreement`, as an octet string of exactly
     * `ceil(log256(p))` bytes (32 for brainpoolP256r1), leading zero bytes included (TR-03111, sections 3.1.3 and
     * 4.3.1; TR-03110 Part 3, A.2.3), or `null` if the agreement gives the point at infinity.
     *
     * [publicKey] must come from [decodePoint], which checks that it lies on the curve.
     */
    fun sharedSecret(privateKey: ECPrivateKeyParameters, publicKey: ECPoint): ByteArray? {
        val agreement = ECDHBasicAgreement()

        agreement.init(privateKey)

        val x =
            try {
                agreement.calculateAgreement(ECPublicKeyParameters(publicKey, privateKey.parameters))
            } catch (_: IllegalStateException) {
                return null
            }

        return BigIntegers.asUnsignedByteArray(agreement.fieldSize, x)
    }

    /**
     * The product `[k]P` of [point] and the secret scalar [scalar], an unsigned big-endian integer of at most
     * [maxScalarLength] bytes, for example the PACE nonce, computed with Bouncy Castle's multiplication for secrets,
     * or `null` if it is the point at infinity. A scalar of `n` or more gives the same point as the scalar modulo `n`.
     *
     * @throws IllegalArgumentException if [scalar] is longer than [maxScalarLength] bytes.
     */
    fun multiplySecret(point: ECPoint, scalar: ByteArray): ECPoint? {
        require(scalar.size <= maxScalarLength) { "A secret scalar has at most $maxScalarLength bytes." }

        val k = BigIntegers.fromUnsignedByteArray(scalar)
        val product = ECAlgorithms.multiplySecret(point, k, parameters.n).normalize()

        return if (product.isInfinity) null else product
    }

    /** The sum of [a] and [b], or `null` if it is the point at infinity. */
    fun add(a: ECPoint, b: ECPoint): ECPoint? {
        val sum = a.add(b).normalize()

        return if (sum.isInfinity) null else sum
    }

    override fun toString(): String = "EcDomain(fieldSize=${parameters.curve.fieldSize})"

    companion object {
        /**
         * brainpoolP256r1 (RFC 5639, section 3.4), the standardized domain parameters with ID 13 of TR-03110 Part 3,
         * Table 4.
         */
        val BRAINPOOL_P256R1: EcDomain = brainpool(TeleTrusTObjectIdentifiers.brainpoolP256r1)

        /**
         * The Brainpool curve [oid] of RFC 5639, section 3, from Bouncy Castle's `TeleTrusTNamedCurves`.
         *
         * @throws IllegalStateException if Bouncy Castle has no curve [oid].
         */
        fun brainpool(oid: ASN1ObjectIdentifier): EcDomain =
            EcDomain(ECDomainParameters(checkNotNull(TeleTrusTNamedCurves.getByOID(oid)) { "Unknown curve $oid." }))

        /**
         * The NIST curve [oid] of RFC 5114, sections 2.4 to 2.8 (FIPS 186-4), from Bouncy Castle's `SECNamedCurves`.
         *
         * @throws IllegalStateException if Bouncy Castle has no curve [oid].
         */
        fun nist(oid: ASN1ObjectIdentifier): EcDomain =
            EcDomain(ECDomainParameters(checkNotNull(SECNamedCurves.getByOID(oid)) { "Unknown curve $oid." }))

        /** First byte of a point in uncompressed encoding (TR-03111, section 3.2.1). */
        const val UNCOMPRESSED_POINT: Byte = 0x04
    }
}
