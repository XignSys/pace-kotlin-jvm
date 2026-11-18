package com.xignsys.pace.internal.pace

import com.xignsys.pace.cardaccess.PaceDomainParameterInfo
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.internal.crypto.EcDomain
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers

/**
 * Explicit domain parameters of a `PACEDomainParameterInfo` (TR-03110 Part 3, A.2.1.2; ICAO 9303-11, sections 9.2.2 and
 * 9.5.2). EF.CardAccess is not protected, and a terminal MUST NOT use explicit domain parameters unless it knows them
 * to be secure (TR-03110 Part 3, A.2.1.3): the library knows only its standardized curves to be secure, so it accepts
 * explicit parameters only if they are one of them.
 */
internal object ExplicitDomainParameters {
    /**
     * The standardized domain parameters among [known] that [info] describes, or `null`: [info] must be ECDH
     * (`PACEDomainParameterInfo.protocol` names the type of the parameters, ICAO 9303-11, section 9.2.2), its algorithm
     * `id-ecPublicKey` with explicit `ECParameters` (named curves MUST NOT be used, section 9.5.2), the generator in
     * uncompressed encoding (only uncompressed points SHALL be used, ICAO 9303-11, sections 4.4.3.2 and 9.4.1), and the
     * prime, the coefficients `a` and `b`, the generator and the order must be those of one of [known]; a cofactor,
     * which `ECParameters` may leave out, must then be 1. The seed is not compared. Elements after the cofactor, which
     * the extension marker of `ECParameters` allows (TR-03111, section 5.1.1), are ignored. PACE then runs on the
     * library's copy.
     *
     * The parameters come from the card and may be anything, for example a generator that is not on its curve. Bouncy
     * Castle reports such parameters with runtime exceptions, some only when a value is first read; none is passed
     * on.
     */
    fun recognize(info: PaceDomainParameterInfo, known: Collection<EcDomain>): EcDomain? {
        if (info.family.keyAgreement != PaceProtocol.KeyAgreement.ECDH) {
            return null
        }

        return try {
            val parameters = explicitParameters(info.domainParameter) ?: return null

            known.firstOrNull { domain ->
                val expected = domain.parameters

                parameters.curve == expected.curve &&
                    parameters.g.normalize() == expected.g.normalize() &&
                    parameters.n == expected.n &&
                    (parameters.h == null || parameters.h == expected.h)
            }
        } catch (_: RuntimeException) {
            null
        }
    }

    /**
     * The explicit `ECParameters` of the `AlgorithmIdentifier` [encoded] with an uncompressed generator, or `null` for
     * another algorithm or encoding of the generator; throws a runtime exception of Bouncy Castle for malformed
     * parameters.
     */
    private fun explicitParameters(encoded: ByteArray): X9ECParameters? {
        val identifier = AlgorithmIdentifier.getInstance(encoded)
        val parameters = identifier.parameters

        return if (identifier.algorithm == X9ObjectIdentifiers.id_ecPublicKey && parameters is ASN1Sequence) {
            X9ECParameters.getInstance(parameters).takeIf {
                it.baseEntry.pointEncoding.firstOrNull() == EcDomain.UNCOMPRESSED_POINT
            }
        } else {
            null
        }
    }
}
