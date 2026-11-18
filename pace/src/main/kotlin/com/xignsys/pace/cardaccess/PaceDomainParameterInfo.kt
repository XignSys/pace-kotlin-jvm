package com.xignsys.pace.cardaccess

/**
 * A `PACEDomainParameterInfo` of EF.CardAccess: one set of explicit domain parameters for PACE (TR-03110 Part 3,
 * A.1.1.1; ICAO 9303-11, section 9.2.2), kept as the encoded `AlgorithmIdentifier`.
 *
 * EF.CardAccess is not protected, so explicit domain parameters from it must not be used unless they are known to be
 * secure (TR-03110 Part 3, A.2.1.3; ICAO 9303-11, section 9.2.2): `Pace.establish` uses them only if they are one of
 * the library's standardized curves.
 *
 * Built by [CardAccess.parse] only. The array is copied out; immutable and thread-safe.
 */
public class PaceDomainParameterInfo internal constructor(
    /** The type of the domain parameters: mapping and key agreement. */
    public val family: PaceProtocol.Family,
    /**
     * The algorithm of the `AlgorithmIdentifier` in dotted form, `dhpublicnumber` for DH or `id-ecPublicKey` for ECDH
     * as TR-03110 Part 3, A.2.1.2, requires; not checked.
     */
    public val algorithm: String,
    domainParameter: ByteArray,
    /** The local domain parameter ID, which a [PaceInfo] refers to; `null` if the card leaves it out. */
    public val parameterId: Int?,
) {
    private val domainParameterBytes = domainParameter.copyOf()

    /** A copy of the DER encoding of the `AlgorithmIdentifier` `domainParameter` (TR-03110 Part 3, A.2.1). */
    public val domainParameter: ByteArray
        get() = domainParameterBytes.copyOf()

    override fun toString(): String =
        "PaceDomainParameterInfo($family, algorithm=$algorithm, parameterId=$parameterId, " +
            "domainParameterLength=${domainParameterBytes.size})"
}
