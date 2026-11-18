package com.xignsys.pace.fixtures

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DLSet

/**
 * Synthetic EF.CardAccess contents, built with Bouncy Castle's ASN.1 classes. The OIDs are written out here, not taken
 * from the production constants, so that the tests also check those.
 */
internal object CardAccessMother {
    /** `id-PACE-ECDH-GM-AES-CBC-CMAC-128` (TR-03110 Part 3, A.1.1.1). */
    val ECDH_GM_AES_128: ASN1ObjectIdentifier = ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.2.2")

    /** `id-PACE-ECDH-IM-AES-CBC-CMAC-256` (TR-03110 Part 3, A.1.1.1). */
    val ECDH_IM_AES_256: ASN1ObjectIdentifier = ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.4.4")

    /** `id-PACE-ECDH-GM` (TR-03110 Part 3, A.1.1.1), the type of a `PACEDomainParameterInfo`. */
    val ECDH_GM: ASN1ObjectIdentifier = ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.2")

    /** `id-PACE-ECDH-CAM` (ICAO 9303-11, section 9.2.3), allowed as the type of a `PACEDomainParameterInfo` there. */
    val ECDH_CAM: ASN1ObjectIdentifier = ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4.6")

    /** `id-PACE` itself (TR-03110 Part 3, A.1.1.1), neither a protocol nor a type. */
    val PACE: ASN1ObjectIdentifier = ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.4")

    /** `id-TA` (TR-03110 Part 3, A.1.1.3), a SecurityInfo that is not about PACE. */
    val TA: ASN1ObjectIdentifier = ASN1ObjectIdentifier("0.4.0.127.0.7.2.2.2")

    /** `id-ecPublicKey` (TR-03110 Part 3, A.2.1.2), the algorithm of explicit EC domain parameters. */
    val EC_PUBLIC_KEY: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.2.840.10045.2.1")

    /** A `PACEInfo`; [parameterId] `null` leaves the optional field out. */
    fun paceInfo(
        protocol: ASN1ObjectIdentifier = ECDH_GM_AES_128,
        version: Long = 2,
        parameterId: Long? = 13,
    ): ASN1Encodable = sequence(protocol, ASN1Integer(version), *optional(parameterId))

    /**
     * A `PACEDomainParameterInfo` of [family] with [algorithmIdentifier], by default the brainpoolP256r1 parameters of
     * ICAO 9303-11, Appendix G.1; [parameterId] `null` leaves the optional field out.
     */
    fun paceDomainParameterInfo(
        parameterId: Long? = 32,
        family: ASN1ObjectIdentifier = ECDH_GM,
        algorithmIdentifier: ASN1Encodable =
            ASN1Primitive.fromByteArray(
                IcaoExamples.BRAINPOOL_P256R1_ALGORITHM_IDENTIFIER,
            ),
    ): ASN1Encodable = sequence(family, algorithmIdentifier, *optional(parameterId))

    /** A `TerminalAuthenticationInfo` with version 2. */
    fun terminalAuthenticationInfo(): ASN1Encodable = sequence(TA, ASN1Integer(2))

    /** A SEQUENCE of [elements]. */
    fun sequence(vararg elements: ASN1Encodable): ASN1Encodable = DERSequence(elements)

    /** The encoding of `SecurityInfos`, a SET of [securityInfos] in the given order. */
    fun cardAccess(vararg securityInfos: ASN1Encodable): ByteArray = DLSet(securityInfos).encoded

    /** The SET of the encoded [securityInfos], each given as its bytes. */
    fun cardAccess(vararg securityInfos: ByteArray): ByteArray =
        cardAccess(*securityInfos.map { ASN1Primitive.fromByteArray(it) }.toTypedArray())

    private fun optional(value: Long?): Array<ASN1Encodable> =
        listOfNotNull(value?.let { ASN1Integer(it) }).toTypedArray()
}
