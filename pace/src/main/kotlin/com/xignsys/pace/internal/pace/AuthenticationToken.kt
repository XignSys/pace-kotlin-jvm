package com.xignsys.pace.internal.pace

import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.internal.crypto.AesCmac
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.BERTags
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject

/**
 * The PACE authentication token: the MAC with `K_MAC` over the public key data object `7F49` that holds the protocol's
 * object identifier and an ephemeral public point `86` (TR-03110 Part 3, A.2.4 and D.3.4; ICAO 9303-11, section
 * 4.4.3.4).
 */
internal object AuthenticationToken {
    /** Application tag number of the public key data object `7F49`. */
    private const val PUBLIC_KEY_TAG_NUMBER = 0x49

    /** Context-specific tag number of the public point `86` (TR-03110 Part 3, D.3.4). */
    private const val PUBLIC_POINT_TAG_NUMBER = 0x06

    /** The token over [publicPoint], an uncompressed point, for [protocol]. */
    fun compute(
        mac: AesCmac,
        protocol: PaceProtocol,
        publicPoint: ByteArray,
    ): ByteArray = mac.mac(publicKeyDataObject(protocol, publicPoint))

    /** Whether [token] is the token over [publicPoint] for [protocol], compared in constant time. */
    fun verify(
        mac: AesCmac,
        token: ByteArray,
        protocol: PaceProtocol,
        publicPoint: ByteArray,
    ): Boolean = mac.verify(token, publicKeyDataObject(protocol, publicPoint))

    /** The DER encoding of `7F49 { 06 protocol, 86 publicPoint }`. */
    fun publicKeyDataObject(protocol: PaceProtocol, publicPoint: ByteArray): ByteArray {
        val point = DERTaggedObject(false, PUBLIC_POINT_TAG_NUMBER, DEROctetString(publicPoint))
        val content = DERSequence(arrayOf<ASN1Encodable>(ASN1ObjectIdentifier(protocol.oid), point))

        return DERTaggedObject(false, BERTags.APPLICATION, PUBLIC_KEY_TAG_NUMBER, content).encoded
    }
}
