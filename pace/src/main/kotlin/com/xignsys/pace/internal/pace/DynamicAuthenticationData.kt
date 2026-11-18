package com.xignsys.pace.internal.pace

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.BERTags
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import java.io.IOException

/**
 * The dynamic authentication data `7C` of General Authenticate: a constructed application object that holds
 * context-specific primitive data objects such as `80` to `88` (TR-03110 Part 3, B.1 and B.11.1).
 */
internal object DynamicAuthenticationData {
    /** Encrypted nonce, in the response to step 1. */
    const val ENCRYPTED_NONCE: Int = 0x00

    /** The terminal's mapping data, in step 2. */
    const val TERMINAL_MAPPING_DATA: Int = 0x01

    /** The chip's mapping data, in the response to step 2. */
    const val CHIP_MAPPING_DATA: Int = 0x02

    /** The terminal's ephemeral public key, in step 3. */
    const val TERMINAL_PUBLIC_KEY: Int = 0x03

    /** The chip's ephemeral public key, in the response to step 3. */
    const val CHIP_PUBLIC_KEY: Int = 0x04

    /** The terminal's authentication token, in step 4. */
    const val TERMINAL_TOKEN: Int = 0x05

    /** The chip's authentication token, in the response to step 4. */
    const val CHIP_TOKEN: Int = 0x06

    /** The most recent Certification Authority Reference, in the response to step 4 (conditional). */
    const val CA_REFERENCE: Int = 0x07

    /** The previous Certification Authority Reference, in the response to step 4 (conditional). */
    const val PREVIOUS_CA_REFERENCE: Int = 0x08

    /**
     * The Encrypted Chip Authentication Data, in the response to step 4 of PACE with Chip Authentication Mapping only
     * (ICAO 9303-11, section 4.4.4, Table 4).
     */
    const val ENCRYPTED_CHIP_AUTHENTICATION_DATA: Int = 0x0A

    /** Application tag number of `7C`. */
    private const val TAG_NUMBER = 0x1C

    /** Encodes `7C` with the data objects [objects], as pairs of context-specific tag number and value, in order. */
    fun encode(vararg objects: Pair<Int, ByteArray>): ByteArray {
        val elements: Array<ASN1Encodable> =
            Array(objects.size) { DERTaggedObject(false, objects[it].first, DEROctetString(objects[it].second)) }

        return DERTaggedObject(false, BERTags.APPLICATION, TAG_NUMBER, DERSequence(elements)).encoded
    }

    /**
     * Decodes `7C` and returns its data objects in order, as pairs of context-specific tag number and value, or `null`
     * if [encoded] is not one `7C` without trailing bytes that holds only context-specific primitive data objects, all
     * in DER.
     */
    fun decode(encoded: ByteArray): List<Pair<Int, ByteArray>>? {
        val objects =
            try {
                decodeObjects(encoded)
            } catch (_: IOException) {
                null
            } catch (_: RuntimeException) {
                // Bouncy Castle reports malformed encodings with various runtime exceptions; none is passed on.
                null
            } ?: return null

        // Bouncy Castle also accepts constructed and other non-DER forms of the data objects. Encoding the result again
        // gives the same bytes only for the DER form of exactly these objects, so anything else is refused.
        return if (encode(*objects.toTypedArray()).contentEquals(encoded)) objects else null
    }

    private fun decodeObjects(encoded: ByteArray): List<Pair<Int, ByteArray>>? {
        val tagged = ASN1Primitive.fromByteArray(encoded) as? ASN1TaggedObject ?: return null

        if (!tagged.hasTag(BERTags.APPLICATION, TAG_NUMBER)) {
            return null
        }

        val content = tagged.getBaseUniversal(false, BERTags.SEQUENCE) as? ASN1Sequence ?: return null

        return content.map { element ->
            val dataObject = element as? ASN1TaggedObject ?: return null

            if (dataObject.tagClass != BERTags.CONTEXT_SPECIFIC) {
                return null
            }

            dataObject.tagNo to ASN1OctetString.getInstance(dataObject, false).octets
        }
    }
}
