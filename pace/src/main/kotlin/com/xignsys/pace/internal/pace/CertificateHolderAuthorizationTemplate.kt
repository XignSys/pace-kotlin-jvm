package com.xignsys.pace.internal.pace

import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.BERTags
import java.io.IOException

/** The Certificate Holder Authorization Template `7F4C` that MSE:Set AT carries (TR-03110 Part 3, B.14.1 and C.1.5). */
internal object CertificateHolderAuthorizationTemplate {
    /** Application tag number of `7F4C`. */
    private const val TAG_NUMBER = 0x4C

    /**
     * Whether [encoded] is exactly one DER-encoded data object with the tag `7F4C`, nothing before or after it. Its
     * content, an object identifier and the discretionary data `53` (C.1.5), is not checked.
     */
    fun isOneDataObject(encoded: ByteArray): Boolean =
        try {
            val primitive = ASN1Primitive.fromByteArray(encoded)

            primitive is ASN1TaggedObject &&
                primitive.hasTag(BERTags.APPLICATION, TAG_NUMBER) &&
                primitive.getEncoded(ASN1Encoding.DER).contentEquals(encoded)
        } catch (_: IOException) {
            false
        } catch (_: RuntimeException) {
            // Bouncy Castle reports malformed encodings with various runtime exceptions; none is passed on.
            false
        }
}
