package com.xignsys.pace.internal.pace

import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.BERTags
import java.io.IOException

/** The certificate extensions `65` that MSE:Set AT carries after the CHAT (TR-03110 Part 3, B.1, B.14.1 and C.3). */
internal object CertificateExtensions {
    /** Application tag number of `65`, the certificate extensions (C.3, Table 27). */
    private const val TAG_NUMBER = 0x05

    /** Application tag number of `73`, a discretionary data template (C.3, Table 27). */
    private const val TEMPLATE_TAG_NUMBER = 0x13

    /** A template holds an object identifier and at least one data object with the extension (C.3). */
    private const val MIN_TEMPLATE_ELEMENTS = 2

    /**
     * Whether [encoded] is exactly one DER-encoded data object `65` with one or more discretionary data templates `73`,
     * each an object identifier followed by at least one data object (C.3; C.3.1 for Authorization Extensions), and
     * nothing before or after it. The data objects after the object identifier are not checked.
     */
    fun isValid(encoded: ByteArray): Boolean =
        try {
            val primitive = ASN1Primitive.fromByteArray(encoded)

            primitive is ASN1TaggedObject &&
                primitive.hasTag(BERTags.APPLICATION, TAG_NUMBER) &&
                primitive.getEncoded(ASN1Encoding.DER).contentEquals(encoded) &&
                contents(primitive).let { templates -> templates.size() > 0 && templates.all(::isTemplate) }
        } catch (_: IOException) {
            false
        } catch (_: RuntimeException) {
            // Bouncy Castle reports malformed encodings with various runtime exceptions; none is passed on.
            false
        }

    private fun isTemplate(element: Any): Boolean {
        if (element !is ASN1TaggedObject || !element.hasTag(BERTags.APPLICATION, TEMPLATE_TAG_NUMBER)) {
            return false
        }

        val elements = contents(element)

        return elements.size() >= MIN_TEMPLATE_ELEMENTS && elements.getObjectAt(0) is ASN1ObjectIdentifier
    }

    /** The data objects inside the constructed [tagged]; throws if it is primitive. */
    private fun contents(tagged: ASN1TaggedObject): ASN1Sequence =
        ASN1Sequence.getInstance(tagged.getBaseUniversal(false, BERTags.SEQUENCE))
}
