package com.xignsys.pace.cardaccess

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import java.io.IOException

/**
 * The PACE part of EF.CardAccess: the `PACEInfo`s and `PACEDomainParameterInfo`s of its `SecurityInfos` (TR-03110
 * Part 3, A.1.1.1 and A.1.2.1; ICAO 9303-11, sections 9.2 and 9.2.11), and the file as it was read.
 *
 * EF.CardAccess is read without Secure Messaging and is not protected; it only tells which PACE the card offers. An
 * attacker between the terminal and the card can change it, for example to make the terminal choose a weaker PACE. The
 * caller must therefore compare it after PACE with the protected copy: with the `SecurityInfos` of EF.CardSecurity
 * (TR-03110 Part 2, section 2.3.4) or with EF.DG14 or EF.CardSecurity of an eMRTD (ICAO 9303-11, section 4.2), once
 * that file has been verified by Passive Authentication. [encoded] is the file as read, for that comparison; the
 * library does not read or verify the protected files.
 *
 * The array is copied in and out; [toString] shows the counts only. Immutable and thread-safe.
 */
public class CardAccess private constructor(
    encoded: ByteArray,
    /** Every `PACEInfo`, in file order; empty if the file offers no PACE. */
    public val paceInfos: List<PaceInfo>,
    /** Every `PACEDomainParameterInfo`, in file order. */
    public val paceDomainParameterInfos: List<PaceDomainParameterInfo>,
) {
    private val encodedBytes = encoded.copyOf()

    /** A copy of the file exactly as it was given to [parse]. */
    public val encoded: ByteArray
        get() = encodedBytes.copyOf()

    /** The `PACEInfo` with [protocol] and [parameterId], or `null` if the card offers no such PACE. */
    public fun paceInfo(protocol: PaceProtocol, parameterId: Int): PaceInfo? =
        paceInfos.firstOrNull { it.protocol == protocol && it.parameterId == parameterId }

    override fun toString(): String =
        "CardAccess(paceInfos=${paceInfos.size}, paceDomainParameterInfos=${paceDomainParameterInfos.size})"

    /** Parser of EF.CardAccess. */
    public companion object {
        private const val PROTOCOL_INDEX = 0
        private const val REQUIRED_DATA_INDEX = 1
        private const val OPTIONAL_DATA_INDEX = 2
        private const val MIN_SECURITY_INFO_SIZE = 2
        private const val MAX_SECURITY_INFO_SIZE = 3
        private const val MIN_ALGORITHM_IDENTIFIER_SIZE = 1
        private const val MAX_ALGORITHM_IDENTIFIER_SIZE = 2

        /**
         * Decodes the content of EF.CardAccess, [encoded]; BER and DER are accepted.
         *
         * The file must be one `SecurityInfos` SET without trailing bytes, and every `SecurityInfo` a SEQUENCE of a
         * protocol OID, the required data and optional data (TR-03110 Part 3, A.1). `SecurityInfo`s of other protocols
         * are skipped (ICAO 9303-11, section 9.2). Every `PACEInfo` and `PACEDomainParameterInfo` is checked against
         * its ASN.1 definition, with a non-negative 32-bit version and parameter ID. The PACE entries must not be
         * ambiguous, because MSE:Set AT names PACE by its protocol and domain parameter ID (TR-03110 Part 3, B.14.1):
         * - no two `PACEInfo`s with the same protocol and parameter ID;
         * - with more than one `PACEDomainParameterInfo`, each has a parameter ID (TR-03110 Part 3, A.1.1.1; ICAO
         *   9303-11, section 9.2.2), and no two have the same;
         * - no `PACEDomainParameterInfo` uses an ID reserved for standardized domain parameters (TR-03110 Part 3,
         *   A.2.1).
         *
         * Entries that are only unusable are kept, so that the caller can tell what the card offers: a file without
         * `PACEInfo` (ICAO 9303-11, section 4.2, step 1), a `PACEInfo` of version 1 or without parameter ID.
         *
         * @throws MalformedCardAccessException if any of these rules is violated.
         */
        @JvmStatic
        @Throws(MalformedCardAccessException::class)
        public fun parse(encoded: ByteArray): CardAccess =
            try {
                parseSecurityInfos(encoded)
            } catch (e: RuntimeException) {
                // Bouncy Castle reads nested objects only when they are used and then reports malformed encodings
                // with various runtime exceptions; none is passed on.
                throw malformed("EF.CardAccess is not valid ASN.1.", e)
            }

        private fun parseSecurityInfos(encoded: ByteArray): CardAccess {
            val paceInfos = mutableListOf<PaceInfo>()
            val domainParameterInfos = mutableListOf<PaceDomainParameterInfo>()

            for (element in decodeSet(encoded)) {
                val securityInfo = element as? ASN1Sequence ?: throw malformed("A SecurityInfo is not a SEQUENCE.")

                if (securityInfo.size() !in MIN_SECURITY_INFO_SIZE..MAX_SECURITY_INFO_SIZE) {
                    throw malformed("A SecurityInfo does not have two or three elements.")
                }

                val protocol =
                    securityInfo.getObjectAt(PROTOCOL_INDEX) as? ASN1ObjectIdentifier
                        ?: throw malformed("A SecurityInfo does not start with an OBJECT IDENTIFIER.")

                val paceProtocol = PaceProtocol.fromOid(protocol.id)
                val family = PaceProtocol.Family.fromOid(protocol.id)

                if (paceProtocol != null) {
                    paceInfos += paceInfo(paceProtocol, securityInfo)
                } else if (family != null) {
                    domainParameterInfos += domainParameterInfo(family, securityInfo)
                }
            }

            requireUnambiguous(paceInfos, domainParameterInfos)

            return CardAccess(encoded, paceInfos.toList(), domainParameterInfos.toList())
        }

        private fun decodeSet(encoded: ByteArray): ASN1Set {
            // Bouncy Castle rejects trailing bytes with an IOException and reports other malformed encodings with
            // runtime exceptions.
            val primitive =
                try {
                    ASN1Primitive.fromByteArray(encoded)
                } catch (e: IOException) {
                    throw malformed("EF.CardAccess is not a single ASN.1 object.", e)
                } catch (e: IllegalArgumentException) {
                    throw malformed("EF.CardAccess is not valid ASN.1.", e)
                } catch (e: IllegalStateException) {
                    throw malformed("EF.CardAccess is not valid ASN.1.", e)
                }

            return primitive as? ASN1Set ?: throw malformed("EF.CardAccess is not a SET of SecurityInfos.")
        }

        // PACEInfo ::= SEQUENCE { protocol, version INTEGER, parameterId INTEGER OPTIONAL }
        private fun paceInfo(protocol: PaceProtocol, securityInfo: ASN1Sequence): PaceInfo {
            val version = nonNegativeInt(securityInfo.getObjectAt(REQUIRED_DATA_INDEX), "PACEInfo version")
            val parameterId = optionalParameterId(securityInfo, "PACEInfo parameterId")

            return PaceInfo(protocol, version, parameterId)
        }

        // PACEDomainParameterInfo ::= SEQUENCE { protocol, domainParameter AlgorithmIdentifier,
        //     parameterId INTEGER OPTIONAL }
        // AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
        private fun domainParameterInfo(
            family: PaceProtocol.Family,
            securityInfo: ASN1Sequence,
        ): PaceDomainParameterInfo {
            val algorithmIdentifier =
                securityInfo.getObjectAt(REQUIRED_DATA_INDEX) as? ASN1Sequence
                    ?: throw malformed("The domainParameter of a PACEDomainParameterInfo is not a SEQUENCE.")

            if (algorithmIdentifier.size() !in MIN_ALGORITHM_IDENTIFIER_SIZE..MAX_ALGORITHM_IDENTIFIER_SIZE) {
                throw malformed("The domainParameter of a PACEDomainParameterInfo does not have one or two elements.")
            }

            val algorithm =
                algorithmIdentifier.getObjectAt(0) as? ASN1ObjectIdentifier
                    ?: throw malformed("The domainParameter of a PACEDomainParameterInfo has no algorithm OID.")
            val encoded =
                try {
                    algorithmIdentifier.getEncoded(ASN1Encoding.DER)
                } catch (e: IOException) {
                    throw malformed("The domainParameter of a PACEDomainParameterInfo cannot be encoded.", e)
                }
            val parameterId = optionalParameterId(securityInfo, "PACEDomainParameterInfo parameterId")

            return PaceDomainParameterInfo(family, algorithm.id, encoded, parameterId)
        }

        private fun optionalParameterId(securityInfo: ASN1Sequence, field: String): Int? =
            if (securityInfo.size() > OPTIONAL_DATA_INDEX) {
                nonNegativeInt(securityInfo.getObjectAt(OPTIONAL_DATA_INDEX), field)
            } else {
                null
            }

        private fun nonNegativeInt(element: ASN1Encodable, field: String): Int {
            val integer = element as? ASN1Integer ?: throw malformed("The $field is not an INTEGER.")
            val value = integer.value

            if (value.signum() < 0 || value.bitLength() >= Int.SIZE_BITS) {
                throw malformed("The $field is not a non-negative 32-bit integer.")
            }

            return value.toInt()
        }

        private fun requireUnambiguous(
            paceInfos: List<PaceInfo>,
            domainParameterInfos: List<PaceDomainParameterInfo>,
        ) {
            if (paceInfos.distinctBy { it.protocol to it.parameterId }.size != paceInfos.size) {
                throw malformed("Two PACEInfos have the same protocol and parameter ID.")
            }

            if (domainParameterInfos.size > 1 && domainParameterInfos.any { it.parameterId == null }) {
                throw malformed("With several PACEDomainParameterInfos, each must have a parameter ID.")
            }

            if (domainParameterInfos.distinctBy { it.parameterId }.size != domainParameterInfos.size) {
                throw malformed("Two PACEDomainParameterInfos have the same parameter ID.")
            }

            val standardized = PaceInfo.STANDARDIZED_DOMAIN_PARAMETER_IDS

            if (domainParameterInfos.any { info -> info.parameterId?.let { it in standardized } == true }) {
                throw malformed("A PACEDomainParameterInfo uses a parameter ID reserved for standardized ones.")
            }
        }

        private fun malformed(message: String, cause: Throwable? = null) = MalformedCardAccessException(message, cause)
    }
}
