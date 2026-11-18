package com.xignsys.pace

import com.xignsys.pace.cardaccess.CardAccess
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.internal.pace.CertificateExtensions
import com.xignsys.pace.internal.pace.CertificateHolderAuthorizationTemplate
import com.xignsys.pace.internal.pace.ImplementedPace
import com.xignsys.pace.internal.pace.PaceCommands

/**
 * What PACE runs with: the [protocol] and the [domainParameterId] of a `PACEInfo` in EF.CardAccess, and optionally the
 * Certificate Holder Authorization Template [chat] and the [certificateExtensions] (TR-03110 Part 3, B.1 and B.14.1).
 *
 * MSE:Set AT always carries [domainParameterId] in data object `84`, so the chip uses exactly the domain parameters
 * chosen here. The CHAT is needed when Terminal Authentication version 2 follows PACE (TR-03110 Part 3, B.14.1); the
 * chip then returns the CA references (B.1). The certificate extensions are needed as well if the chip supports
 * Authorization Extensions, which it declares in the CardInfo of EF.CardAccess (A.1.1.7); otherwise they should be left
 * out (B.14.1). The caller chooses both, from the terminal's certificate and the authorization it needs (TR-03110 Part
 * 2, section 2.7.1); the library does not read CardInfo.
 *
 * [chat] and [certificateExtensions] are copied in and out.
 *
 * @throws IllegalArgumentException with the message
 *   - "The domain parameter ID must not be negative." if [domainParameterId] is negative;
 *   - "The CHAT must be exactly one DER-encoded data object with the tag 7F4C." if [chat] is not;
 *   - "The certificate extensions must be exactly one DER-encoded data object with the tag 65 that holds discretionary
 *     data templates 73, each an object identifier followed by data objects." if [certificateExtensions] are not
 *     (TR-03110 Part 3, C.3);
 *   - "Certificate extensions need a CHAT." if there are [certificateExtensions] without [chat]: both serve Terminal
 *     Authentication version 2 (B.14.1);
 *   - "The CHAT and the certificate extensions are too long for MSE:Set AT in short length." if MSE:Set AT with them
 *     would not fit short length, also when protected by Secure Messaging: MSE:Set AT is not among the commands that
 *     may use extended length (B.12.2).
 */
public class PaceParameters
    @JvmOverloads
    constructor(
        /** The PACE protocol. */
        public val protocol: PaceProtocol,
        /** The domain parameter ID, the `parameterId` of the `PACEInfo`. */
        public val domainParameterId: Int,
        chat: ByteArray? = null,
        certificateExtensions: ByteArray? = null,
    ) {
        private val chatBytes: ByteArray? = chat?.copyOf()
        private val extensionBytes: ByteArray? = certificateExtensions?.copyOf()

        init {
            require(domainParameterId >= 0) { "The domain parameter ID must not be negative." }
            require(chatBytes == null || CertificateHolderAuthorizationTemplate.isOneDataObject(chatBytes)) {
                "The CHAT must be exactly one DER-encoded data object with the tag 7F4C."
            }
            require(extensionBytes == null || CertificateExtensions.isValid(extensionBytes)) {
                "The certificate extensions must be exactly one DER-encoded data object with the tag 65 that holds " +
                    "discretionary data templates 73, each an object identifier followed by data objects."
            }
            require(extensionBytes == null || chatBytes != null) { "Certificate extensions need a CHAT." }
            // An ID above 255 cannot be sent; PACE refuses it as not supported before anything is sent.
            require(
                domainParameterId > BYTE_MAX ||
                    PaceCommands.mseSetAtFitsShortLength(protocol, domainParameterId, chatBytes, extensionBytes),
            ) { "The CHAT and the certificate extensions are too long for MSE:Set AT in short length." }
        }

        /** A copy of the DER encoding of the CHAT `7F4C`, or `null` if PACE runs without one. */
        public val chat: ByteArray?
            get() = chatBytes?.copyOf()

        /** A copy of the DER encoding of the certificate extensions `65`, or `null` if PACE runs without them. */
        public val certificateExtensions: ByteArray?
            get() = extensionBytes?.copyOf()

        override fun toString(): String =
            "PaceParameters($protocol, domainParameterId=$domainParameterId, chat=${chatBytes != null}, " +
                "certificateExtensions=${extensionBytes != null})"

        /** The default choice. */
        public companion object {
            private const val BYTE_MAX = 0xFF

            /**
             * The parameters the library prefers among those [cardAccess] offers, or `null` if it offers none the
             * library implements: the first implemented PACE variant, in the library's order of preference, for which
             * [cardAccess] has a `PACEInfo` of version 2. The order of the entries in EF.CardAccess does not matter.
             *
             * The order of preference: first ECDH, Generic Mapping and AES-128 on brainpoolP256r1 (ID 13), the
             * baseline of BSI TR-03116-2; then Generic Mapping before Chip Authentication Mapping, each with AES-256,
             * AES-192 and AES-128, each on the larger standardized domain parameters first (the higher IDs of TR-03110
             * Part 3, Table 4). The deprecated IDs 8 and 9 are never chosen by default, but can be given to the
             * constructor.
             *
             * @throws IllegalArgumentException with the messages of the constructor if [chat] or
             *   [certificateExtensions] break its rules.
             */
            @JvmStatic
            @JvmOverloads
            public fun defaultFor(
                cardAccess: CardAccess,
                chat: ByteArray? = null,
                certificateExtensions: ByteArray? = null,
            ): PaceParameters? =
                ImplementedPace.VARIANTS
                    .firstOrNull { (protocol, id) ->
                        cardAccess.paceInfo(protocol, id)?.version ==
                            ImplementedPace.VERSION
                    }?.let { (protocol, id) -> PaceParameters(protocol, id, chat, certificateExtensions) }
        }
    }
