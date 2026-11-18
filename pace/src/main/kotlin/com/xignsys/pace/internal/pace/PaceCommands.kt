package com.xignsys.pace.internal.pace

import com.xignsys.pace.apdu.CommandApdu
import com.xignsys.pace.apdu.CommandApdu.LengthForm
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.internal.securemessaging.SecureMessaging
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERTaggedObject

/** The commands of PACE: MSE:Set AT and the General Authenticate chain (TR-03110 Part 3, B.1, B.11.1 and B.14.1). */
internal object PaceCommands {
    private const val CLA_PLAIN = 0x00
    private const val CLA_CHAINING = 0x10
    private const val INS_MANAGE_SECURITY_ENVIRONMENT = 0x22
    private const val INS_GENERAL_AUTHENTICATE = 0x86
    private const val P1_SET_FOR_MUTUAL_AUTHENTICATION = 0xC1
    private const val P2_AUTHENTICATION_TEMPLATE = 0xA4
    private const val P1_P2_IMPLICIT = 0x00
    private const val TAG_MECHANISM_REFERENCE = 0x00
    private const val TAG_PASSWORD_REFERENCE = 0x03
    private const val TAG_DOMAIN_PARAMETER_REFERENCE = 0x04
    private const val BYTE_MAX = 0xFF

    /**
     * MSE:Set AT for PACE: `00 22 C1 A4` with the cryptographic mechanism reference `80` (the object identifier of
     * [protocol], value only), the password reference `83`, the domain parameter reference `84`, then [chat] and
     * [certificateExtensions] unchanged if there are, in the order TR-03110 Part 3, B.1, and ICAO 9303-11, section
     * 4.4.4.1, list them. Short length only: MSE:Set AT is not among the commands that may use extended length
     * (TR-03110 Part 3, B.12.2).
     *
     * The domain parameter reference is always sent: TR-03110 Part 3, B.14.1, and ICAO 9303-11, section 4.4.4.1,
     * require it when the domain parameters are ambiguous and do not forbid it otherwise, and it tells the chip exactly
     * which parameters the terminal chose.
     *
     * @param chat the DER encoding of the Certificate Holder Authorization Template `7F4C`, or `null`.
     * @param certificateExtensions the DER encoding of the certificate extensions `65`, or `null`.
     * @throws IllegalArgumentException if [passwordReference] or [domainParameterId] does not fit one byte, or if the
     *   data field does not fit short length.
     */
    fun mseSetAt(
        protocol: PaceProtocol,
        passwordReference: Int,
        domainParameterId: Int,
        chat: ByteArray?,
        certificateExtensions: ByteArray?,
    ): CommandApdu =
        mseSetAt(protocol, passwordReference, domainParameterId, chat, certificateExtensions, LengthForm.SHORT)

    /**
     * Whether [mseSetAt] with these values fits short length, also when Secure Messaging protects it, as for a second
     * PACE run through a channel (TR-03110 Part 3, B.1 and B.12.2). The password reference has one byte for every
     * password, so it does not change the length.
     *
     * @throws IllegalArgumentException if [domainParameterId] does not fit one byte.
     */
    fun mseSetAtFitsShortLength(
        protocol: PaceProtocol,
        domainParameterId: Int,
        chat: ByteArray?,
        certificateExtensions: ByteArray?,
    ): Boolean {
        val command = mseSetAt(protocol, 0, domainParameterId, chat, certificateExtensions, LengthForm.EXTENDED)
        val maxNc = LengthForm.SHORT.maxNc

        return command.nc <= maxNc && SecureMessaging.protectedDataLength(command) <= maxNc
    }

    private fun mseSetAt(
        protocol: PaceProtocol,
        passwordReference: Int,
        domainParameterId: Int,
        chat: ByteArray?,
        certificateExtensions: ByteArray?,
        lengthForm: LengthForm,
    ): CommandApdu {
        require(passwordReference in 0..BYTE_MAX) { "The password reference has one byte." }
        require(domainParameterId in 0..BYTE_MAX) { "The domain parameter reference has one byte." }

        // Implicit context-specific tag [0] on the object identifier gives 80 with the value only, as B.14.1 requires.
        val mechanism = DERTaggedObject(false, TAG_MECHANISM_REFERENCE, ASN1ObjectIdentifier(protocol.oid)).encoded
        val password = oneByteObject(TAG_PASSWORD_REFERENCE, passwordReference)
        val domainParameters = oneByteObject(TAG_DOMAIN_PARAMETER_REFERENCE, domainParameterId)

        return CommandApdu.of(
            CLA_PLAIN,
            INS_MANAGE_SECURITY_ENVIRONMENT,
            P1_SET_FOR_MUTUAL_AUTHENTICATION,
            P2_AUTHENTICATION_TEMPLATE,
            data =
                mechanism + password + domainParameters + (chat ?: byteArrayOf()) +
                    (certificateExtensions ?: byteArrayOf()),
            lengthForm = lengthForm,
        )
    }

    /**
     * General Authenticate with the dynamic authentication data [data] (`7C`) and `Le` `00`. Every step but the last
     * is sent with command chaining (TR-03110 Part 3, B.13; ICAO 9303-11, section 4.4.4.3).
     */
    fun generalAuthenticate(data: ByteArray, isLast: Boolean): CommandApdu =
        CommandApdu.of(
            if (isLast) CLA_PLAIN else CLA_CHAINING,
            INS_GENERAL_AUTHENTICATE,
            P1_P2_IMPLICIT,
            P1_P2_IMPLICIT,
            data = data,
            ne = CommandApdu.LengthForm.SHORT.maxNe,
        )

    private fun oneByteObject(tagNumber: Int, value: Int): ByteArray =
        DERTaggedObject(false, tagNumber, DEROctetString(byteArrayOf(value.toByte()))).encoded
}
