package com.xignsys.pace.internal.securemessaging

import com.xignsys.pace.SecureMessagingResult.Refused
import com.xignsys.pace.apdu.CommandApdu
import com.xignsys.pace.apdu.ResponseApdu
import com.xignsys.pace.apdu.StatusWord
import com.xignsys.pace.internal.crypto.AesCbc
import com.xignsys.pace.internal.crypto.AesCmac
import com.xignsys.pace.internal.crypto.Iso7816Padding
import com.xignsys.pace.internal.crypto.wipe
import com.xignsys.pace.internal.pace.PaceSessionKeys
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.BERTags
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.util.Pack
import java.io.IOException

/**
 * PACE Secure Messaging with AES (TR-03110 Part 3, F; ICAO 9303-11, section 9.8): protects command APDUs and checks and
 * unprotects the card's responses with the PACE session keys and the send sequence counter (SSC).
 *
 * The cryptography is Bouncy Castle's, through `internal.crypto`: AES-CBC with the IV `E(K_Enc, SSC)` (F.4.2.1), the
 * 8-byte AES-CMAC over the SSC and the padded data (F.4.2.2), ISO/IEC 7816-4 padding (F.3.3), DER data objects (F.3).
 * This class only puts them together as F defines: a command becomes `[87] [97] 8E` with a new `Le` (F.3.1); a
 * response must be exactly `[87] 99 8E` followed by the status word of `99` (F.3.2). The MAC of a response is checked
 * before anything is decrypted. A response without these data objects, such as `69 87` or `69 88` from a card that has
 * aborted Secure Messaging (F.6), fails like any other.
 *
 * A command keeps its length form: a short command whose protected form does not fit short length is refused (see
 * [refusal]); the caller that built it chooses the form, because it knows which commands may use extended length
 * (TR-03110 Part 3, B.12.2).
 *
 * The SSC starts at [ssc] (0 right after PACE, ICAO 9303-11, section 9.8.7.3) and is increased before every command
 * and every response (F.5). Owns [keys]: [destroy] overwrites them. Not thread-safe.
 */
internal class SecureMessaging(
    /** The session keys; [destroy] overwrites them. */
    val keys: PaceSessionKeys,
    ssc: Long = 0,
) {
    /** The send sequence counter after the last command or response. */
    var ssc: Long = ssc
        private set

    init {
        require(ssc >= 0) { "The send sequence counter must not be negative." }
    }

    /**
     * Why [command] cannot be protected, or `null` if it can: its class byte is not of the first interindustry class
     * with at most command chaining and a logical channel, its INS is odd (F.3 covers even INS only), or its protected
     * form does not fit its length form. Only lengths are computed; the SSC is not changed.
     */
    fun refusal(command: CommandApdu): Refused? {
        if (command.cla and PROTECTABLE_CLA_BITS.inv() != 0) {
            return Refused.UnsupportedClass
        }

        if (command.ins and 1 != 0) {
            return Refused.OddInstruction
        }

        val length = protectedDataLength(command)

        return if (length > command.lengthForm.maxNc) Refused.TooLongForShortLength(length) else null
    }

    /**
     * Protects [command] (F.3.1, F.4.2) in its length form, with the new `Le` `00` for short and `00 00` for extended
     * length (ICAO 9303-11, Figure 5).
     *
     * @throws IllegalArgumentException if [refusal] is not `null` for [command].
     * @throws IllegalStateException after [destroy].
     */
    fun protect(command: CommandApdu): CommandApdu {
        require(refusal(command) == null) { "The command cannot be protected." }

        val block = nextSscBlock()
        val header =
            byteArrayOf(
                (command.cla or SECURE_MESSAGING_CLA).toByte(),
                command.ins.toByte(),
                command.p1.toByte(),
                command.p2.toByte(),
            )
        val cryptogram = if (command.nc == 0) byteArrayOf() else cryptogram(block, command.data)
        val dataObjects = cryptogram + protectedLe(command)
        val mac =
            if (dataObjects.isEmpty()) {
                keys.mac.mac(block, pad(header))
            } else {
                keys.mac.mac(block, pad(header), pad(dataObjects))
            }

        return CommandApdu.of(
            command.cla or SECURE_MESSAGING_CLA,
            command.ins,
            command.p1,
            command.p2,
            data = dataObjects + dataObject(TAG_CHECKSUM, mac),
            ne = command.lengthForm.maxNe,
            lengthForm = command.lengthForm,
        )
    }

    /**
     * Checks and unprotects [response], the response APDU as received (F.3.2, F.4.2): structure first, then the MAC in
     * constant time, then decryption and padding.
     *
     * @return the plain response with the status word of `99`, or `null` if [response] does not pass Secure Messaging.
     * @throws IllegalStateException after [destroy].
     */
    fun unprotect(response: ByteArray): ResponseApdu? {
        val block = nextSscBlock()

        if (response.size < StatusWord.SIZE) {
            return null
        }

        val body = response.copyOf(response.size - StatusWord.SIZE)
        val statusWord = Pack.bigEndianToShort(response, body.size).toInt() and STATUS_WORD_MASK
        val objects = dataObjects(body) ?: return null
        val cryptogram: ByteArray?
        val processingStatus: ByteArray?
        val checksum: ByteArray?
        val authenticated: ByteArray

        when (objects.size) {
            2 -> {
                cryptogram = null
                processingStatus = octets(objects[0], TAG_BYTE_PROCESSING_STATUS)
                checksum = octets(objects[1], TAG_BYTE_CHECKSUM)
                authenticated = encoded(objects[0])
            }

            3 -> {
                cryptogram = octets(objects[0], TAG_BYTE_CRYPTOGRAM) ?: return null
                processingStatus = octets(objects[1], TAG_BYTE_PROCESSING_STATUS)
                checksum = octets(objects[2], TAG_BYTE_CHECKSUM)
                authenticated = encoded(objects[0]) + encoded(objects[1])
            }

            else -> {
                return null
            }
        }

        if (processingStatus?.size != StatusWord.SIZE ||
            checksum?.size != AesCmac.MAC_LENGTH ||
            !keys.mac.verify(checksum, block, pad(authenticated))
        ) {
            return null
        }

        if (Pack.bigEndianToShort(processingStatus, 0).toInt() and STATUS_WORD_MASK != statusWord) {
            return null
        }

        val data = if (cryptogram == null) byteArrayOf() else decrypt(block, cryptogram) ?: return null

        return ResponseApdu.of(data, StatusWord(statusWord)).also { data.wipe() }
    }

    /** Overwrites the keys. Later calls have no effect. */
    fun destroy() {
        keys.destroy()
    }

    override fun toString(): String = "SecureMessaging(ssc=$ssc)"

    private fun nextSscBlock(): ByteArray {
        check(ssc != Long.MAX_VALUE) { "The send sequence counter is exhausted." }

        ssc++

        val block = ByteArray(AesCbc.BLOCK_SIZE)

        Pack.longToBigEndian(ssc, block, AesCbc.BLOCK_SIZE - Long.SIZE_BYTES)

        return block
    }

    private fun cryptogram(sscBlock: ByteArray, data: ByteArray): ByteArray {
        val padded = pad(data)
        val encrypted = keys.encryption.encrypt(keys.encryption.encryptBlock(sscBlock), padded)

        padded.wipe()

        return dataObject(TAG_CRYPTOGRAM, byteArrayOf(PADDING_CONTENT_INDICATOR) + encrypted)
    }

    /** The decrypted data of [cryptogram], or `null` if its indicator, length or padding is not valid. */
    private fun decrypt(sscBlock: ByteArray, cryptogram: ByteArray): ByteArray? {
        if (cryptogram.size < 1 + AesCbc.BLOCK_SIZE ||
            cryptogram[0] != PADDING_CONTENT_INDICATOR ||
            (cryptogram.size - 1) % AesCbc.BLOCK_SIZE != 0
        ) {
            return null
        }

        val encrypted = cryptogram.copyOfRange(1, cryptogram.size)
        val padded = keys.encryption.decrypt(keys.encryption.encryptBlock(sscBlock), encrypted)

        return Iso7816Padding.unpad(padded).also { padded.wipe() }
    }

    companion object {
        /** CLA bits that indicate Secure Messaging with the header authenticated (TR-03110 Part 3, F.3). */
        private const val SECURE_MESSAGING_CLA = 0x0C

        /**
         * CLA bits a command to protect may carry: command chaining (`10`) and the logical channel (`03`) of the first
         * interindustry class. Anything else (other classes, Secure Messaging already indicated) is refused.
         */
        private const val PROTECTABLE_CLA_BITS = 0x13

        /** Tag numbers of `87` (padding-content indicator and cryptogram), `97` (protected `Le`) and `8E` (MAC). */
        private const val TAG_CRYPTOGRAM = 7
        private const val TAG_PROTECTED_LE = 23
        private const val TAG_CHECKSUM = 14

        /** The tag bytes of the response data objects `87`, `99` and `8E` (TR-03110 Part 3, Table 32). */
        private const val TAG_BYTE_CRYPTOGRAM = 0x87
        private const val TAG_BYTE_PROCESSING_STATUS = 0x99
        private const val TAG_BYTE_CHECKSUM = 0x8E

        /** Padding-content indicator of `87`: ISO/IEC 7816-4 padding (F.3.3). */
        private const val PADDING_CONTENT_INDICATOR: Byte = 0x01

        private const val STATUS_WORD_MASK = 0xFFFF

        /** The length of the data field of the protected form of [command], `Lc'`, from the lengths alone. */
        fun protectedDataLength(command: CommandApdu): Int {
            // The data objects of protect(), with placeholder values of the lengths that padding and MAC produce.
            val cryptogram =
                if (command.nc == 0) {
                    byteArrayOf()
                } else {
                    dataObject(TAG_CRYPTOGRAM, ByteArray(1 + paddedSize(command.nc)))
                }
            val checksum = dataObject(TAG_CHECKSUM, ByteArray(AesCmac.MAC_LENGTH))

            return cryptogram.size + protectedLe(command).size + checksum.size
        }

        private fun paddedSize(size: Int): Int = (size / AesCbc.BLOCK_SIZE + 1) * AesCbc.BLOCK_SIZE

        private fun pad(data: ByteArray): ByteArray = Iso7816Padding.pad(data)

        /**
         * `97` with the `Le` field of [command]: one byte for short and two for extended length, the largest `Ne`
         * encoded as zero; empty if the command expects no response data.
         */
        private fun protectedLe(command: CommandApdu): ByteArray {
            if (command.ne == CommandApdu.NO_RESPONSE_DATA) {
                return byteArrayOf()
            }

            val le = if (command.ne == command.lengthForm.maxNe) 0 else command.ne
            val value =
                when (command.lengthForm) {
                    CommandApdu.LengthForm.SHORT -> byteArrayOf(le.toByte())
                    CommandApdu.LengthForm.EXTENDED -> Pack.shortToBigEndian(le.toShort())
                }

            return dataObject(TAG_PROTECTED_LE, value)
        }

        private fun dataObject(tagNumber: Int, value: ByteArray): ByteArray =
            encoded(DERTaggedObject(false, tagNumber, DEROctetString(value)))

        private fun encoded(tagged: ASN1TaggedObject): ByteArray = tagged.getEncoded(ASN1Encoding.DER)

        /**
         * The data objects of [body], read with Bouncy Castle, or `null` if they are not context-specific DER data
         * objects whose encodings, concatenated, give back [body] exactly.
         */
        private fun dataObjects(body: ByteArray): List<ASN1TaggedObject>? {
            val objects = mutableListOf<ASN1TaggedObject>()

            try {
                ASN1InputStream(body).use { input ->
                    while (true) {
                        val element = input.readObject() ?: break
                        val tagged = element as? ASN1TaggedObject ?: return null

                        if (tagged.tagClass != BERTags.CONTEXT_SPECIFIC) {
                            return null
                        }

                        objects += tagged
                    }
                }

                val reencoded = objects.fold(byteArrayOf()) { all, tagged -> all + encoded(tagged) }

                return if (reencoded.contentEquals(body)) objects else null
            } catch (_: IOException) {
                return null
            } catch (_: RuntimeException) {
                // Bouncy Castle reads nested objects only when they are used and reports malformed encodings with
                // various runtime exceptions; none is passed on.
                return null
            }
        }

        /** The value of [tagged] if its tag byte is [tagByte] and it is primitive; `null` otherwise. */
        private fun octets(tagged: ASN1TaggedObject, tagByte: Int): ByteArray? {
            if (encoded(tagged)[0].toInt() and BYTE_MASK != tagByte) {
                return null
            }

            return try {
                ASN1OctetString.getInstance(tagged, false).octets
            } catch (_: RuntimeException) {
                // A constructed or otherwise unexpected encoding of the data object.
                null
            }
        }

        private const val BYTE_MASK = 0xFF
    }
}
