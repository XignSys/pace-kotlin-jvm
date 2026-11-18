package com.xignsys.pace.fixtures

import com.xignsys.pace.CardTransport
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.macs.CMac
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.BigIntegers
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The card side of PACE with ECDH, Generic Mapping or Chip Authentication Mapping and AES, written independently of
 * the production code straight from TR-03110 Part 3, A.2.3, A.2.4, A.3.3, A.3.4.1 and B.1, and ICAO 9303-11, section
 * 4.4.3.5: it answers MSE:Set AT and the four General Authenticate steps, and afterwards Secure Messaging through a [SimulatedSecureMessagingCard] with its own session keys. The
 * digests and AES come from the JDK, CMAC and the curve arithmetic from Bouncy Castle (plain, not constant-time
 * multiplication); the data objects are handled by hand. Test code only.
 *
 * [curve] and [protocolOid] are the domain parameters and the protocol; [keyLength] is the AES key length in bytes;
 * [encodedPassword] is `f(pi)` (TR-03110 Part 3, Table 5); [nonce] is `s`. With [chipAuthenticationMapping], step 4
 * also returns the Encrypted Chip Authentication Data `8A` for the static key pair of [staticPublicKey].
 */
internal class SimulatedPaceCard(
    private val curve: X9ECParameters,
    private val protocolOid: String,
    private val keyLength: Int,
    private val encodedPassword: ByteArray,
    private val nonce: ByteArray,
    private val chipAuthenticationMapping: Boolean = false,
) : CardTransport {
    private val staticKey = BigInteger("0F1E2D3C4B5A69788796A5B4C3D2E1F0", HEX).mod(curve.n)
    private val mappingKey = BigInteger("1234567890ABCDEF1234567890ABCDEF", HEX).mod(curve.n)
    private val agreementKey = BigInteger("FEDCBA0987654321FEDCBA0987654321", HEX).mod(curve.n)
    private var step = 0
    private var mappedGenerator: ECPoint? = null
    private var terminalKey: ByteArray? = null
    private var encryptionKey: ByteArray? = null
    private var macKey: ByteArray? = null
    private var secureMessaging: SimulatedSecureMessagingCard? = null

    /** The card's static public key `PK_IC` for Chip Authentication Mapping, uncompressed. */
    val staticPublicKey: ByteArray =
        curve.g
            .multiply(staticKey)
            .normalize()
            .getEncoded(false)

    /** The card's ephemeral public key of the key agreement, uncompressed, once step 3 has run. */
    var chipKey: ByteArray? = null
        private set

    override fun transceive(command: ByteArray): ByteArray {
        secureMessaging?.let { card ->
            card.receive(command)

            return card.respond(hex("01 02 03 04"), SW_OK)
        }

        val response =
            when (step) {
                0 -> statusWord(SW_OK)
                1 -> encryptedNonce()
                2 -> mapNonce(objectOf(command, 0x81))
                3 -> keyAgreement(objectOf(command, 0x83))
                else -> mutualAuthentication(objectOf(command, 0x85))
            }

        step++

        return response
    }

    private fun encryptedNonce(): ByteArray {
        val passwordKey = kdf(encodedPassword, 3)
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")

        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(passwordKey, "AES"), IvParameterSpec(ByteArray(BLOCK)))

        return dynamicData(tlv(0x80, cipher.doFinal(nonce))) + statusWord(SW_OK)
    }

    private fun mapNonce(terminalMappingKey: ByteArray): ByteArray {
        // A.3.4.1: H = [sk_PICC] PK_PCD, G' = [s]G + H.
        val h =
            curve.curve
                .decodePoint(terminalMappingKey)
                .multiply(mappingKey)
                .normalize()

        mappedGenerator =
            curve.g
                .multiply(BigIntegers.fromUnsignedByteArray(nonce))
                .add(h)
                .normalize()

        return dynamicData(
            tlv(
                0x82,
                curve.g
                    .multiply(mappingKey)
                    .normalize()
                    .getEncoded(false),
            ),
        ) + statusWord(SW_OK)
    }

    private fun keyAgreement(terminalPublicKey: ByteArray): ByteArray {
        val generator = checkNotNull(mappedGenerator)
        val own = generator.multiply(agreementKey).normalize().getEncoded(false)
        val shared =
            curve.curve
                .decodePoint(terminalPublicKey)
                .multiply(agreementKey)
                .normalize()
        // A.2.3: K is the x-coordinate as an octet string of the field length.
        val secret =
            BigIntegers.asUnsignedByteArray(
                (curve.curve.fieldSize + 7) / 8,
                shared.affineXCoord.toBigInteger(),
            )

        terminalKey = terminalPublicKey
        chipKey = own
        macKey = kdf(secret, 2)
        encryptionKey = kdf(secret, 1)

        return dynamicData(tlv(0x84, own)) + statusWord(SW_OK)
    }

    private fun mutualAuthentication(terminalToken: ByteArray): ByteArray {
        // A.2.4: the terminal's token is over the chip's key, the chip's token over the terminal's key.
        if (!token(checkNotNull(chipKey)).contentEquals(terminalToken)) {
            return statusWord(SW_AUTHENTICATION_FAILED)
        }

        val chipToken = tlv(0x86, token(checkNotNull(terminalKey)))
        val response =
            dynamicData(if (chipAuthenticationMapping) chipToken + tlv(0x8A, chipAuthenticationData()) else chipToken) +
                statusWord(SW_OK)

        secureMessaging =
            SimulatedSecureMessagingCard(checkNotNull(encryptionKey), checkNotNull(macKey), ssc = 0)

        return response
    }

    /**
     * `A_IC = E(KS_Enc, CA_IC)` with `CA_IC = SK_IC^-1 * SK_Map,IC mod n` as FE2OS of the length of `n`, padded with
     * `80 00 ...`, in AES-CBC with the IV `E(KS_Enc, -1)` (ICAO 9303-11, sections 4.4.3.5 and 4.4.5.6).
     */
    private fun chipAuthenticationData(): ByteArray {
        val key = SecretKeySpec(checkNotNull(encryptionKey), "AES")
        val ecb = Cipher.getInstance("AES/ECB/NoPadding")
        val cbc = Cipher.getInstance("AES/CBC/NoPadding")
        val data =
            BigIntegers.asUnsignedByteArray(
                (curve.n.bitLength() + 7) / 8,
                staticKey.modInverse(curve.n).multiply(mappingKey).mod(curve.n),
            )
        val padded = data.copyOf((data.size / BLOCK + 1) * BLOCK).also { it[data.size] = PADDING_START }

        ecb.init(Cipher.ENCRYPT_MODE, key)
        cbc.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(ecb.doFinal(ByteArray(BLOCK) { ALL_ONES })))

        return cbc.doFinal(padded)
    }

    /** The authentication token: the 8-byte CMAC over `7F49 { 06 OID, 86 point }` with `K_MAC` (A.2.4, D.3). */
    private fun token(publicKey: ByteArray): ByteArray {
        val input = tlv(0x7F49, ASN1ObjectIdentifier(protocolOid).encoded + tlv(0x86, publicKey))
        val mac = CMac(AESEngine.newInstance(), MAC * Byte.SIZE_BITS)
        val result = ByteArray(MAC)

        mac.init(KeyParameter(checkNotNull(macKey)))
        mac.update(input, 0, input.size)
        mac.doFinal(result, 0)

        return result
    }

    /** `KDF(K, c) = H(K || c)`, SHA-1 for AES-128, SHA-256 otherwise, cut to the key length (A.2.3). */
    private fun kdf(secret: ByteArray, counter: Int): ByteArray =
        MessageDigest
            .getInstance(if (keyLength == AES_128) "SHA-1" else "SHA-256")
            .digest(secret + ByteBuffer.allocate(Int.SIZE_BYTES).putInt(counter).array())
            .copyOf(keyLength)

    private companion object {
        const val HEX = 16
        const val BLOCK = 16
        const val MAC = 8
        const val AES_128 = 16
        const val SW_OK = 0x9000
        const val SW_AUTHENTICATION_FAILED = 0x6300
        const val PADDING_START: Byte = 0x80.toByte()
        const val ALL_ONES: Byte = -1

        fun statusWord(value: Int): ByteArray = byteArrayOf((value shr 8).toByte(), value.toByte())

        fun dynamicData(objects: ByteArray): ByteArray = tlv(0x7C, objects)

        /** The value of the data object [tag] inside the `7C` of the General Authenticate [command]. */
        fun objectOf(command: ByteArray, tag: Int): ByteArray {
            val (lc, lcBytes) =
                if (command[4].toInt() ==
                    0
                ) {
                    (u(command[5]) shl 8 or u(command[6])) to 3
                } else {
                    u(command[4]) to 1
                }
            val data = command.copyOfRange(4 + lcBytes, 4 + lcBytes + lc)
            val (outerLength, outerBytes) = length(data, 1)
            val inner = data.copyOfRange(1 + outerBytes, 1 + outerBytes + outerLength)

            check(u(inner[0]) == tag) { "unexpected data object" }

            val (innerLength, innerBytes) = length(inner, 1)

            return inner.copyOfRange(1 + innerBytes, 1 + innerBytes + innerLength)
        }

        fun u(byte: Byte): Int = byte.toInt() and 0xFF

        fun length(bytes: ByteArray, offset: Int): Pair<Int, Int> =
            when (val first = u(bytes[offset])) {
                in 0 until 0x80 -> first to 1
                0x81 -> u(bytes[offset + 1]) to 2
                else -> ((u(bytes[offset + 1]) shl 8) or u(bytes[offset + 2])) to 3
            }

        fun tlv(tag: Int, value: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()

            if (tag > 0xFF) {
                out.write(tag shr 8)
            }

            out.write(tag and 0xFF)

            when {
                value.size < 0x80 -> {
                    out.write(value.size)
                }

                value.size <= 0xFF -> {
                    out.write(0x81)
                    out.write(value.size)
                }

                else -> {
                    out.write(0x82)
                    out.write(value.size shr 8)
                    out.write(value.size)
                }
            }

            out.write(value)

            return out.toByteArray()
        }
    }
}
