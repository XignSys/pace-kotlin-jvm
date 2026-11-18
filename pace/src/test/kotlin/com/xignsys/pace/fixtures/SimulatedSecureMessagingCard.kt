package com.xignsys.pace.fixtures

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.macs.CMac
import org.bouncycastle.crypto.params.KeyParameter
import java.io.ByteArrayOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The card side of Secure Messaging with AES, written independently of the production code straight from TR-03110
 * Part 3, F: it checks and decrypts protected commands and protects responses. AES comes from the JDK, CMAC from
 * Bouncy Castle; the APDU and data object handling is its own. [ssc] is the send sequence counter before the next
 * command or response. Test code only.
 */
internal class SimulatedSecureMessagingCard(
    encryptionKey: ByteArray,
    macKey: ByteArray,
    var ssc: Long,
) {
    private val encryptionKey = encryptionKey.copyOf()
    private val macKey = macKey.copyOf()

    /** Checks and decrypts the protected [command]; fails with an [AssertionError] if it does not verify. */
    fun receive(command: ByteArray): PlainCommand {
        val extended = command[HEADER].toInt() == 0
        val lcLength = if (extended) 3 else 1
        val leLength = if (extended) 2 else 1
        val dataLength =
            if (extended) (command[5].toInt() and 0xFF shl 8) or (command[6].toInt() and 0xFF) else command[HEADER].u()

        check(command.size == HEADER + lcLength + dataLength + leLength, "length")
        check(command.copyOfRange(command.size - leLength, command.size).all { it.toInt() == 0 }, "new Le")

        val header = command.copyOf(HEADER)
        val data = command.copyOfRange(HEADER + lcLength, HEADER + lcLength + dataLength)
        var cryptogram: ByteArray? = null
        var protectedLe: ByteArray? = null
        var checksum: ByteArray? = null
        var offset = 0

        while (offset < data.size) {
            val (length, lengthBytes) = length(data, offset + 1)
            val end = offset + 1 + lengthBytes + length
            val tlv = data.copyOfRange(offset, end)

            when (data[offset].u()) {
                0x87 -> cryptogram = tlv
                0x97 -> protectedLe = tlv
                0x8E -> checksum = value(tlv)
                else -> throw AssertionError("unexpected data object")
            }

            offset = end
        }

        check(checksum != null, "8E")
        ssc++

        val counter = counter()
        val objects = (cryptogram ?: byteArrayOf()) + (protectedLe ?: byteArrayOf())
        val macInput = if (objects.isEmpty()) counter + pad(header) else counter + pad(header) + pad(objects)

        check(cmac(macInput).contentEquals(checksum), "MAC")

        val plainData = cryptogram?.let { unpad(cbc(Cipher.DECRYPT_MODE, counter, withoutIndicator(value(it)))) }

        return PlainCommand(header, plainData ?: byteArrayOf(), protectedLe?.let { le(value(it)) } ?: 0, extended)
    }

    /** Protects a response with [data] (possibly empty) and [statusWord]. */
    fun respond(data: ByteArray, statusWord: Int): ByteArray =
        respondRaw(if (data.isEmpty()) null else pad(data), INDICATOR, statusWord)

    /**
     * Protects a response whose [plaintext] is taken as given (whole blocks, padding not checked), with [indicator];
     * for responses that are wrong behind a valid MAC. [plaintext] `null` gives a response without data.
     */
    fun respondRaw(
        plaintext: ByteArray?,
        indicator: Byte,
        statusWord: Int,
    ): ByteArray {
        ssc++

        val counter = counter()
        val cryptogram =
            if (plaintext == null) {
                byteArrayOf()
            } else {
                tlv(0x87, byteArrayOf(indicator) + cbc(Cipher.ENCRYPT_MODE, counter, plaintext))
            }
        val status = byteArrayOf((statusWord shr 8).toByte(), statusWord.toByte())
        val objects = cryptogram + tlv(0x99, status)

        return objects + tlv(0x8E, cmac(counter + pad(objects))) + status
    }

    /** A command as the card received it: the protected header, the decrypted data, `Ne` from `97` (0 if absent). */
    class PlainCommand(
        val header: ByteArray,
        val data: ByteArray,
        val ne: Int,
        val extended: Boolean,
    )

    private fun counter(): ByteArray {
        val block = ByteArray(BLOCK)

        for (i in 0 until Long.SIZE_BYTES) {
            block[BLOCK - 1 - i] = (ssc ushr (Byte.SIZE_BITS * i)).toByte()
        }

        return block
    }

    private fun cbc(
        mode: Int,
        counter: ByteArray,
        input: ByteArray,
    ): ByteArray {
        val ecb = Cipher.getInstance("AES/ECB/NoPadding")

        ecb.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encryptionKey, "AES"))

        val cbc = Cipher.getInstance("AES/CBC/NoPadding")

        cbc.init(mode, SecretKeySpec(encryptionKey, "AES"), IvParameterSpec(ecb.doFinal(counter)))

        return cbc.doFinal(input)
    }

    private fun cmac(input: ByteArray): ByteArray {
        val mac = CMac(AESEngine.newInstance(), MAC * Byte.SIZE_BITS)
        val result = ByteArray(MAC)

        mac.init(KeyParameter(macKey))
        mac.update(input, 0, input.size)
        mac.doFinal(result, 0)

        return result
    }

    private companion object {
        const val BLOCK = 16
        const val MAC = 8
        const val HEADER = 4
        const val INDICATOR: Byte = 0x01

        fun Byte.u(): Int = toInt() and 0xFF

        fun value(tlv: ByteArray): ByteArray = tlv.copyOfRange(1 + length(tlv, 1).second, tlv.size)

        fun withoutIndicator(value: ByteArray): ByteArray {
            check(value[0] == INDICATOR, "padding-content indicator")

            return value.copyOfRange(1, value.size)
        }

        fun le(value: ByteArray): Int {
            val le = if (value.size == 1) value[0].u() else (value[0].u() shl 8) or value[1].u()

            return if (le != 0) {
                le
            } else if (value.size == 1) {
                256
            } else {
                65_536
            }
        }

        /** The BER length at [offset] and the number of its bytes. */
        fun length(bytes: ByteArray, offset: Int): Pair<Int, Int> =
            when (val first = bytes[offset].u()) {
                in 0 until 0x80 -> first to 1
                0x81 -> bytes[offset + 1].u() to 2
                else -> ((bytes[offset + 1].u() shl 8) or bytes[offset + 2].u()) to 3
            }

        fun tlv(tag: Int, value: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()

            out.write(tag)

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

        fun pad(data: ByteArray): ByteArray =
            data.copyOf((data.size / BLOCK + 1) * BLOCK).also {
                it[data.size] =
                    0x80.toByte()
            }

        fun unpad(padded: ByteArray): ByteArray {
            var end = padded.size - 1

            while (padded[end].toInt() == 0) {
                end--
            }

            check(padded[end] == 0x80.toByte(), "padding")

            return padded.copyOf(end)
        }

        fun check(condition: Boolean, what: String) {
            if (!condition) {
                throw AssertionError("the protected command fails the card's check: $what")
            }
        }
    }
}
