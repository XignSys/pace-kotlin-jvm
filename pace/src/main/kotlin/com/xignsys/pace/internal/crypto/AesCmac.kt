package com.xignsys.pace.internal.crypto

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.macs.CMac

/**
 * AES-CMAC (NIST SP 800-38B, RFC 4493) with a MAC length of 8 bytes, for the PACE authentication token (TR-03110 Part
 * 3, A.2.4.2) and for Secure Messaging (F.4.2.2).
 *
 * Takes over [key]: [destroy] overwrites it. The MAC engine and its subkeys are created once and kept until [destroy].
 * Not thread-safe.
 */
internal class AesCmac(private val key: AesKey) {
    private var mac: CMac? =
        CMac(
            AESEngine.newInstance(),
            MAC_LENGTH * Byte.SIZE_BITS,
        ).also { it.init(key.keyParameter()) }

    /**
     * Computes the MAC over the concatenation of [parts].
     *
     * @throws IllegalStateException after [destroy].
     */
    fun mac(vararg parts: ByteArray): ByteArray {
        val engine = checkNotNull(mac) { "The MAC key has been destroyed." }
        val output = ByteArray(MAC_LENGTH)

        for (part in parts) {
            engine.update(part, 0, part.size)
        }

        engine.doFinal(output, 0)

        return output
    }

    /**
     * Checks in constant time whether [expected] is the MAC over the concatenation of [parts].
     *
     * @throws IllegalStateException after [destroy].
     */
    fun verify(expected: ByteArray, vararg parts: ByteArray): Boolean = constantTimeEquals(mac(*parts), expected)

    /** Overwrites the key and drops the MAC engine. Later calls have no effect. */
    fun destroy() {
        key.destroy()
        mac = null
    }

    companion object {
        /** MAC length in bytes (TR-03110 Part 3, A.2.4.2 and F.4.2.2). */
        const val MAC_LENGTH: Int = 8
    }
}
