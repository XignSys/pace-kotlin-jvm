package com.xignsys.pace.internal.crypto

import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.DefaultBufferedBlockCipher
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.params.ParametersWithIV

/**
 * AES in CBC mode with one key, for the encrypted PACE nonce (TR-03110 Part 3, A.3.3) and for Secure Messaging
 * (F.4.2.1).
 *
 * Takes over [key]: [destroy] overwrites it. One cipher per direction is created on first use and kept until [destroy],
 * so that each key schedule exists once per key; a new IV is set without passing the key again. Data is processed in
 * whole blocks: padding is the caller's task (F.3.3). Not thread-safe.
 */
internal class AesCbc(private val key: AesKey) {
    private var encryptor: BufferedBlockCipher? = null
    private var decryptor: BufferedBlockCipher? = null

    /**
     * Encrypts [data] with [iv].
     *
     * @throws IllegalArgumentException if [iv] is not one block or [data] is not whole blocks.
     * @throws IllegalStateException after [destroy].
     */
    fun encrypt(iv: ByteArray, data: ByteArray): ByteArray = process(encryptingCipher(), ENCRYPT, iv, data)

    /**
     * Decrypts [data] with [iv].
     *
     * @throws IllegalArgumentException if [iv] is not one block or [data] is not whole blocks.
     * @throws IllegalStateException after [destroy].
     */
    fun decrypt(iv: ByteArray, data: ByteArray): ByteArray = process(decryptingCipher(), DECRYPT, iv, data)

    /**
     * Encrypts one block with the key alone, `E(K, block)`: CBC with an all-zero IV on a single block, as for the
     * Secure Messaging IV `E(K_Enc, SSC)` (TR-03110 Part 3, F.4.2.1).
     *
     * @throws IllegalArgumentException if [block] is not exactly one block.
     * @throws IllegalStateException after [destroy].
     */
    fun encryptBlock(block: ByteArray): ByteArray {
        require(block.size == BLOCK_SIZE) { "Expected one block of $BLOCK_SIZE bytes, got ${block.size}." }

        return encrypt(ByteArray(BLOCK_SIZE), block)
    }

    /** Overwrites the key and drops both ciphers. Later calls have no effect. */
    fun destroy() {
        key.destroy()
        encryptor = null
        decryptor = null
    }

    private fun encryptingCipher(): BufferedBlockCipher = encryptor ?: newCipher(ENCRYPT).also { encryptor = it }

    private fun decryptingCipher(): BufferedBlockCipher = decryptor ?: newCipher(DECRYPT).also { decryptor = it }

    private fun newCipher(encrypting: Boolean): BufferedBlockCipher {
        val cipher = DefaultBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()))

        cipher.init(encrypting, key.keyParameter())

        return cipher
    }

    private fun process(
        cipher: BufferedBlockCipher,
        encrypting: Boolean,
        iv: ByteArray,
        data: ByteArray,
    ): ByteArray {
        require(iv.size == BLOCK_SIZE) { "The IV must be one block of $BLOCK_SIZE bytes, got ${iv.size}." }
        require(data.size % BLOCK_SIZE == 0) { "The data must be whole blocks of $BLOCK_SIZE bytes, got ${data.size}." }

        // Without a key in the parameters, the cipher keeps its key and its key schedule.
        cipher.init(encrypting, ParametersWithIV(null, iv))

        val output = ByteArray(data.size)
        val processed = cipher.processBytes(data, 0, data.size, output, 0)

        cipher.doFinal(output, processed)

        return output
    }

    companion object {
        /** AES block size in bytes (FIPS 197). */
        const val BLOCK_SIZE: Int = 16

        private const val ENCRYPT = true
        private const val DECRYPT = false
    }
}
