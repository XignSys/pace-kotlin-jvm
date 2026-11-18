package com.xignsys.pace.internal.crypto

import org.bouncycastle.crypto.params.KeyParameter

/**
 * An AES key of 128, 192 or 256 bits that can be overwritten (TR-03110 Part 3, A.2.3.2).
 *
 * The key bytes live in a Bouncy Castle [KeyParameter], whose internal array is overwritten by [destroy]. Not
 * thread-safe.
 */
internal class AesKey private constructor(private val parameter: KeyParameter) {
    /** Whether [destroy] has been called. */
    var isDestroyed: Boolean = false
        private set

    /**
     * The key as a Bouncy Castle parameter, for initialising an engine.
     *
     * @throws IllegalStateException if the key has been destroyed.
     */
    fun keyParameter(): KeyParameter {
        check(!isDestroyed) { "The key has been destroyed." }

        return parameter
    }

    /** Overwrites the key bytes. Later calls have no effect. */
    fun destroy() {
        parameter.key.wipe()
        isDestroyed = true
    }

    override fun toString(): String = "AesKey(destroyed=$isDestroyed)"

    /** The key sizes of PACE and Secure Messaging with AES (TR-03110 Part 3, A.2.3.2). */
    enum class Size(
        /** The key length in bytes. */
        val bytes: Int,
    ) {
        /** AES-128, 16 bytes. */
        AES_128(16),

        /** AES-192, 24 bytes. */
        AES_192(24),

        /** AES-256, 32 bytes. */
        AES_256(32),
    }

    companion object {
        /**
         * Creates a key from [key] and overwrites [key] afterwards, so that only this object holds the key bytes.
         *
         * @throws IllegalArgumentException if [key] is not 16, 24 or 32 bytes long.
         */
        fun takeOver(key: ByteArray): AesKey {
            try {
                require(Size.entries.any { it.bytes == key.size }) {
                    "An AES key has 16, 24 or 32 bytes, got ${key.size}."
                }

                return AesKey(KeyParameter(key))
            } finally {
                key.wipe()
            }
        }
    }
}
