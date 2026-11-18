package com.xignsys.pace.internal.crypto

import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.KDF2BytesGenerator
import org.bouncycastle.crypto.params.KDFParameters

/**
 * The key derivation function `KDF(K, c) = H(K || c)` of TR-03110 Part 3, A.2.3, for AES keys (A.2.3.2): for AES-128
 * `H` is SHA-1 and the key is the first 16 bytes of the hash; for AES-192 and AES-256 `H` is SHA-256 and the key is the
 * first 24 or all 32 bytes. The optional nonce `r` is used by Chip Authentication version 2 only and is not supported.
 *
 * Bouncy Castle's `KDF2BytesGenerator` (ISO 18033-2) computes this function: its output is
 * `H(K || 1) || H(K || 2) || ...` with the counter as a 32-bit big-endian integer, so `H(K || c)` is its block number
 * `c`. Its optional extra input follows the counter, so a nonce `r`, which A.2.3 places before the counter in
 * `H(K || r || c)`, would have to be part of the secret given to the generator, never its extra input.
 *
 * The callers keep ownership of the input and overwrite it themselves.
 */
internal object KeyDerivation {
    /** Counter `c` for the encryption key, `KDF_Enc` (TR-03110 Part 3, A.2.3). */
    const val ENCRYPTION_KEY_COUNTER: Int = 1

    /** Counter `c` for the MAC key, `KDF_MAC` (TR-03110 Part 3, A.2.3). */
    const val MAC_KEY_COUNTER: Int = 2

    /** Counter `c` for the key derived from the password, `KDF_pi` (TR-03110 Part 3, A.2.3). */
    const val PASSWORD_KEY_COUNTER: Int = 3

    /** `K_Enc = KDF_Enc(K)` of [size] from the shared secret [sharedSecret]. */
    fun encryptionKey(sharedSecret: ByteArray, size: AesKey.Size): AesKey =
        derive(sharedSecret, ENCRYPTION_KEY_COUNTER, size)

    /** `K_MAC = KDF_MAC(K)` of [size] from the shared secret [sharedSecret]. */
    fun macKey(sharedSecret: ByteArray, size: AesKey.Size): AesKey = derive(sharedSecret, MAC_KEY_COUNTER, size)

    /** `K_pi = KDF_pi(pi)` of [size] from the encoded password `f(pi)` (TR-03110 Part 3, Table 5). */
    fun passwordKey(encodedPassword: ByteArray, size: AesKey.Size): AesKey =
        derive(encodedPassword, PASSWORD_KEY_COUNTER, size)

    private fun derive(
        secret: ByteArray,
        counter: Int,
        size: AesKey.Size,
    ): AesKey {
        val digestSize = digest(size).digestSize
        val generator = KDF2BytesGenerator(digest(size))
        val blocks = ByteArray(counter * digestSize)

        generator.init(KDFParameters(secret, null))
        generator.generateBytes(blocks, 0, blocks.size)

        try {
            val start = (counter - 1) * digestSize

            return AesKey.takeOver(blocks.copyOfRange(start, start + size.bytes))
        } finally {
            blocks.wipe()
        }
    }

    /** SHA-1 for AES-128 keys, SHA-256 for AES-192 and AES-256 keys (A.2.3.2). */
    private fun digest(size: AesKey.Size): Digest =
        when (size) {
            AesKey.Size.AES_128 -> SHA1Digest()
            AesKey.Size.AES_192, AesKey.Size.AES_256 -> SHA256Digest()
        }
}
