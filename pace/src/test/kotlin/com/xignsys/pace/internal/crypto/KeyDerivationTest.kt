package com.xignsys.pace.internal.crypto

import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * The key derivation function of TR-03110 Part 3, A.2.3, for AES keys (A.2.3.2). Expected values for AES-128: ICAO
 * 9303-11, Appendix G (PACE with ECDH, Generic Mapping and AES-128 session keys). No published example covers AES-192
 * and AES-256; their keys are checked against `H(K || c)` with the JDK's SHA-256.
 */
class KeyDerivationTest {
    @Test
    fun derivesThePasswordKeyOfTheIcaoExample() {
        // ICAO 9303-11, Appendix G: the encoding K of the MRZ and the derived K_pi.
        val key = KeyDerivation.passwordKey(hex("7E2D2A41 C74EA0B3 8CD36F86 3939BFA8 E9032AAD"), AesKey.Size.AES_128)

        assertThat(key.keyParameter().key).isEqualTo(hex("89DED1B2 6624EC1E 634C1989 302849DD"))
    }

    @Test
    fun derivesTheSessionKeysOfTheIcaoExample() {
        // ICAO 9303-11, Appendix G.1: the shared secret of the key agreement and the session keys KS_Enc and KS_MAC.
        val sharedSecret = hex("28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925")

        assertThat(KeyDerivation.encryptionKey(sharedSecret, AesKey.Size.AES_128).keyParameter().key)
            .isEqualTo(hex("F5F0E35C 0D7161EE 6724EE51 3A0D9A7F"))
        assertThat(KeyDerivation.macKey(sharedSecret, AesKey.Size.AES_128).keyParameter().key)
            .isEqualTo(hex("FE251C78 58B356B2 4514B3BD 5F4297D1"))
    }

    @Test
    fun leavesTheInputToTheCaller() {
        val sharedSecret = hex("28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925")
        val copy = sharedSecret.copyOf()

        KeyDerivation.encryptionKey(sharedSecret, AesKey.Size.AES_128)

        assertThat(sharedSecret).isEqualTo(copy)
    }

    @ParameterizedTest
    @EnumSource(value = AesKey.Size::class, names = ["AES_192", "AES_256"])
    internal fun derivesAes192And256KeysWithSha256(size: AesKey.Size) {
        // A.2.3.2: SHA-256, octets 1 to 24 for AES-192, all 32 for AES-256; keydata = H(K || c), c a 32-bit big-endian
        // integer (A.2.3).
        val secret = hex("28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925")

        assertThat(KeyDerivation.encryptionKey(secret, size).keyParameter().key).isEqualTo(expected(secret, 1, size))
        assertThat(KeyDerivation.macKey(secret, size).keyParameter().key).isEqualTo(expected(secret, 2, size))
        assertThat(KeyDerivation.passwordKey(secret, size).keyParameter().key).isEqualTo(expected(secret, 3, size))
    }

    @Test
    fun usesTheCountersOfTheSpecification() {
        // TR-03110 Part 3, A.2.3: KDF_Enc uses c = 1, KDF_MAC c = 2, KDF_pi c = 3.
        assertThat(KeyDerivation.ENCRYPTION_KEY_COUNTER).isEqualTo(1)
        assertThat(KeyDerivation.MAC_KEY_COUNTER).isEqualTo(2)
        assertThat(KeyDerivation.PASSWORD_KEY_COUNTER).isEqualTo(3)
    }

    private fun expected(
        secret: ByteArray,
        counter: Int,
        size: AesKey.Size,
    ): ByteArray =
        MessageDigest
            .getInstance("SHA-256")
            .digest(secret + ByteBuffer.allocate(Int.SIZE_BYTES).putInt(counter).array())
            .copyOf(size.bytes)
}
