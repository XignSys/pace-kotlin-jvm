package com.xignsys.pace.internal.crypto

import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.assertj.core.api.Assertions.assertThatIllegalStateException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

/** AES-CBC without padding (TR-03110 Part 3, A.3.3 and F.4.2.1). */
class AesCbcTest {
    @Test
    fun encryptsTheNistCbcExample() {
        val cbc = AesCbc(AesKey.takeOver(hex(NIST_KEY)))

        // NIST SP 800-38A, F.2.1 CBC-AES128.Encrypt
        assertThat(cbc.encrypt(hex(NIST_IV), hex(NIST_PLAINTEXT))).isEqualTo(hex(NIST_CBC_CIPHERTEXT))
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(
        // NIST SP 800-38A, F.2.3 CBC-AES192.Encrypt and F.2.5 CBC-AES256.Encrypt, same IV and plaintext as F.2.1.
        "F.2.3, 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b, " +
            "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a" +
            "571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
        "F.2.5, 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4, " +
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d" +
            "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
    )
    fun encryptsAndDecryptsTheNistCbcExamplesWithLongerKeys(
        section: String,
        key: String,
        ciphertext: String,
    ) {
        // TR-03110 Part 3, F.4.2.1: AES-192 and AES-256 encrypt in CBC mode like AES-128.
        val cbc = AesCbc(AesKey.takeOver(hex(key)))

        assertThat(cbc.encrypt(hex(NIST_IV), hex(NIST_PLAINTEXT))).`as`(section).isEqualTo(hex(ciphertext))
        assertThat(cbc.decrypt(hex(NIST_IV), hex(ciphertext))).`as`(section).isEqualTo(hex(NIST_PLAINTEXT))
    }

    @Test
    fun decryptsTheNistCbcExample() {
        val cbc = AesCbc(AesKey.takeOver(hex(NIST_KEY)))

        // NIST SP 800-38A, F.2.2 CBC-AES128.Decrypt
        assertThat(cbc.decrypt(hex(NIST_IV), hex(NIST_CBC_CIPHERTEXT))).isEqualTo(hex(NIST_PLAINTEXT))
    }

    @Test
    fun usesTheNewIvOfEveryCallWithTheSameKey() {
        val cbc = AesCbc(AesKey.takeOver(hex(NIST_KEY)))
        val plaintext = hex(NIST_PLAINTEXT)
        val ciphertext = hex(NIST_CBC_CIPHERTEXT)

        cbc.encrypt(hex(NIST_IV), plaintext)

        // NIST SP 800-38A, F.2.1: in CBC mode, the second ciphertext block is the encryption of the second plaintext
        // block with the first ciphertext block as IV.
        assertThat(cbc.encrypt(ciphertext.copyOfRange(0, 16), plaintext.copyOfRange(16, 32)))
            .isEqualTo(ciphertext.copyOfRange(16, 32))
        assertThat(cbc.decrypt(ciphertext.copyOfRange(16, 32), ciphertext.copyOfRange(32, 48)))
            .isEqualTo(plaintext.copyOfRange(32, 48))
    }

    @Test
    fun encryptsSingleBlocksLikeTheNistEcbExample() {
        val cbc = AesCbc(AesKey.takeOver(hex(NIST_KEY)))
        val plaintext = hex(NIST_PLAINTEXT)
        val expected = hex(NIST_ECB_CIPHERTEXT)

        // NIST SP 800-38A, F.1.1 ECB-AES128.Encrypt: each block is encrypted with the key alone.
        for (offset in plaintext.indices step AesCbc.BLOCK_SIZE) {
            assertThat(cbc.encryptBlock(plaintext.copyOfRange(offset, offset + AesCbc.BLOCK_SIZE)))
                .isEqualTo(expected.copyOfRange(offset, offset + AesCbc.BLOCK_SIZE))
        }
    }

    @Test
    fun decryptsTheEncryptedPaceNonceOfTheIcaoExample() {
        // ICAO 9303-11, Appendix G.1: z is the nonce s encrypted with K_pi in CBC mode with IV = 0 (TR-03110 Part 3,
        // A.3.3).
        val cbc = AesCbc(AesKey.takeOver(hex("89DED1B2 6624EC1E 634C1989 302849DD")))

        assertThat(cbc.decrypt(ByteArray(AesCbc.BLOCK_SIZE), hex("95A3A016 522EE98D 01E76CB6 B98B42C3")))
            .isEqualTo(hex("3F00C4D3 9D153F2B 2A214A07 8D899B22"))
    }

    @Test
    fun processesEmptyData() {
        val cbc = AesCbc(AesKey.takeOver(hex(NIST_KEY)))

        assertThat(cbc.encrypt(hex(NIST_IV), ByteArray(0))).isEmpty()
    }

    @Test
    fun rejectsDataThatIsNotWholeBlocks() {
        val cbc = AesCbc(AesKey.takeOver(hex(NIST_KEY)))

        assertThatIllegalArgumentException().isThrownBy { cbc.encrypt(hex(NIST_IV), ByteArray(15)) }
        assertThatIllegalArgumentException().isThrownBy { cbc.decrypt(hex(NIST_IV), ByteArray(17)) }
        assertThatIllegalArgumentException().isThrownBy { cbc.encryptBlock(ByteArray(32)) }
    }

    @Test
    fun rejectsAnIvThatIsNotOneBlock() {
        val cbc = AesCbc(AesKey.takeOver(hex(NIST_KEY)))

        assertThatIllegalArgumentException().isThrownBy { cbc.encrypt(ByteArray(8), ByteArray(16)) }
    }

    @Test
    fun destroyOverwritesTheKeyAndBlocksFurtherUse() {
        val key = AesKey.takeOver(hex(NIST_KEY))
        val keyBytes = key.keyParameter().key
        val cbc = AesCbc(key)

        cbc.encrypt(hex(NIST_IV), hex(NIST_PLAINTEXT))
        cbc.destroy()

        assertThat(keyBytes).containsOnly(0)
        assertThatIllegalStateException().isThrownBy { cbc.encrypt(hex(NIST_IV), hex(NIST_PLAINTEXT)) }
        assertThatIllegalStateException().isThrownBy { cbc.decrypt(hex(NIST_IV), hex(NIST_CBC_CIPHERTEXT)) }
    }

    private companion object {
        /** NIST SP 800-38A, F.1.1 and F.2.1: the AES-128 key. */
        const val NIST_KEY = "2b7e1516 28aed2a6 abf71588 09cf4f3c"

        /** NIST SP 800-38A, F.2.1: the initialization vector. */
        const val NIST_IV = "00010203 04050607 08090a0b 0c0d0e0f"

        /** NIST SP 800-38A, F.1.1 and F.2.1: the four plaintext blocks. */
        const val NIST_PLAINTEXT =
            "6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 " +
                "30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710"

        /** NIST SP 800-38A, F.2.1: the ciphertext. */
        const val NIST_CBC_CIPHERTEXT =
            "7649abac 8119b246 cee98e9b 12e9197d 5086cb9b 507219ee 95db113a 917678b2 " +
                "73bed6b8 e3c1743b 7116e69e 22229516 3ff1caa1 681fac09 120eca30 7586e1a7"

        /** NIST SP 800-38A, F.1.1: the ciphertext. */
        const val NIST_ECB_CIPHERTEXT =
            "3ad77bb4 0d7a3660 a89ecaf3 2466ef97 f5d3d585 03b9699d e785895a 96fdbaaf " +
                "43b1cd7f 598ece23 881b00e3 ed030688 7b0c785e 27e8ad3f 82232071 04725dd4"
    }
}
