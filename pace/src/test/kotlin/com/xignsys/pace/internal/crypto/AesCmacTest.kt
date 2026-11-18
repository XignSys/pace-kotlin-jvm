package com.xignsys.pace.internal.crypto

import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalStateException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource

/**
 * AES-CMAC with an 8-byte MAC (TR-03110 Part 3, A.2.4.2 and F.4.2.2). Expected values: RFC 4493, section 4 (AES-128
 * examples 1 to 4), and the NIST example values "Block Cipher Modes of Operation, CMAC Mode for Authentication",
 * sections CMAC-AES192 and CMAC-AES256 (examples 1 to 4 each), truncated to the leftmost 8 bytes as NIST SP 800-38B,
 * section 5.4 defines it.
 */
class AesCmacTest {
    @ParameterizedTest(name = "RFC 4493 example with {0} bytes")
    @CsvSource(
        "0, bb1d6929e95937287fa37d129b756746",
        "16, 070a16b46b4d4144f79bdd9dd04a287c",
        "40, dfa66747de9ae63030ca32611497c827",
        "64, 51f0bebf7e3b9d92fc49741779363cfe",
    )
    fun computesTheTruncatedRfc4493Mac(length: Int, fullMac: String) {
        val cmac = AesCmac(AesKey.takeOver(hex(RFC_4493_KEY)))

        assertThat(cmac.mac(hex(RFC_4493_MESSAGE).copyOf(length))).isEqualTo(hex(fullMac).copyOf(AesCmac.MAC_LENGTH))
    }

    @ParameterizedTest(name = "AES-{0} example with {1} bytes")
    @CsvSource(
        // NIST example values, CMAC-AES192 and CMAC-AES256, examples 1 to 4: the messages are prefixes of the RFC 4493
        // message; the third example has 20 bytes, not the 40 of RFC 4493.
        "192, 0, d17ddf46adaacde531cac483de7a9367",
        "192, 16, 9e99a7bf31e710900662f65e617c5184",
        "192, 20, 3d75c194ed96070444a9fa7ec740ecf8",
        "192, 64, a1d5df0eed790f794d77589659f39a11",
        "256, 0, 028962f61b7bf89efc6b551f4667d983",
        "256, 16, 28a7023f452e8f82bd4bf28d8c37c35c",
        "256, 20, 156727dc0878944a023c1fe03bad6d93",
        "256, 64, e1992190549f6ed5696a2c056c315410",
    )
    fun computesTheTruncatedNistMacWithLongerKeys(
        bits: Int,
        length: Int,
        fullMac: String,
    ) {
        // TR-03110 Part 3, A.2.4.2 and F.4.2.2: CMAC with an 8-byte MAC for every AES key size.
        val key = if (bits == 192) NIST_AES_192_KEY else NIST_AES_256_KEY
        val cmac = AesCmac(AesKey.takeOver(hex(key)))

        assertThat(cmac.mac(hex(RFC_4493_MESSAGE).copyOf(length))).isEqualTo(hex(fullMac).copyOf(AesCmac.MAC_LENGTH))
    }

    @Test
    fun macOverSeveralPartsEqualsTheMacOverTheirConcatenation() {
        val cmac = AesCmac(AesKey.takeOver(hex(RFC_4493_KEY)))
        val message = hex(RFC_4493_MESSAGE).copyOf(40)

        assertThat(cmac.mac(message.copyOfRange(0, 7), message.copyOfRange(7, 40)))
            .isEqualTo(hex("dfa66747de9ae630"))
    }

    @Test
    fun theEngineIsReusableAfterAMac() {
        val cmac = AesCmac(AesKey.takeOver(hex(RFC_4493_KEY)))

        cmac.mac(hex(RFC_4493_MESSAGE))

        assertThat(cmac.mac()).isEqualTo(hex("bb1d6929e9593728"))
    }

    @Test
    fun verifiesOnlyTheCorrectMac() {
        val cmac = AesCmac(AesKey.takeOver(hex(RFC_4493_KEY)))
        val message = hex(RFC_4493_MESSAGE).copyOf(16)

        assertThat(cmac.verify(hex("070a16b46b4d4144"), message)).isTrue()
        assertThat(cmac.verify(hex("070a16b46b4d4145"), message)).isFalse()
        assertThat(cmac.verify(hex("070a16b46b4d41"), message)).isFalse()
        assertThat(cmac.verify(hex("070a16b46b4d4144f79bdd9dd04a287c"), message)).isFalse()
    }

    @Test
    fun destroyOverwritesTheKeyAndBlocksFurtherUse() {
        val key = AesKey.takeOver(hex(RFC_4493_KEY))
        val keyBytes = key.keyParameter().key
        val cmac = AesCmac(key)

        cmac.destroy()

        assertThat(keyBytes).containsOnly(0)
        assertThat(key.isDestroyed).isTrue()
        assertThatIllegalStateException().isThrownBy { cmac.mac(hex(RFC_4493_MESSAGE)) }
    }

    private companion object {
        /** NIST example values, CMAC-AES192: the key. */
        const val NIST_AES_192_KEY = "8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b"

        /** NIST example values, CMAC-AES256: the key. */
        const val NIST_AES_256_KEY = "603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4"

        /** RFC 4493, section 4: the AES-128 key K. */
        const val RFC_4493_KEY = "2b7e1516 28aed2a6 abf71588 09cf4f3c"

        /** RFC 4493, section 4: the 64-byte message of example 4; the other examples use its prefixes. */
        const val RFC_4493_MESSAGE =
            "6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51 " +
                "30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710"
    }
}
