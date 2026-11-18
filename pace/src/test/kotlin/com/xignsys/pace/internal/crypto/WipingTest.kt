package com.xignsys.pace.internal.crypto

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test

class WipingTest {
    @Test
    fun wipesByteArrays() {
        val bytes = ByteArray(8) { (it + 1).toByte() }

        bytes.wipe()

        assertThat(bytes).containsOnly(0)
    }

    @Test
    fun wipesCharArrays() {
        val chars = "123456".toCharArray()

        chars.wipe()

        assertThat(chars).containsOnly(Char.MIN_VALUE)
    }

    @Test
    fun comparesArrays() {
        assertThat(constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3))).isTrue()
        assertThat(constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 4))).isFalse()
        assertThat(constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2))).isFalse()
        assertThat(constantTimeEquals(ByteArray(0), ByteArray(0))).isTrue()
    }

    @Test
    fun overwritesARefusedArrayBeforeItThrows() {
        val accepted = "123456".toCharArray()
        val refused = "123456".toCharArray()

        accepted.requireOrWipe(true) { "not thrown" }

        assertThatIllegalArgumentException()
            .isThrownBy { refused.requireOrWipe(false) { "refused" } }
            .withMessage("refused")
        assertThat(accepted).containsExactly(*"123456".toCharArray())
        assertThat(refused).containsOnly(Char.MIN_VALUE)
    }
}
