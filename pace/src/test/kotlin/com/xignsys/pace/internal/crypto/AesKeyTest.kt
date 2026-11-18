package com.xignsys.pace.internal.crypto

import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.assertj.core.api.Assertions.assertThatIllegalStateException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class AesKeyTest {
    @Test
    fun takesOverTheKeyAndOverwritesTheSource() {
        val source = hex(KEY)
        val key = AesKey.takeOver(source)

        assertThat(source).containsOnly(0)
        assertThat(key.keyParameter().key).isEqualTo(hex(KEY))
    }

    @ParameterizedTest
    @ValueSource(ints = [16, 24, 32])
    fun takesTheKeySizesOfPace(length: Int) {
        // TR-03110 Part 3, A.2.3.2: AES-128, AES-192 and AES-256.
        val key = AesKey.takeOver(ByteArray(length) { 1 })

        assertThat(key.keyParameter().key).hasSize(length)
        assertThat(AesKey.Size.entries.map { it.bytes }).containsExactly(16, 24, 32)
    }

    @ParameterizedTest
    @ValueSource(ints = [1, 8, 15, 17, 20, 31, 33, 64])
    fun rejectsOtherLengthsAndStillOverwritesThem(length: Int) {
        val source = ByteArray(length) { 1 }

        assertThatIllegalArgumentException()
            .isThrownBy { AesKey.takeOver(source) }
            .withMessage("An AES key has 16, 24 or 32 bytes, got $length.")
        assertThat(source).containsOnly(0)
    }

    @Test
    fun destroyOverwritesTheKey() {
        val key = AesKey.takeOver(hex(KEY))
        val keyBytes = key.keyParameter().key

        key.destroy()
        key.destroy()

        assertThat(keyBytes).containsOnly(0)
        assertThat(key.isDestroyed).isTrue()
        assertThatIllegalStateException().isThrownBy { key.keyParameter() }
    }

    @Test
    fun toStringShowsNoKeyMaterial() {
        val key = AesKey.takeOver(hex(KEY))

        assertThat(key.toString()).isEqualTo("AesKey(destroyed=false)")
    }

    private companion object {
        const val KEY = "00112233 44556677 8899aabb ccddeeff"
    }
}
