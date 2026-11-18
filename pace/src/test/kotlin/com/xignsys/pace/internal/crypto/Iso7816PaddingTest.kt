package com.xignsys.pace.internal.crypto

import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/** Padding of ISO/IEC 7816-4 with the padding-content indicator `80` (TR-03110 Part 3, F.3.3 and Figure 4). */
class Iso7816PaddingTest {
    @Test
    fun padsToTheNextBlock() {
        assertThat(Iso7816Padding.pad(hex("0102 03"))).isEqualTo(hex("010203 80 000000000000000000000000"))
    }

    @Test
    fun addsAFullBlockToDataOfWholeBlocks() {
        val padded = Iso7816Padding.pad(ByteArray(16) { 1 })

        assertThat(padded).hasSize(32)
        assertThat(padded.copyOfRange(16, 32)).isEqualTo(hex("80 000000000000000000000000000000"))
    }

    @Test
    fun padsEmptyDataToOneBlock() {
        assertThat(Iso7816Padding.pad(ByteArray(0))).isEqualTo(hex("80 000000000000000000000000000000"))
    }

    @Test
    fun padsToAnotherBlockSize() {
        assertThat(Iso7816Padding.pad(hex("01020304 050607"), blockSize = 8)).isEqualTo(hex("01020304 05060780"))
    }

    @ParameterizedTest
    @ValueSource(ints = [0, 1, 15, 16, 17, 31])
    fun unpadReversesPad(length: Int) {
        val data = ByteArray(length) { (it + 1).toByte() }

        assertThat(Iso7816Padding.unpad(Iso7816Padding.pad(data))).isEqualTo(data)
    }

    @Test
    fun keepsZeroBytesOfTheDataBeforeThePadding() {
        assertThat(Iso7816Padding.unpad(hex("010000 80 000000000000000000000000"))).isEqualTo(hex("010000"))
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "",
            "0102 80",
            "00000000000000000000000000000000",
            "01020304050607080910111213141516",
            "01020304050607080910111213141580 00000000000000000000000000000000",
            "80000000000000000000000000000000 00000000000000000000000000000000",
            "0102030405060708091011121314 8001",
        ],
    )
    fun rejectsInvalidPadding(padded: String) {
        assertThat(Iso7816Padding.unpad(hex(padded))).isNull()
    }
}
