package com.xignsys.pace.apdu

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test

/** Status words `SW1 SW2` (ISO/IEC 7816-4, section 5.6). */
class StatusWordTest {
    @Test
    fun namesNormalProcessing() {
        // ICAO 9303-10, section 3.6, Table 1: '9000' normal processing.
        assertThat(StatusWord.NO_ERROR.value).isEqualTo(0x9000)
        assertThat(StatusWord.NO_ERROR.sw1).isEqualTo(0x90)
        assertThat(StatusWord.NO_ERROR.sw2).isEqualTo(0x00)
    }

    @Test
    fun isBuiltFromItsTwoBytes() {
        assertThat(StatusWord.of(0x69, 0x82)).isEqualTo(StatusWord(0x6982))
        assertThat(StatusWord.of(0x69, 0x82).hashCode()).isEqualTo(StatusWord(0x6982).hashCode())
        assertThat(StatusWord(0x6982)).isNotEqualTo(StatusWord(0x6988))
    }

    @Test
    fun limitsStatusWordsToTwoBytes() {
        assertThatIllegalArgumentException().isThrownBy { StatusWord(0x10000) }
        assertThatIllegalArgumentException().isThrownBy { StatusWord(-1) }
        assertThatIllegalArgumentException().isThrownBy { StatusWord.of(0x100, 0x00) }
        assertThatIllegalArgumentException().isThrownBy { StatusWord.of(0x90, -1) }
    }

    @Test
    fun showsFourHexadecimalDigits() {
        assertThat(StatusWord(0x6A80).toString()).isEqualTo("StatusWord(6A80)")
        assertThat(StatusWord(0x0001).toString()).isEqualTo("StatusWord(0001)")
    }
}
