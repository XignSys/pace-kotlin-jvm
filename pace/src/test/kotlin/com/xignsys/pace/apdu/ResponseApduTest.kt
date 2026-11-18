package com.xignsys.pace.apdu

import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test

/** Response APDUs (ISO/IEC 7816-4, section 5.1) and status words (section 5.6). */
class ResponseApduTest {
    @Test
    fun parsesTheGetNonceResponseOfTheWorkedExample() {
        // Worked Example section 3.2: 7C 12 80 10 ... and 90 00.
        val response = ResponseApdu.parse(WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE_RESPONSE)

        assertThat(response.data).hasSize(0x14)
        assertThat(response.statusWord).isEqualTo(StatusWord.NO_ERROR)
        assertThat(response.encode()).isEqualTo(WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE_RESPONSE)
    }

    @Test
    fun parsesAStatusWordWithoutData() {
        val response = ResponseApdu.parse(hex("69 82"))

        assertThat(response.data).isEmpty()
        assertThat(response.statusWord).isEqualTo(StatusWord(0x6982))
    }

    @Test
    fun refusesResponsesWithoutStatusWord() {
        assertThatIllegalArgumentException().isThrownBy { ResponseApdu.parse(hex("90")) }
        assertThatIllegalArgumentException().isThrownBy { ResponseApdu.parse(ByteArray(0)) }
    }

    @Test
    fun buildsAResponse() {
        assertThat(ResponseApdu.of(hex("01 02"), StatusWord.NO_ERROR).encode()).isEqualTo(hex("01 02 90 00"))
    }

    @Test
    fun copiesTheDataInAndOut() {
        val data = hex("01 02")
        val response = ResponseApdu.of(data, StatusWord.NO_ERROR)

        data[0] = 0x7F
        response.data[1] = 0x7F

        assertThat(response.data).isEqualTo(hex("01 02"))
    }

    @Test
    fun showsNoDataInToString() {
        assertThat(ResponseApdu.parse(WorkedExample.GENERAL_AUTHENTICATE_GET_NONCE_RESPONSE).toString())
            .isEqualTo("ResponseApdu(dataLength=20, StatusWord(9000))")
    }
}
