package com.xignsys.pace

import com.xignsys.pace.PaceResult.Failed
import com.xignsys.pace.PaceResult.Failed.PasswordNotUsable
import com.xignsys.pace.PaceResult.Failed.PasswordNotUsable.State
import com.xignsys.pace.apdu.StatusWord
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** The failure cases of PACE: equality by value and readable names. */
class PaceResultTest {
    @Test
    fun comparesFailuresByValue() {
        assertThat(Failed.CardError(PaceStep.MAP_NONCE, StatusWord(0x6300)))
            .isEqualTo(Failed.CardError(PaceStep.MAP_NONCE, StatusWord(0x6300)))
            .hasSameHashCodeAs(Failed.CardError(PaceStep.MAP_NONCE, StatusWord(0x6300)))
            .isNotEqualTo(Failed.CardError(PaceStep.MAP_NONCE, StatusWord(0x6A80)))
            .isNotEqualTo(Failed.CardError(PaceStep.KEY_AGREEMENT, StatusWord(0x6300)))
        assertThat(Failed.MalformedResponse(PaceStep.MAP_NONCE))
            .isEqualTo(Failed.MalformedResponse(PaceStep.MAP_NONCE))
            .isNotEqualTo(Failed.InvalidChipKey(PaceStep.MAP_NONCE))
        assertThat(Failed.InvalidChipKey(PaceStep.KEY_AGREEMENT))
            .isEqualTo(Failed.InvalidChipKey(PaceStep.KEY_AGREEMENT))
            .hasSameHashCodeAs(Failed.InvalidChipKey(PaceStep.KEY_AGREEMENT))
        assertThat(Failed.AuthenticationFailed(PaceStep.MUTUAL_AUTHENTICATION, 2))
            .isEqualTo(Failed.AuthenticationFailed(PaceStep.MUTUAL_AUTHENTICATION, 2))
            .hasSameHashCodeAs(Failed.AuthenticationFailed(PaceStep.MUTUAL_AUTHENTICATION, 2))
            .isNotEqualTo(Failed.AuthenticationFailed(PaceStep.MUTUAL_AUTHENTICATION, null))
            .isNotEqualTo(Failed.AuthenticationFailed(PaceStep.KEY_AGREEMENT, 2))
        assertThat(PasswordNotUsable(PaceStep.SET_AUTHENTICATION_TEMPLATE, State.SUSPENDED))
            .isEqualTo(PasswordNotUsable(PaceStep.SET_AUTHENTICATION_TEMPLATE, State.SUSPENDED))
            .hasSameHashCodeAs(PasswordNotUsable(PaceStep.SET_AUTHENTICATION_TEMPLATE, State.SUSPENDED))
            .isNotEqualTo(PasswordNotUsable(PaceStep.SET_AUTHENTICATION_TEMPLATE, State.BLOCKED))
            .isNotEqualTo(PasswordNotUsable(PaceStep.ENCRYPTED_NONCE, State.SUSPENDED))
        assertThat(Failed.SecureMessagingFailed(PaceStep.MAP_NONCE))
            .isEqualTo(Failed.SecureMessagingFailed(PaceStep.MAP_NONCE))
            .hasSameHashCodeAs(Failed.SecureMessagingFailed(PaceStep.MAP_NONCE))
            .isNotEqualTo(Failed.SecureMessagingFailed(PaceStep.KEY_AGREEMENT))
    }

    @Test
    fun namesTheCaseTheStepAndTheStatusWord() {
        assertThat(Failed.CardError(PaceStep.MUTUAL_AUTHENTICATION, StatusWord(0x6300)).toString())
            .isEqualTo("CardError(MUTUAL_AUTHENTICATION, StatusWord(6300))")
        assertThat(Failed.MalformedResponse(PaceStep.ENCRYPTED_NONCE).toString())
            .isEqualTo("MalformedResponse(ENCRYPTED_NONCE)")
        assertThat(Failed.InvalidChipKey(PaceStep.MAP_NONCE).toString()).isEqualTo("InvalidChipKey(MAP_NONCE)")
        assertThat(Failed.AuthenticationFailed(PaceStep.MUTUAL_AUTHENTICATION, null).toString())
            .isEqualTo("AuthenticationFailed(MUTUAL_AUTHENTICATION, remainingTries=null)")
        assertThat(PasswordNotUsable(PaceStep.SET_AUTHENTICATION_TEMPLATE, State.DEACTIVATED).toString())
            .isEqualTo("PasswordNotUsable(SET_AUTHENTICATION_TEMPLATE, DEACTIVATED)")
        assertThat(Failed.SecureMessagingFailed(PaceStep.KEY_AGREEMENT).toString())
            .isEqualTo("SecureMessagingFailed(KEY_AGREEMENT)")
        assertThat(Failed.InvalidChipToken.toString()).isEqualTo("InvalidChipToken")
        assertThat(Failed.ParametersNotOffered.toString()).isEqualTo("ParametersNotOffered")
        assertThat(Failed.ParametersNotSupported.toString()).isEqualTo("ParametersNotSupported")
    }
}
