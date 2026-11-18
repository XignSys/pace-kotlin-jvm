package com.xignsys.pace.internal.pace

import com.xignsys.pace.PaceResult.Failed
import com.xignsys.pace.PaceResult.Failed.PasswordNotUsable.State
import com.xignsys.pace.PaceStep
import com.xignsys.pace.apdu.StatusWord

/**
 * The status words of the PACE commands other than `90 00` (TR-03110 Part 3, B.14.1 for MSE:Set AT, B.14.2 for General
 * Authenticate) and what they mean for a run.
 */
internal object PaceStatusWords {
    /** SW1 of `63 CX` (B.14.1, B.14.2). */
    private const val SW1_WARNING = 0x63

    /** The high nibble of SW2 of `63 CX`, whose low nibble X is the number of verification tries left. */
    private const val SW2_COUNTER = 0xC0
    private const val HIGH_NIBBLE = 0xF0
    private const val LOW_NIBBLE = 0x0F

    /** X of `63 CX` for a suspended password (B.14.1, B.14.2; TR-03110 Part 2, section 2.2.3). */
    private const val TRIES_SUSPENDED = 1

    /** X of `63 CX` for a blocked password (B.14.1, B.14.2; TR-03110 Part 2, section 2.2.3). */
    private const val TRIES_BLOCKED = 0

    /** General Authenticate: authentication failed, without a retry counter (B.14.2). */
    private val AUTHENTICATION_FAILED = StatusWord(0x6300)

    /** MSE:Set AT: the password is deactivated (B.14.1). */
    private val DEACTIVATED_WARNING = StatusWord(0x6283)

    /** General Authenticate: the password is blocked (B.14.2). */
    private val BLOCKED = StatusWord(0x6983)

    /** General Authenticate: the password is deactivated (B.14.2). */
    private val DEACTIVATED = StatusWord(0x6984)

    /** General Authenticate: the password is suspended (B.14.2). */
    private val SUSPENDED = StatusWord(0x6985)

    /**
     * What the answer [statusWord] to [step] means: `null` if the run goes on, otherwise the failure that ends it.
     *
     * MSE:Set AT goes on with `90 00` and with the warning `63 CX` for X of 2 or more, because the card has selected
     * the password (B.14.1); `63 C0` and `62 83` end the run before General Authenticate, which the card would refuse.
     * So does `63 C1`, unless the run goes [throughChannel], the open channel of an earlier run: X is the number of
     * tries left, which stays 1 until the suspended password has been entered correctly (TR-03110 Part 2, section
     * 2.2.3), so a card whose password the earlier run has temporarily resumed (section 2.4.1) still answers `63 C1`,
     * and the run goes on. A card that has not resumed the password refuses General Authenticate. A General
     * Authenticate step goes on with `90 00` only.
     */
    fun failure(
        step: PaceStep,
        statusWord: StatusWord,
        throughChannel: Boolean,
    ): Failed? {
        if (statusWord == StatusWord.NO_ERROR) {
            return null
        }

        val tries = remainingTries(statusWord)

        if (step == PaceStep.SET_AUTHENTICATION_TEMPLATE) {
            return when {
                tries == TRIES_SUSPENDED && !throughChannel -> Failed.PasswordNotUsable(step, State.SUSPENDED)
                tries == TRIES_BLOCKED -> Failed.PasswordNotUsable(step, State.BLOCKED)
                tries != null -> null
                statusWord == DEACTIVATED_WARNING -> Failed.PasswordNotUsable(step, State.DEACTIVATED)
                else -> Failed.CardError(step, statusWord)
            }
        }

        return when {
            tries != null -> Failed.AuthenticationFailed(step, tries)
            statusWord == AUTHENTICATION_FAILED -> Failed.AuthenticationFailed(step, null)
            statusWord == SUSPENDED -> Failed.PasswordNotUsable(step, State.SUSPENDED)
            statusWord == BLOCKED -> Failed.PasswordNotUsable(step, State.BLOCKED)
            statusWord == DEACTIVATED -> Failed.PasswordNotUsable(step, State.DEACTIVATED)
            else -> Failed.CardError(step, statusWord)
        }
    }

    /** X of `63 CX`, or `null` for any other status word. */
    private fun remainingTries(statusWord: StatusWord): Int? =
        if (statusWord.sw1 == SW1_WARNING && statusWord.sw2 and HIGH_NIBBLE == SW2_COUNTER) {
            statusWord.sw2 and LOW_NIBBLE
        } else {
            null
        }
}
