package com.xignsys.pace

import com.xignsys.pace.apdu.CommandApdu
import com.xignsys.pace.internal.securemessaging.SecureMessaging
import java.io.IOException

/**
 * The PACE Secure Messaging channel to the card, from a successful [Pace.establish]: protects every command with the
 * PACE session keys and checks and unprotects every response (TR-03110 Part 3, F; ICAO 9303-11, section 9.8).
 *
 * The rules are fixed: a response without Secure Messaging data objects is never passed on; the MAC is verified before
 * anything is decrypted, and the status word after the MAC must equal the protected one; the response data objects
 * must be exactly `[87] 99 8E` in DER; a command keeps its length form, with the new `Le` `00` or `00 00` and its own
 * `Le` in `97`.
 *
 * The channel ends with [handOver] or [close], for good: nothing is sent unprotected through it after PACE. It also
 * ends when a second PACE run through it succeeds (`Pace.establish` with this channel), whose channel replaces it. The
 * send sequence counter starts at 0. Not thread-safe.
 */
public class SecureMessagingChannel internal constructor(
    internal val transport: CardTransport,
    internal val secureMessaging: SecureMessaging,
) : AutoCloseable {
    private var state = State.OPEN

    /** Whether commands can still be sent: neither [handOver] nor [close] has been called, and no command failed. */
    public val isOpen: Boolean
        get() = state == State.OPEN

    /**
     * Protects [command], sends it and returns the card's checked and unprotected response.
     *
     * A command that cannot be protected is [SecureMessagingResult.Refused]: nothing is sent and the channel stays
     * open. A response that does not pass Secure Messaging is [SecureMessagingResult.Failed]: the channel is closed and
     * the keys are overwritten.
     *
     * @throws IOException if the transport throws it; the channel is closed first, because the card and the library no
     *   longer agree on the send sequence counter.
     * @throws IllegalStateException if the channel is no longer open.
     */
    @Throws(IOException::class)
    public fun transceive(command: CommandApdu): SecureMessagingResult {
        check(isOpen) { "The Secure Messaging channel has been closed or handed over." }

        secureMessaging.refusal(command)?.let { return it }

        val protectedCommand = secureMessaging.protect(command).encode()
        val encoded =
            try {
                transport.transceive(protectedCommand)
            } catch (failure: Throwable) {
                close()

                throw failure
            }
        val response = secureMessaging.unprotect(encoded)

        if (response == null) {
            close()

            return SecureMessagingResult.Failed
        }

        return SecureMessagingResult.Response(response)
    }

    /**
     * Ends Secure Messaging without sending anything: overwrites the keys and returns the transport PACE ran on, for
     * example for commands that another protocol protects end to end. The card keeps its Secure Messaging session until
     * it receives a command without Secure Messaging (TR-03110 Part 3, F.1 and F.6).
     *
     * @throws IllegalStateException if the channel is no longer open.
     */
    public fun handOver(): CardTransport {
        check(isOpen) { "The Secure Messaging channel has been closed or handed over." }

        secureMessaging.destroy()
        state = State.HANDED_OVER

        return transport
    }

    /** Overwrites the keys and ends the channel. Has no effect once the channel is no longer open. */
    override fun close() {
        if (state == State.OPEN) {
            secureMessaging.destroy()
            state = State.CLOSED
        }
    }

    override fun toString(): String = "SecureMessagingChannel($state)"

    private enum class State { OPEN, HANDED_OVER, CLOSED }
}
