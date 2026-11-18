package com.xignsys.pace

import com.xignsys.pace.apdu.StatusWord
import java.util.Objects

/** The outcome of one PACE run: [Established] or one of the [Failed] cases. */
public sealed class PaceResult {
    /**
     * PACE succeeded: [channel] protects every further command with the session keys, which it owns. Close the channel
     * or hand it over when it is no longer needed.
     */
    public class Established internal constructor(
        /** The Secure Messaging channel with the session keys. */
        public val channel: SecureMessagingChannel,
        chipEphemeralPublicKey: ByteArray,
        certificationAuthorityReferences: List<ByteArray>,
        /**
         * After PACE with Chip Authentication Mapping, the Chip Authentication Data to verify against the chip's
         * static public key (ICAO 9303-11, section 4.4.3.5); `null` after PACE with Generic Mapping.
         */
        public val chipAuthentication: ChipAuthenticationData?,
    ) : PaceResult() {
        private val chipKey = chipEphemeralPublicKey.copyOf()
        private val references = certificationAuthorityReferences.map { it.copyOf() }

        /**
         * A copy of the chip's ephemeral public key of the key agreement, the value of data object `84` of the third
         * General Authenticate as received: an uncompressed point for ECDH (TR-03110 Part 3, D.3.4). Terminal
         * Authentication version 2 needs it.
         */
        public val chipEphemeralPublicKey: ByteArray
            get() = chipKey.copyOf()

        /**
         * Copies of the Certification Authority References, the values of data objects `87` and `88` of the last
         * General Authenticate in card order: the most recent first, at most two (TR-03110 Part 3, B.1 and B.1.4). The
         * chip returns them when PACE runs with a CHAT, for Terminal Authentication version 2; empty if it sent none.
         *
         * Each value is given as the octets the chip returned, neither decoded nor checked. A reference is a character
         * string of at most 16 characters encoded with ISO/IEC 8859-1, in which the codes `00` to `1F` and `7F` to `9F`
         * are unassigned (TR-03110 Part 3, D.2, Table 27 and D.2.1.4); a caller that needs it as a string decodes it
         * with ISO/IEC 8859-1 and refuses those codes.
         */
        public val certificationAuthorityReferences: List<ByteArray>
            get() = references.map { it.copyOf() }

        override fun toString(): String =
            "Established(certificationAuthorityReferences=${references.size}, " +
                "chipAuthentication=${chipAuthentication != null})"
    }

    /** PACE failed; the session keys, if any, have been overwritten. */
    public sealed class Failed : PaceResult() {
        /**
         * EF.CardAccess has no `PACEInfo` with the protocol and the domain parameter ID of the parameters. Nothing was
         * sent.
         */
        public data object ParametersNotOffered : Failed()

        /**
         * The library does not implement the protocol with the domain parameter ID of the parameters, or the card
         * offers them only in a `PACEInfo` version other than 2. Nothing was sent.
         */
        public data object ParametersNotSupported : Failed()

        /**
         * The card refused the authentication in [step], a General Authenticate step, with `63 00` or with `63 CX`, X
         * being the number of verification tries left (TR-03110 Part 3, B.14.2). The usual cause is a wrong password.
         * A PIN or a PUK with X = 1 is now suspended and with X = 0 blocked (TR-03110 Part 2, section 2.2.3); the
         * CAN and the MRZ have no retry counter, so their failure is `63 00`.
         */
        public class AuthenticationFailed(
            /** The General Authenticate step the card refused. */
            public val step: PaceStep,
            /** X of `63 CX`, the verification tries left; `null` for `63 00`. */
            public val remainingTries: Int?,
        ) : Failed() {
            override fun equals(other: Any?): Boolean =
                other is AuthenticationFailed && other.step == step && other.remainingTries == remainingTries

            override fun hashCode(): Int = Objects.hash(step, remainingTries)

            override fun toString(): String = "AuthenticationFailed($step, remainingTries=$remainingTries)"
        }

        /**
         * The card cannot use the password in its [state] (TR-03110 Part 2, sections 2.2.3 and 2.4). At MSE:Set AT the
         * card selects the password but warns with `63 C1` (suspended), `63 C0` (blocked) or `62 83` (deactivated), and
         * PACE stops there (TR-03110 Part 3, B.14.1), except that a run through a [SecureMessagingChannel] goes on
         * after `63 C1`, to resume the password; in a General Authenticate step the card refuses with `69 85`
         * (suspended), `69 83` (blocked) or `69 84` (deactivated) (B.14.2). A card may answer `69 82` instead, which is
         * a [CardError], because it also means that the terminal is not authorized.
         */
        public class PasswordNotUsable(
            /** The command whose answer gave the state. */
            public val step: PaceStep,
            /** Why the password cannot be used. */
            public val state: State,
        ) : Failed() {
            /** The states in which a PIN or a PUK cannot be used (TR-03110 Part 2, sections 2.2.3 and 2.4). */
            public enum class State {
                /**
                 * One try is left. The card accepts the password again only after PACE with the CAN, followed by PACE
                 * with the password through the channel of the first run (`Pace.establish` with a
                 * [SecureMessagingChannel]; TR-03110 Part 2, sections 2.4.1 and 3.2.2).
                 */
                SUSPENDED,

                /** No try is left; the password has to be unblocked, for a PIN with the PUK (TR-03110 Part 2, 2.4). */
                BLOCKED,

                /** The PIN is deactivated; only an authenticated terminal can activate it (TR-03110 Part 2, 2.4.2). */
                DEACTIVATED,
            }

            override fun equals(other: Any?): Boolean =
                other is PasswordNotUsable && other.step == step && other.state == state

            override fun hashCode(): Int = Objects.hash(step, state)

            override fun toString(): String = "PasswordNotUsable($step, $state)"
        }

        /**
         * Only when PACE runs through a [SecureMessagingChannel]: the card's response to [step] did not pass Secure
         * Messaging, for example because the card has aborted it (TR-03110 Part 3, F.6). The channel has been closed
         * and its keys overwritten.
         */
        public class SecureMessagingFailed(
            /** The command whose response failed. */
            public val step: PaceStep,
        ) : Failed() {
            override fun equals(other: Any?): Boolean = other is SecureMessagingFailed && other.step == step

            override fun hashCode(): Int = step.hashCode()

            override fun toString(): String = "SecureMessagingFailed($step)"
        }

        /**
         * The card answered [step] with [statusWord] instead of `90 00`, and the status word is none of those of
         * [AuthenticationFailed] and [PasswordNotUsable] (TR-03110 Part 3, B.14.1 and B.14.2).
         */
        public class CardError(
            /** The command the card refused. */
            public val step: PaceStep,
            /** The status word of the response. */
            public val statusWord: StatusWord,
        ) : Failed() {
            override fun equals(other: Any?): Boolean =
                other is CardError && other.step == step && other.statusWord == statusWord

            override fun hashCode(): Int = Objects.hash(step, statusWord)

            override fun toString(): String = "CardError($step, $statusWord)"
        }

        /**
         * The response to [step] is not what the step expects: no status word, not the dynamic authentication data `7C`
         * in DER with the expected data objects, or an encrypted nonce that is not a positive multiple of the block
         * size (TR-03110 Part 3, A.3.3 and B.1). A nonce longer than the group order of the domain parameters, for
         * example more than 32 bytes for brainpoolP256r1 or more than 16 bytes for brainpoolP192r1, is also reported
         * here: A.3.3 allows it, but the library does not support it.
         */
        public class MalformedResponse(
            /** The command whose response is malformed. */
            public val step: PaceStep,
        ) : Failed() {
            override fun equals(other: Any?): Boolean = other is MalformedResponse && other.step == step

            override fun hashCode(): Int = step.hashCode()

            override fun toString(): String = "MalformedResponse($step)"
        }

        /**
         * The chip's public key in [step] is not a valid point on the curve (TR-03110 Part 3, A.2.2.1), equals the
         * terminal's ephemeral public key of the key agreement (TR-03110 Part 2, section 3.2.1; ICAO 9303-11, section
         * 4.4.1), or gives the point at infinity.
         */
        public class InvalidChipKey(
            /** The step with the chip's public key. */
            public val step: PaceStep,
        ) : Failed() {
            override fun equals(other: Any?): Boolean = other is InvalidChipKey && other.step == step

            override fun hashCode(): Int = step.hashCode()

            override fun toString(): String = "InvalidChipKey($step)"
        }

        /** The chip's authentication token does not match (TR-03110 Part 3, A.2.4). */
        public data object InvalidChipToken : Failed()
    }
}
