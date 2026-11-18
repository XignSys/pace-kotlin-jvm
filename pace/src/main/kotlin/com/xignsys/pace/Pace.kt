package com.xignsys.pace

import com.xignsys.pace.cardaccess.CardAccess
import com.xignsys.pace.cardaccess.PaceInfo
import com.xignsys.pace.internal.pace.ImplementedPace
import com.xignsys.pace.internal.pace.PaceTerminal
import java.io.IOException
import java.security.SecureRandom

/**
 * Password Authenticated Connection Establishment (PACE) as the terminal (TR-03110 Part 2, section 3.2, and Part 3, A.3
 * and B.1; ICAO 9303-11, section 4.4).
 */
public object Pace {
    /** The largest domain parameter ID that the one byte of data object `84` in MSE:Set AT holds. */
    private const val MAX_ONE_BYTE_ID = 0xFF

    /**
     * Runs PACE with the card behind [transport]: MSE:Set AT, then the four General Authenticate steps.
     *
     * Before anything is sent, [parameters] are checked against what the library implements and against [cardAccess],
     * the card's EF.CardAccess: the result is [PaceResult.Failed.ParametersNotSupported] if the library does not
     * implement them or the card offers them only in a `PACEInfo` version other than 2, and
     * [PaceResult.Failed.ParametersNotOffered] if [cardAccess] has no `PACEInfo` with them. Today the library
     * implements PACE with ECDH, Generic Mapping or Chip Authentication Mapping and AES-128, AES-192 or AES-256 on the
     * standardized domain parameters with the Brainpool curves of RFC 5639 and the NIST curves of RFC 5114: IDs 8 to 18
     * of TR-03110 Part 3, Table 4.
     *
     * A domain parameter ID of 32 or more names explicit domain parameters, a `PACEDomainParameterInfo` of [cardAccess]
     * with that ID. EF.CardAccess is not protected, and a terminal must not use explicit domain parameters it does not
     * know to be secure (TR-03110 Part 3, A.2.1.3; ICAO 9303-11, section 9.2.2): they are used only if they are one of
     * the curves above, given explicitly (`id-ecPublicKey` with `ECParameters` and an uncompressed generator, ICAO
     * 9303-11, sections 4.4.3.2 and 9.5.2), and PACE then runs on the library's copy of that curve. Other explicit
     * parameters, and IDs above 255, which the one byte of data object `84` in MSE:Set AT cannot hold, are
     * [PaceResult.Failed.ParametersNotSupported]; an ID without a `PACEDomainParameterInfo` is
     * [PaceResult.Failed.ParametersNotOffered]. A `PACEInfo` without an ID cannot be chosen. With Chip Authentication
     * Mapping, [PaceResult.Established.chipAuthentication] holds the Chip Authentication Data to verify against the
     * chip's static public key, together with Passive Authentication (ICAO 9303-11, section 4.4.3.5.2).
     *
     * The characters of [password] are overwritten when this call ends, whatever its outcome (see [PacePassword]). The
     * ephemeral key pairs are drawn from [random]. Every secret value is overwritten or dropped as soon as it is no
     * longer needed; only the session keys remain, in the [SecureMessagingChannel] of [PaceResult.Established].
     *
     * The status words of TR-03110 Part 3, B.14.1 and B.14.2, are reported as follows: `63 CX` at MSE:Set AT with X of
     * 2 or more is a warning, and PACE goes on; `63 C1`, `63 C0` and `62 83` at MSE:Set AT, and `69 85`, `69 83` and
     * `69 84` at General Authenticate, are [PaceResult.Failed.PasswordNotUsable]; `63 00` and `63 CX` at General
     * Authenticate are [PaceResult.Failed.AuthenticationFailed]; any other is [PaceResult.Failed.CardError]. Through
     * a channel, `63 C1` at MSE:Set AT is a warning as well (see the other [establish]).
     *
     * @throws IOException if [transport] throws it; it is passed on unchanged after every secret has been overwritten.
     * @throws IllegalStateException with the message "The password has been wiped or already used for PACE." if
     *   [password] has been wiped or used; nothing is sent.
     */
    @JvmStatic
    @JvmOverloads
    @Throws(IOException::class)
    public fun establish(
        transport: CardTransport,
        cardAccess: CardAccess,
        parameters: PaceParameters,
        password: PacePassword,
        random: SecureRandom = SecureRandom(),
    ): PaceResult = run(cardAccess, parameters, password) { PaceTerminal(transport, random) }

    /**
     * Runs PACE through [channel], the open channel of an earlier run: every command of this run is protected with the
     * keys of [channel]. TR-03110 Part 2, sections 2.4.1 and 3.2.2, uses such a second run to resume a suspended PIN or
     * PUK ([PaceResult.Failed.PasswordNotUsable.State.SUSPENDED]): first PACE with the CAN, then PACE with the PIN or
     * the PUK through the channel of the first run. The card decides whether it accepts the second run.
     *
     * The checks and results are those of the other [establish], plus [PaceResult.Failed.SecureMessagingFailed], with
     * one difference: `63 C1` at MSE:Set AT is a warning, and PACE goes on. The retry counter stays 1 until the
     * suspended password has been entered correctly (TR-03110 Part 2, section 2.2.3), so the card still reports it
     * after the first run has temporarily resumed the password (section 2.4.1). A card that has not resumed the
     * password refuses General Authenticate, with `69 85` for [PaceResult.Failed.PasswordNotUsable]. On
     * [PaceResult.Established], [channel] is closed and its keys are overwritten, and the new channel uses the new
     * session keys with the send sequence counter 0 (TR-03110 Part 3, F.5). On any other result [channel] stays open
     * with its keys, as the card continues with them (Part 2, section 3.2.2), except after a response that failed
     * Secure Messaging, which closes it.
     *
     * @throws IOException if the transport of [channel] throws it; [channel] is closed, and the exception is passed on
     *   unchanged after every secret has been overwritten.
     * @throws IllegalStateException with the message "The password has been wiped or already used for PACE." if
     *   [password] has been wiped or used, or with the message "The Secure Messaging channel has been closed or handed
     *   over." if [channel] is no longer open; nothing is sent, and [password] is overwritten.
     */
    @JvmStatic
    @JvmOverloads
    @Throws(IOException::class)
    public fun establish(
        channel: SecureMessagingChannel,
        cardAccess: CardAccess,
        parameters: PaceParameters,
        password: PacePassword,
        random: SecureRandom = SecureRandom(),
    ): PaceResult =
        run(cardAccess, parameters, password) {
            check(channel.isOpen) { "The Secure Messaging channel has been closed or handed over." }

            PaceTerminal(channel.transport, random, channel)
        }

    private inline fun run(
        cardAccess: CardAccess,
        parameters: PaceParameters,
        password: PacePassword,
        terminal: () -> PaceTerminal,
    ): PaceResult {
        try {
            // No password accepts MIN_VALUE, the value its characters are overwritten with when it is wiped or used.
            check(password.characters[0] != Char.MIN_VALUE) { "The password has been wiped or already used for PACE." }

            val paceTerminal = terminal()
            val id = parameters.domainParameterId
            val standardized = id in PaceInfo.STANDARDIZED_DOMAIN_PARAMETER_IDS

            if (!ImplementedPace.implements(parameters.protocol) ||
                (standardized && !ImplementedPace.supports(parameters.protocol, id)) ||
                // TR-03110 Part 3, B.14.1, does not say how 84 encodes an ID that does not fit one byte.
                id > MAX_ONE_BYTE_ID
            ) {
                return PaceResult.Failed.ParametersNotSupported
            }

            val paceInfo = cardAccess.paceInfo(parameters.protocol, id) ?: return PaceResult.Failed.ParametersNotOffered

            if (paceInfo.version != ImplementedPace.VERSION) {
                return PaceResult.Failed.ParametersNotSupported
            }

            val domain =
                if (standardized) {
                    checkNotNull(ImplementedPace.domain(id))
                } else {
                    val info =
                        cardAccess.paceDomainParameterInfos.firstOrNull { it.parameterId == id }
                            ?: return PaceResult.Failed.ParametersNotOffered

                    ImplementedPace.explicitDomain(info) ?: return PaceResult.Failed.ParametersNotSupported
                }

            return paceTerminal.establish(parameters, password, domain)
        } finally {
            password.wipe()
        }
    }
}
