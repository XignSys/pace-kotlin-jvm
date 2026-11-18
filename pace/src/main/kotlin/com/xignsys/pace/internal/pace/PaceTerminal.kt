package com.xignsys.pace.internal.pace

import com.xignsys.pace.CardTransport
import com.xignsys.pace.ChipAuthenticationData
import com.xignsys.pace.PaceParameters
import com.xignsys.pace.PacePassword
import com.xignsys.pace.PaceResult
import com.xignsys.pace.PaceResult.Failed
import com.xignsys.pace.PaceStep
import com.xignsys.pace.SecureMessagingChannel
import com.xignsys.pace.SecureMessagingResult
import com.xignsys.pace.apdu.CommandApdu
import com.xignsys.pace.apdu.ResponseApdu
import com.xignsys.pace.apdu.StatusWord
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.internal.crypto.AesCbc
import com.xignsys.pace.internal.crypto.AesCmac
import com.xignsys.pace.internal.crypto.AesKey
import com.xignsys.pace.internal.crypto.EcDomain
import com.xignsys.pace.internal.crypto.KeyDerivation
import com.xignsys.pace.internal.crypto.wipe
import com.xignsys.pace.internal.securemessaging.SecureMessaging
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.math.ec.ECPoint
import java.security.SecureRandom

/**
 * PACE with ECDH and Generic Mapping through [transport], as the terminal (TR-03110 Part 3, A.3 and B.1; ICAO 9303-11,
 * section 4.4): MSE:Set AT, then the four General Authenticate steps encrypted nonce, map nonce, key agreement and
 * mutual authentication. The ephemeral key pairs are drawn from [random].
 *
 * Without [outer], the commands go to [transport] as they are. With [outer], the open channel of an earlier run on
 * [transport], they are protected by it: the second run that TR-03110 Part 2, section 3.2.2, allows to resume a
 * suspended PIN or PUK after PACE with the CAN. Every response of the run, the last one included, is checked with the
 * old keys; on success [outer] is closed and the new channel starts with the send sequence counter 0 (TR-03110 Part 3,
 * F.5). Otherwise [outer] stays open with its keys, unless a response failed Secure Messaging, which closes it.
 *
 * The cryptographic operations are those of Bouncy Castle, through `internal.crypto`; this class composes them as the
 * protocol defines.
 */
internal class PaceTerminal(
    private val transport: CardTransport,
    private val random: SecureRandom,
    private val outer: SecureMessagingChannel? = null,
) {
    /**
     * Runs PACE with [parameters] and [password] on [domain], the standardized domain parameters of [parameters] or the
     * recognized explicit ones. The caller has checked that the library implements [parameters] and that the card
     * offers them.
     *
     * The characters of [password] are overwritten as soon as `K_pi` is derived, and in any case before this function
     * returns or throws. Every other secret value is overwritten or dropped as soon as it is no longer needed; only the
     * session keys remain, owned by the channel of [PaceResult.Established].
     *
     * @throws java.io.IOException if [transport] throws it.
     */
    fun establish(
        parameters: PaceParameters,
        password: PacePassword,
        domain: EcDomain,
    ): PaceResult {
        val keySize = ImplementedPace.keySize(parameters.protocol)
        var nonceCipher: AesCbc? = null
        var nonce: ByteArray? = null
        var sharedSecret: ByteArray? = null
        var sessionKeys: PaceSessionKeys? = null
        var established = false

        try {
            nonceCipher = AesCbc(passwordKey(password, keySize))

            exchange(
                PaceStep.SET_AUTHENTICATION_TEMPLATE,
                PaceCommands.mseSetAt(
                    parameters.protocol,
                    password.reference,
                    parameters.domainParameterId,
                    parameters.chat,
                    parameters.certificateExtensions,
                ),
            )

            // Step 1: the encrypted nonce z, a positive multiple of the block size, decrypted with K_pi and IV 0
            // (A.3.3). A.3.3 sets no upper bound; a nonce longer than the group order is not supported, because Bouncy
            // Castle's multiplication for secret scalars refuses them.
            val encryptedNonce = chainedStep(PaceStep.ENCRYPTED_NONCE, DynamicAuthenticationData.ENCRYPTED_NONCE)

            if (encryptedNonce.isEmpty() ||
                encryptedNonce.size % AesCbc.BLOCK_SIZE != 0 ||
                encryptedNonce.size > domain.maxScalarLength
            ) {
                abort(Failed.MalformedResponse(PaceStep.ENCRYPTED_NONCE))
            }

            nonce = nonceCipher.decrypt(ByteArray(AesCbc.BLOCK_SIZE), encryptedNonce)
            nonceCipher.destroy()

            // Step 2: Generic Mapping, G' = [s]G + H with H from an anonymous key agreement (A.3.4.1).
            val mappingKeys = domain.generateKeyPair(random)
            val chipMappingKey =
                chainedStep(
                    PaceStep.MAP_NONCE,
                    DynamicAuthenticationData.CHIP_MAPPING_DATA,
                    DynamicAuthenticationData.TERMINAL_MAPPING_DATA to domain.encodePoint(publicPoint(mappingKeys)),
                )
            val chipMappingPoint = domain.decodePoint(chipMappingKey) ?: abort(invalidKey(PaceStep.MAP_NONCE))
            val h =
                domain.sharedPoint(privateKey(mappingKeys), chipMappingPoint) ?: abort(invalidKey(PaceStep.MAP_NONCE))
            val nonceTimesG =
                domain.multiplySecret(domain.generator, nonce)
                    ?: abort(Failed.MalformedResponse(PaceStep.ENCRYPTED_NONCE))
            val mappedDomain = domain.withGenerator(domain.add(nonceTimesG, h) ?: abort(invalidKey(PaceStep.MAP_NONCE)))

            nonce.wipe()

            // Step 3: key agreement on the mapped generator; K is the x-coordinate of the shared point (A.2.3).
            val agreementKeys = mappedDomain.generateKeyPair(random)
            val terminalPoint = publicPoint(agreementKeys)
            val terminalKey = mappedDomain.encodePoint(terminalPoint)
            val chipKey =
                chainedStep(
                    PaceStep.KEY_AGREEMENT,
                    DynamicAuthenticationData.CHIP_PUBLIC_KEY,
                    DynamicAuthenticationData.TERMINAL_PUBLIC_KEY to terminalKey,
                )
            val chipPoint = mappedDomain.decodePoint(chipKey) ?: abort(invalidKey(PaceStep.KEY_AGREEMENT))

            // TR-03110 Part 2, section 3.2.1, and ICAO 9303-11, section 4.4.1 d): the two public keys should differ.
            if (chipPoint == terminalPoint) {
                abort(invalidKey(PaceStep.KEY_AGREEMENT))
            }

            sharedSecret =
                mappedDomain.sharedSecret(privateKey(agreementKeys), chipPoint)
                    ?: abort(invalidKey(PaceStep.KEY_AGREEMENT))
            sessionKeys =
                PaceSessionKeys(
                    AesCbc(KeyDerivation.encryptionKey(sharedSecret, keySize)),
                    AesCmac(KeyDerivation.macKey(sharedSecret, keySize)),
                )
            sharedSecret.wipe()

            // Step 4: exchange and check the authentication tokens (A.2.4), with Chip Authentication Mapping also
            // decrypt the Chip Authentication Data (ICAO 9303-11, section 4.4.3.5).
            val step4 = mutualAuthentication(parameters, sessionKeys.mac, terminalKey, chipKey)
            val chipAuthentication =
                step4.encryptedChipAuthenticationData?.let { encrypted ->
                    val data =
                        EncryptedChipAuthenticationData.decrypt(
                            sessionKeys.encryption,
                            encrypted,
                            domain.maxScalarLength,
                        )
                            ?: abort(Failed.MalformedResponse(PaceStep.MUTUAL_AUTHENTICATION))

                    try {
                        ChipAuthenticationData(domain, chipMappingKey, data)
                    } finally {
                        data.wipe()
                    }
                }

            established = true
            outer?.close()

            return PaceResult.Established(
                SecureMessagingChannel(transport, SecureMessaging(sessionKeys)),
                chipKey,
                step4.references,
                chipAuthentication,
            )
        } catch (abort: Abort) {
            return abort.failure
        } finally {
            password.characters.wipe()
            nonceCipher?.destroy()
            nonce?.wipe()
            sharedSecret?.wipe()

            if (!established) {
                sessionKeys?.destroy()
            }
        }
    }

    /** `K_pi = KDF_pi(f(pi))`; the characters of [password] are overwritten. */
    private fun passwordKey(password: PacePassword, size: AesKey.Size): AesKey {
        try {
            val encoded = PasswordEncoding.encode(password)

            try {
                return KeyDerivation.passwordKey(encoded, size)
            } finally {
                encoded.wipe()
            }
        } finally {
            password.characters.wipe()
        }
    }

    /**
     * Sends one chained General Authenticate with [objects] and returns the value of the single data object
     * [expectedTag] of the response.
     */
    private fun chainedStep(
        step: PaceStep,
        expectedTag: Int,
        vararg objects: Pair<Int, ByteArray>,
    ): ByteArray {
        val single = generalAuthenticate(step, isLast = false, *objects).singleOrNull()

        if (single == null || single.first != expectedTag) {
            abort(Failed.MalformedResponse(step))
        }

        return single.second
    }

    /**
     * Step 4: sends `85`, checks `86` and returns the values of the CA references `87` and `88` as received, in card
     * order, and, with Chip Authentication Mapping, the Encrypted Chip Authentication Data `8A`, which comes last and
     * is required with it and refused without it (ICAO 9303-11, section 4.4.4, Table 4).
     */
    private fun mutualAuthentication(
        parameters: PaceParameters,
        mac: AesCmac,
        terminalKey: ByteArray,
        chipKey: ByteArray,
    ): MutualAuthentication {
        val step = PaceStep.MUTUAL_AUTHENTICATION
        val terminalToken = AuthenticationToken.compute(mac, parameters.protocol, chipKey)
        val response =
            generalAuthenticate(step, isLast = true, DynamicAuthenticationData.TERMINAL_TOKEN to terminalToken)
        val chipAuthenticationMapping = parameters.protocol.mapping == PaceProtocol.Mapping.CHIP_AUTHENTICATION
        val tags = response.map { it.first }
        val expected =
            if (chipAuthenticationMapping) {
                MUTUAL_AUTHENTICATION_RESPONSES.map {
                    it + DynamicAuthenticationData.ENCRYPTED_CHIP_AUTHENTICATION_DATA
                }
            } else {
                MUTUAL_AUTHENTICATION_RESPONSES
            }

        if (tags !in expected) {
            abort(Failed.MalformedResponse(step))
        }

        if (!AuthenticationToken.verify(mac, response.first().second, parameters.protocol, terminalKey)) {
            abort(Failed.InvalidChipToken)
        }

        val references =
            response.drop(1).filter {
                it.first !=
                    DynamicAuthenticationData.ENCRYPTED_CHIP_AUTHENTICATION_DATA
            }

        return MutualAuthentication(
            references.map { it.second },
            if (chipAuthenticationMapping) response.last().second else null,
        )
    }

    /** The CA references of step 4 and, with Chip Authentication Mapping, the Encrypted Chip Authentication Data. */
    private class MutualAuthentication(
        val references: List<ByteArray>,
        val encryptedChipAuthenticationData: ByteArray?,
    )

    private fun generalAuthenticate(
        step: PaceStep,
        isLast: Boolean,
        vararg objects: Pair<Int, ByteArray>,
    ): List<Pair<Int, ByteArray>> {
        val response =
            exchange(step, PaceCommands.generalAuthenticate(DynamicAuthenticationData.encode(*objects), isLast))

        return DynamicAuthenticationData.decode(response.data) ?: abort(Failed.MalformedResponse(step))
    }

    private fun exchange(step: PaceStep, command: CommandApdu): ResponseApdu {
        val response = if (outer == null) plainExchange(step, command) else protectedExchange(outer, step, command)

        PaceStatusWords.failure(step, response.statusWord, throughChannel = outer != null)?.let { abort(it) }

        return response
    }

    private fun plainExchange(step: PaceStep, command: CommandApdu): ResponseApdu {
        val encoded = transport.transceive(command.encode())

        if (encoded.size < StatusWord.SIZE) {
            abort(Failed.MalformedResponse(step))
        }

        return ResponseApdu.parse(encoded)
    }

    /** A refusal cannot happen: PACE commands have an even INS, the first interindustry class and short data. */
    private fun protectedExchange(
        channel: SecureMessagingChannel,
        step: PaceStep,
        command: CommandApdu,
    ): ResponseApdu =
        when (val result = channel.transceive(command)) {
            is SecureMessagingResult.Response -> result.response
            SecureMessagingResult.Failed -> abort(Failed.SecureMessagingFailed(step))
            is SecureMessagingResult.Refused -> error("A PACE command cannot be refused by Secure Messaging.")
        }

    private fun publicPoint(keys: AsymmetricCipherKeyPair): ECPoint = (keys.public as ECPublicKeyParameters).q

    private fun privateKey(keys: AsymmetricCipherKeyPair): ECPrivateKeyParameters =
        keys.private as ECPrivateKeyParameters

    private fun invalidKey(step: PaceStep): Failed = Failed.InvalidChipKey(step)

    private fun abort(failure: Failed): Nothing = throw Abort(failure)

    /** Ends a run with [failure]; carries no stack trace. */
    private class Abort(val failure: Failed) : Exception(null, null, false, false)

    private companion object {
        /** The response to step 4: the chip's token `86`, then optionally `87`, then optionally `88` (B.1). */
        val MUTUAL_AUTHENTICATION_RESPONSES: Set<List<Int>> =
            setOf(
                listOf(DynamicAuthenticationData.CHIP_TOKEN),
                listOf(DynamicAuthenticationData.CHIP_TOKEN, DynamicAuthenticationData.CA_REFERENCE),
                listOf(
                    DynamicAuthenticationData.CHIP_TOKEN,
                    DynamicAuthenticationData.CA_REFERENCE,
                    DynamicAuthenticationData.PREVIOUS_CA_REFERENCE,
                ),
            )
    }
}
