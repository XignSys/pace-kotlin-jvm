package com.xignsys.pace

import com.xignsys.pace.PaceResult.Established
import com.xignsys.pace.PaceResult.Failed
import com.xignsys.pace.cardaccess.CardAccess
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.fixtures.CardAccessMother
import com.xignsys.pace.fixtures.FakeCardTransport
import com.xignsys.pace.fixtures.FakeCardTransport.Exchange
import com.xignsys.pace.fixtures.IcaoCamExample
import com.xignsys.pace.fixtures.hex
import com.xignsys.pace.internal.crypto.AesCbc
import com.xignsys.pace.internal.crypto.AesCmac
import com.xignsys.pace.internal.crypto.AesKey
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.util.test.FixedSecureRandom
import org.junit.jupiter.api.Test

/**
 * PACE with Chip Authentication Mapping, replayed on ICAO 9303-11, Appendix I.1 (MRZ, brainpoolP256r1, AES-128): the
 * Encrypted Chip Authentication Data `8A` of step 4 and its verification against the chip's static public key (sections
 * 4.4.3.5 and 4.4.4).
 */
class ChipAuthenticationMappingTest {
    private val cardAccess = CardAccess.parse(CardAccessMother.cardAccess(IcaoCamExample.PACE_INFO))
    private val parameters = PaceParameters(PaceProtocol.ECDH_CAM_AES_CBC_CMAC_128, 13)

    @Test
    fun runsTheCamExampleOfIcaoAppendixI1AndVerifiesTheChip() {
        val transport = FakeCardTransport(*exchanges())

        val result = run(transport)

        assertThat(result).isInstanceOf(Established::class.java)
        result as Established
        assertThat(transport.isExhausted).isTrue()
        assertThat(result.certificationAuthorityReferences).isEmpty()
        assertThat(
            result.toString(),
        ).isEqualTo("Established(certificationAuthorityReferences=0, chipAuthentication=true)")

        val keys = result.channel.secureMessaging.keys
        val block = ByteArray(16)

        assertThat(keys.encryption.encryptBlock(block))
            .isEqualTo(AesCbc(AesKey.takeOver(IcaoCamExample.ENCRYPTION_KEY.copyOf())).encryptBlock(block))
        assertThat(keys.mac.mac(block)).isEqualTo(AesCmac(AesKey.takeOver(IcaoCamExample.MAC_KEY.copyOf())).mac(block))

        // Section 4.4.3.5.2: PK_Map,IC = KA(CA_IC, PK_IC), PK_IC from the ChipAuthenticationPublicKeyInfo.
        val chipAuthentication = checkNotNull(result.chipAuthentication)

        assertThat(chipAuthentication.verify(IcaoCamExample.CHIP_PUBLIC_KEY)).isTrue()
        assertThat(chipAuthentication.verify(IcaoCamExample.CHIP_PUBLIC_KEY)).isTrue()
        assertThat(chipAuthentication.toString()).isEqualTo("ChipAuthenticationData")
    }

    @Test
    fun theChipPublicKeyIsTheOneOfTheChipAuthenticationPublicKeyInfo() {
        // Appendix I.1 prints PK_IC and the ChipAuthenticationPublicKeyInfo (section 9.2.6) separately: the same point.
        val info = ASN1Sequence.getInstance(IcaoCamExample.CHIP_AUTHENTICATION_PUBLIC_KEY_INFO)
        val publicKey = SubjectPublicKeyInfo.getInstance(info.getObjectAt(1))

        assertThat(publicKey.publicKeyData.octets).isEqualTo(IcaoCamExample.CHIP_PUBLIC_KEY)
    }

    @Test
    fun refusesOtherChipKeys() {
        val chipAuthentication = checkNotNull((run(FakeCardTransport(*exchanges())) as Established).chipAuthentication)
        val key = IcaoCamExample.CHIP_PUBLIC_KEY
        // The chip's mapping key of step 2, and the generator of brainpoolP256r1 (RFC 5639, section 3.4).
        val mappingKey = IcaoCamExample.MAP_NONCE_RESPONSE.copyOfRange(4, 69)
        val generator =
            hex(
                "04 8BD2AEB9 CB7E57CB 2C4B482F FC81B7AF B9DE27E1 E3BD23C2 3A4453BD 9ACE3262 " +
                    "547EF835 C3DAC4FD 97F8461A 14611DC9 C2774513 2DED8E54 5C1D54C7 2F046997",
            )

        assertThat(chipAuthentication.verify(mappingKey)).isFalse()
        assertThat(chipAuthentication.verify(generator)).isFalse()
        // TR-03110 Part 3, D.2.1.2: uncompressed only; a point that is not on the curve; no point at all.
        assertThat(chipAuthentication.verify(hex("02") + key.copyOfRange(1, 33))).isFalse()
        assertThat(chipAuthentication.verify(key.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() })).isFalse()
        assertThat(chipAuthentication.verify(ByteArray(0))).isFalse()
    }

    @Test
    fun requiresTheEncryptedChipAuthenticationDataLast() {
        // Section 4.4.4: 8A MUST be present with Chip Authentication Mapping, after 86, 87 and 88.
        val token = hex("86 08") + IcaoCamExample.CHIP_TOKEN
        val data = hex("8A 30") + IcaoCamExample.ENCRYPTED_CHIP_AUTHENTICATION_DATA

        assertThat(run(atStep4(hex("7C 0A") + token + hex("90 00"))))
            .isEqualTo(Failed.MalformedResponse(PaceStep.MUTUAL_AUTHENTICATION))
        assertThat(run(atStep4(hex("7C 3F") + token + data.copyOfRange(0, 50) + hex("87 01 41") + hex("90 00"))))
            .isEqualTo(Failed.MalformedResponse(PaceStep.MUTUAL_AUTHENTICATION))
    }

    @Test
    fun takesTheCaReferencesBeforeTheEncryptedChipAuthenticationData() {
        // Section 4.4.4, Table 4: 86, 87, 88, 8A. The chip's token covers the terminal's key only, not the response.
        val response =
            hex("7C 42 86 08") + IcaoCamExample.CHIP_TOKEN + hex("87 01 41 88 01 42 8A 30") +
                IcaoCamExample.ENCRYPTED_CHIP_AUTHENTICATION_DATA + hex("90 00")
        val result = run(atStep4(response)) as Established

        assertThat(result.certificationAuthorityReferences).containsExactly("A".toByteArray(), "B".toByteArray())
        assertThat(checkNotNull(result.chipAuthentication).verify(IcaoCamExample.CHIP_PUBLIC_KEY)).isTrue()
    }

    @Test
    fun refusesEncryptedChipAuthenticationDataThatDoesNotDecrypt() {
        // Sections 4.4.3.5.3 and 4.4.5.6: whole blocks, padding method 2, FE2OS of the length of the group order.
        val encrypted = IcaoCamExample.ENCRYPTED_CHIP_AUTHENTICATION_DATA

        for (value in listOf(encrypted.copyOf(47), encrypted.copyOf(32), byteArrayOf())) {
            val response =
                hex("7C") + byteArrayOf((12 + value.size).toByte(), 0x86.toByte(), 0x08) + IcaoCamExample.CHIP_TOKEN +
                    byteArrayOf(0x8A.toByte(), value.size.toByte()) + value + hex("90 00")

            assertThat(run(atStep4(response))).isEqualTo(Failed.MalformedResponse(PaceStep.MUTUAL_AUTHENTICATION))
        }
    }

    private fun run(transport: FakeCardTransport): PaceResult =
        Pace.establish(
            transport,
            cardAccess,
            parameters,
            Mrz.fromMrzInformation(IcaoCamExample.MRZ_INFORMATION.toCharArray()),
            FixedSecureRandom(IcaoCamExample.MAPPING_PRIVATE_KEY + IcaoCamExample.AGREEMENT_PRIVATE_KEY),
        )

    private fun atStep4(response: ByteArray): FakeCardTransport {
        val exchanges = exchanges()

        return FakeCardTransport(*exchanges.copyOfRange(0, 4), Exchange.Respond(exchanges[4].command, response))
    }

    private fun exchanges(): Array<Exchange> =
        arrayOf(
            Exchange.Respond(IcaoCamExample.MSE_SET_AT, hex("90 00")),
            Exchange.Respond(IcaoCamExample.ENCRYPTED_NONCE, IcaoCamExample.ENCRYPTED_NONCE_RESPONSE),
            Exchange.Respond(IcaoCamExample.MAP_NONCE, IcaoCamExample.MAP_NONCE_RESPONSE),
            Exchange.Respond(IcaoCamExample.KEY_AGREEMENT, IcaoCamExample.KEY_AGREEMENT_RESPONSE),
            Exchange.Respond(IcaoCamExample.MUTUAL_AUTHENTICATION, IcaoCamExample.MUTUAL_AUTHENTICATION_RESPONSE),
        )
}
