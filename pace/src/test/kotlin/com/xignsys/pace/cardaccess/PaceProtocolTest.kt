package com.xignsys.pace.cardaccess

import com.xignsys.pace.cardaccess.PaceProtocol.Cipher
import com.xignsys.pace.cardaccess.PaceProtocol.Family
import com.xignsys.pace.cardaccess.PaceProtocol.KeyAgreement
import com.xignsys.pace.cardaccess.PaceProtocol.Mapping
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

/** The PACE object identifiers of TR-03110 Part 3, A.1.1.1, and ICAO 9303-11, section 9.2.3, written out. */
class PaceProtocolTest {
    @Test
    fun hasTheDottedValuesOfTheSpecifications() {
        // bsi-de = 0.4.0.127.0.7, id-PACE = bsi-de 2 2 4; families 1 (DH-GM), 2 (ECDH-GM), 3 (DH-IM), 4 (ECDH-IM),
        // 6 (ECDH-CAM, ICAO only); ciphers 1 (3DES), 2 to 4 (AES-128, -192, -256).
        val expected =
            mapOf(
                PaceProtocol.DH_GM_3DES_CBC_CBC to "0.4.0.127.0.7.2.2.4.1.1",
                PaceProtocol.DH_GM_AES_CBC_CMAC_128 to "0.4.0.127.0.7.2.2.4.1.2",
                PaceProtocol.DH_GM_AES_CBC_CMAC_192 to "0.4.0.127.0.7.2.2.4.1.3",
                PaceProtocol.DH_GM_AES_CBC_CMAC_256 to "0.4.0.127.0.7.2.2.4.1.4",
                PaceProtocol.ECDH_GM_3DES_CBC_CBC to "0.4.0.127.0.7.2.2.4.2.1",
                PaceProtocol.ECDH_GM_AES_CBC_CMAC_128 to "0.4.0.127.0.7.2.2.4.2.2",
                PaceProtocol.ECDH_GM_AES_CBC_CMAC_192 to "0.4.0.127.0.7.2.2.4.2.3",
                PaceProtocol.ECDH_GM_AES_CBC_CMAC_256 to "0.4.0.127.0.7.2.2.4.2.4",
                PaceProtocol.DH_IM_3DES_CBC_CBC to "0.4.0.127.0.7.2.2.4.3.1",
                PaceProtocol.DH_IM_AES_CBC_CMAC_128 to "0.4.0.127.0.7.2.2.4.3.2",
                PaceProtocol.DH_IM_AES_CBC_CMAC_192 to "0.4.0.127.0.7.2.2.4.3.3",
                PaceProtocol.DH_IM_AES_CBC_CMAC_256 to "0.4.0.127.0.7.2.2.4.3.4",
                PaceProtocol.ECDH_IM_3DES_CBC_CBC to "0.4.0.127.0.7.2.2.4.4.1",
                PaceProtocol.ECDH_IM_AES_CBC_CMAC_128 to "0.4.0.127.0.7.2.2.4.4.2",
                PaceProtocol.ECDH_IM_AES_CBC_CMAC_192 to "0.4.0.127.0.7.2.2.4.4.3",
                PaceProtocol.ECDH_IM_AES_CBC_CMAC_256 to "0.4.0.127.0.7.2.2.4.4.4",
                PaceProtocol.ECDH_CAM_AES_CBC_CMAC_128 to "0.4.0.127.0.7.2.2.4.6.2",
                PaceProtocol.ECDH_CAM_AES_CBC_CMAC_192 to "0.4.0.127.0.7.2.2.4.6.3",
                PaceProtocol.ECDH_CAM_AES_CBC_CMAC_256 to "0.4.0.127.0.7.2.2.4.6.4",
            )

        assertThat(PaceProtocol.entries).containsExactlyInAnyOrderElementsOf(expected.keys)
        expected.forEach { (protocol, oid) -> assertThat(protocol.oid).isEqualTo(oid) }
    }

    @Test
    fun hasTheFamiliesOfAPaceDomainParameterInfo() {
        // TR-03110 Part 3, A.1.1.1: id-PACE-DH-GM to id-PACE-ECDH-IM; ICAO 9303-11, section 9.2.2: also id-PACE-ECDH-CAM.
        assertThat(Family.entries.associateWith { it.oid })
            .containsExactlyInAnyOrderEntriesOf(
                mapOf(
                    Family.DH_GM to "0.4.0.127.0.7.2.2.4.1",
                    Family.ECDH_GM to "0.4.0.127.0.7.2.2.4.2",
                    Family.DH_IM to "0.4.0.127.0.7.2.2.4.3",
                    Family.ECDH_IM to "0.4.0.127.0.7.2.2.4.4",
                    Family.ECDH_CAM to "0.4.0.127.0.7.2.2.4.6",
                ),
            )
    }

    @Test
    fun namesMappingKeyAgreementAndCipher() {
        val protocol = PaceProtocol.ECDH_CAM_AES_CBC_CMAC_256

        assertThat(protocol.mapping).isEqualTo(Mapping.CHIP_AUTHENTICATION)
        assertThat(protocol.keyAgreement).isEqualTo(KeyAgreement.ECDH)
        assertThat(protocol.cipher).isEqualTo(Cipher.AES_CBC_CMAC_256)
        assertThat(PaceProtocol.DH_IM_3DES_CBC_CBC.mapping).isEqualTo(Mapping.INTEGRATED)
        assertThat(PaceProtocol.DH_IM_3DES_CBC_CBC.keyAgreement).isEqualTo(KeyAgreement.DH)
        // ICAO 9303-11, section 9.2.3: Chip Authentication Mapping has no 3DES variant.
        assertThat(PaceProtocol.entries.filter { it.family == Family.ECDH_CAM }.map { it.cipher })
            .doesNotContain(Cipher.TRIPLE_DES_CBC_CBC)
    }

    @Test
    fun findsProtocolsAndFamiliesByTheirIdentifiers() {
        assertThat(PaceProtocol.fromOid("0.4.0.127.0.7.2.2.4.2.2")).isEqualTo(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128)
        assertThat(PaceProtocol.fromOid("0.4.0.127.0.7.2.2.4.2")).isNull()
        assertThat(PaceProtocol.fromOid("0.4.0.127.0.7.2.2.4.6.1")).isNull()
        assertThat(PaceProtocol.fromOid("0.4.0.127.0.7.2.2.4.5.2")).isNull()
        assertThat(Family.fromOid("0.4.0.127.0.7.2.2.4.6")).isEqualTo(Family.ECDH_CAM)
        assertThat(Family.fromOid("0.4.0.127.0.7.2.2.4.2.2")).isNull()
    }
}
