package com.xignsys.pace

import com.xignsys.pace.internal.crypto.EcDomain

/**
 * The Chip Authentication Data `CA_IC` of PACE with Chip Authentication Mapping, decrypted during PACE, with the chip's
 * mapping key `PK_Map,IC` of step 2 (ICAO 9303-11, sections 4.4.3.5 and 4.4.4). [verify] checks them against the
 * chip's static public key `PK_IC`.
 *
 * **Passive Authentication is still required** (ICAO 9303-11, section 4.4.3.5.2): `PK_IC` comes from the
 * `ChipAuthenticationPublicKeyInfo` of EF.CardSecurity whose `keyId` equals the `parameterId` of the `PACEInfo` used
 * (section 9.2.1), and the chip is genuine only once that file has been verified. The library neither reads nor
 * verifies EF.CardSecurity; the caller reads it through the channel and verifies it.
 *
 * `CA_IC` reveals neither the chip's nor the terminal's keys; it is kept while this object lives, so that [verify] can
 * be called more than once. [toString] shows no data. Immutable and thread-safe.
 */
public class ChipAuthenticationData internal constructor(
    private val domain: EcDomain,
    chipMappingKey: ByteArray,
    chipAuthenticationData: ByteArray,
) {
    private val mappingKey = chipMappingKey.copyOf()
    private val data = chipAuthenticationData.copyOf()

    /**
     * Whether `PK_Map,IC = KA(CA_IC, PK_IC)` holds (ICAO 9303-11, section 4.4.3.5.2) for [chipPublicKey], `PK_IC` as an
     * uncompressed elliptic curve point on the domain parameters of PACE. `false` if [chipPublicKey] is not such a
     * point or the equation does not hold.
     */
    public fun verify(chipPublicKey: ByteArray): Boolean {
        val publicKey = domain.decodePoint(chipPublicKey) ?: return false
        val expected = domain.decodePoint(mappingKey) ?: return false
        val product = domain.multiplySecret(publicKey, data) ?: return false

        return product == expected
    }

    override fun toString(): String = "ChipAuthenticationData"
}
