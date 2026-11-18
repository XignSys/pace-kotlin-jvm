package com.xignsys.pace.cardaccess

/**
 * The PACE protocols a `PACEInfo` may name: mapping, key agreement and the cipher of the session keys, identified by
 * an object identifier under `id-PACE` (TR-03110 Part 3, A.1.1.1; ICAO 9303-11, sections 9.2.1 and 9.2.3).
 *
 * The protocols that use 3DES are deprecated (TR-03110 Part 3, A.1.1.1). That a protocol is listed here does not mean
 * that the library implements it.
 */
public enum class PaceProtocol(
    /** The mapping and key agreement, which a `PACEDomainParameterInfo` names on its own. */
    public val family: Family,
    /** The symmetric cipher and MAC of the session keys. */
    public val cipher: Cipher,
) {
    /** `id-PACE-DH-GM-3DES-CBC-CBC`. */
    DH_GM_3DES_CBC_CBC(Family.DH_GM, Cipher.TRIPLE_DES_CBC_CBC),

    /** `id-PACE-DH-GM-AES-CBC-CMAC-128`. */
    DH_GM_AES_CBC_CMAC_128(Family.DH_GM, Cipher.AES_CBC_CMAC_128),

    /** `id-PACE-DH-GM-AES-CBC-CMAC-192`. */
    DH_GM_AES_CBC_CMAC_192(Family.DH_GM, Cipher.AES_CBC_CMAC_192),

    /** `id-PACE-DH-GM-AES-CBC-CMAC-256`. */
    DH_GM_AES_CBC_CMAC_256(Family.DH_GM, Cipher.AES_CBC_CMAC_256),

    /** `id-PACE-ECDH-GM-3DES-CBC-CBC`. */
    ECDH_GM_3DES_CBC_CBC(Family.ECDH_GM, Cipher.TRIPLE_DES_CBC_CBC),

    /** `id-PACE-ECDH-GM-AES-CBC-CMAC-128`. */
    ECDH_GM_AES_CBC_CMAC_128(Family.ECDH_GM, Cipher.AES_CBC_CMAC_128),

    /** `id-PACE-ECDH-GM-AES-CBC-CMAC-192`. */
    ECDH_GM_AES_CBC_CMAC_192(Family.ECDH_GM, Cipher.AES_CBC_CMAC_192),

    /** `id-PACE-ECDH-GM-AES-CBC-CMAC-256`. */
    ECDH_GM_AES_CBC_CMAC_256(Family.ECDH_GM, Cipher.AES_CBC_CMAC_256),

    /** `id-PACE-DH-IM-3DES-CBC-CBC`. */
    DH_IM_3DES_CBC_CBC(Family.DH_IM, Cipher.TRIPLE_DES_CBC_CBC),

    /** `id-PACE-DH-IM-AES-CBC-CMAC-128`. */
    DH_IM_AES_CBC_CMAC_128(Family.DH_IM, Cipher.AES_CBC_CMAC_128),

    /** `id-PACE-DH-IM-AES-CBC-CMAC-192`. */
    DH_IM_AES_CBC_CMAC_192(Family.DH_IM, Cipher.AES_CBC_CMAC_192),

    /** `id-PACE-DH-IM-AES-CBC-CMAC-256`. */
    DH_IM_AES_CBC_CMAC_256(Family.DH_IM, Cipher.AES_CBC_CMAC_256),

    /** `id-PACE-ECDH-IM-3DES-CBC-CBC`. */
    ECDH_IM_3DES_CBC_CBC(Family.ECDH_IM, Cipher.TRIPLE_DES_CBC_CBC),

    /** `id-PACE-ECDH-IM-AES-CBC-CMAC-128`. */
    ECDH_IM_AES_CBC_CMAC_128(Family.ECDH_IM, Cipher.AES_CBC_CMAC_128),

    /** `id-PACE-ECDH-IM-AES-CBC-CMAC-192`. */
    ECDH_IM_AES_CBC_CMAC_192(Family.ECDH_IM, Cipher.AES_CBC_CMAC_192),

    /** `id-PACE-ECDH-IM-AES-CBC-CMAC-256`. */
    ECDH_IM_AES_CBC_CMAC_256(Family.ECDH_IM, Cipher.AES_CBC_CMAC_256),

    /** `id-PACE-ECDH-CAM-AES-CBC-CMAC-128` (ICAO 9303-11 only). */
    ECDH_CAM_AES_CBC_CMAC_128(Family.ECDH_CAM, Cipher.AES_CBC_CMAC_128),

    /** `id-PACE-ECDH-CAM-AES-CBC-CMAC-192` (ICAO 9303-11 only). */
    ECDH_CAM_AES_CBC_CMAC_192(Family.ECDH_CAM, Cipher.AES_CBC_CMAC_192),

    /** `id-PACE-ECDH-CAM-AES-CBC-CMAC-256` (ICAO 9303-11 only). */
    ECDH_CAM_AES_CBC_CMAC_256(Family.ECDH_CAM, Cipher.AES_CBC_CMAC_256),
    ;

    /** The object identifier in dotted form, `{family cipher}`. */
    public val oid: String = "${family.oid}.${cipher.arc}"

    /** The mapping of the [family]. */
    public val mapping: Mapping
        get() = family.mapping

    /** The key agreement of the [family]. */
    public val keyAgreement: KeyAgreement
        get() = family.keyAgreement

    /**
     * A mapping with a key agreement, the parent arc of the protocols that use it and the type of a
     * `PACEDomainParameterInfo` (TR-03110 Part 3, A.1.1.1; ICAO 9303-11, sections 9.2.2 and 9.2.3).
     */
    public enum class Family(
        /** The mapping. */
        public val mapping: Mapping,
        /** The key agreement. */
        public val keyAgreement: KeyAgreement,
        arc: Int,
    ) {
        /** `id-PACE-DH-GM`: `{id-PACE 1}`. */
        DH_GM(Mapping.GENERIC, KeyAgreement.DH, 1),

        /** `id-PACE-ECDH-GM`: `{id-PACE 2}`. */
        ECDH_GM(Mapping.GENERIC, KeyAgreement.ECDH, 2),

        /** `id-PACE-DH-IM`: `{id-PACE 3}`. */
        DH_IM(Mapping.INTEGRATED, KeyAgreement.DH, 3),

        /** `id-PACE-ECDH-IM`: `{id-PACE 4}`. */
        ECDH_IM(Mapping.INTEGRATED, KeyAgreement.ECDH, 4),

        /** `id-PACE-ECDH-CAM`: `{id-PACE 6}` (ICAO 9303-11 only). */
        ECDH_CAM(Mapping.CHIP_AUTHENTICATION, KeyAgreement.ECDH, 6),
        ;

        /** The object identifier in dotted form. */
        public val oid: String = "$ID_PACE.$arc"

        /** Lookup of a [Family] by its object identifier. */
        public companion object {
            /** The family with the dotted object identifier [oid], or `null` if it is not one of them. */
            @JvmStatic
            public fun fromOid(oid: String): Family? = entries.firstOrNull { it.oid == oid }
        }
    }

    /**
     * The mapping of the nonce to a new generator (TR-03110 Part 3, A.3.4 and A.3.5; ICAO 9303-11, section 4.4.3.3).
     */
    public enum class Mapping {
        /** Generic Mapping. */
        GENERIC,

        /** Integrated Mapping. */
        INTEGRATED,

        /** Chip Authentication Mapping (ICAO 9303-11 only). */
        CHIP_AUTHENTICATION,
    }

    /** The key agreement. */
    public enum class KeyAgreement {
        /** Diffie-Hellman. */
        DH,

        /** Elliptic curve Diffie-Hellman. */
        ECDH,
    }

    /** The symmetric cipher and MAC of the session keys, the last arc of the protocol's object identifier. */
    public enum class Cipher(internal val arc: Int) {
        /** 3DES in CBC mode with the retail MAC: `{family 1}`; deprecated. */
        TRIPLE_DES_CBC_CBC(1),

        /** AES-128 in CBC mode with CMAC: `{family 2}`. */
        AES_CBC_CMAC_128(2),

        /** AES-192 in CBC mode with CMAC: `{family 3}`. */
        AES_CBC_CMAC_192(3),

        /** AES-256 in CBC mode with CMAC: `{family 4}`. */
        AES_CBC_CMAC_256(4),
    }

    /** Lookup of a [PaceProtocol] by its object identifier. */
    public companion object {
        /**
         * `bsi-de`: `itu-t(0) identified-organization(4) etsi(0) reserved(127) etsi-identified-organization(0) 7`
         * (TR-03110 Part 3, A; ICAO 9303-11, section 9.2.3).
         */
        private const val BSI_DE = "0.4.0.127.0.7"

        /** `id-PACE`: `{bsi-de protocols(2) smartcard(2) 4}`. */
        private const val ID_PACE = "$BSI_DE.2.2.4"

        /** The protocol with the dotted object identifier [oid], or `null` if it is not a PACE protocol. */
        @JvmStatic
        public fun fromOid(oid: String): PaceProtocol? = entries.firstOrNull { it.oid == oid }
    }
}
