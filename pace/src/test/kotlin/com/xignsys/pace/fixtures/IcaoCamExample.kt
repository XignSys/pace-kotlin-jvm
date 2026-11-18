package com.xignsys.pace.fixtures

/**
 * Published vectors of ICAO Doc 9303 Part 11 (8th edition), Appendix I.1: PACE with ECDH, Chip Authentication Mapping
 * and AES-128 on brainpoolP256r1, with the MRZ as password. Each value names its place in the appendix.
 */
internal object IcaoCamExample {
    /**
     * The MRZ information, Appendix I: document number C11T002JM with check digit 4, date of birth 960812 (2), date of
     * expiry 231031 (4).
     */
    const val MRZ_INFORMATION: String = "C11T002JM496081222310314"

    /** `K = f(pi)`, Appendix I. */
    val ENCODED_PASSWORD: ByteArray = hex("894D03F1 48C6265E 89845B21 8856EA34 D00EF8E8")

    /** `K_pi`, Appendix I. */
    val PASSWORD_KEY: ByteArray = hex("4E6F6FBF 7BE748B9 32C7B741 61BBA9DF")

    /** The `PACEInfo`, Appendix I.1: id-PACE-ECDH-CAM-AES-CBC-CMAC-128, version 2, ID 13. */
    val PACE_INFO: ByteArray = hex("3012060A 04007F00 07020204 06020201 0202010D")

    /**
     * MSE:Set AT of Appendix I.1 with the domain parameter reference `84 01 0D` added, as the library sends it; `Lc`
     * grows by three. The appendix sends `00 22 C1 A4 0F 80 0A 04 00 7F 00 07 02 02 04 06 02 83 01 01`.
     */
    val MSE_SET_AT: ByteArray = hex("00 22 C1 A4 12 80 0A 04 00 7F 00 07 02 02 04 06 02 83 01 01 84 01 0D")

    /** General Authenticate, encrypted nonce, Appendix I.1. */
    val ENCRYPTED_NONCE: ByteArray = hex("10 86 00 00 02 7C 00 00")

    /** The response to [ENCRYPTED_NONCE], Appendix I.1. */
    val ENCRYPTED_NONCE_RESPONSE: ByteArray =
        hex("7C 12 80 10 CB 60 E8 E0 D8 5B 76 A9 BD 30 47 47 C2 AD 42 E2 90 00")

    /** The terminal's private key of the mapping, Appendix I.1. */
    val MAPPING_PRIVATE_KEY: ByteArray =
        hex("5D8BB87B D74D985A 4B7D4325 B9F7B976 FE835122 77340079 8914AA22 738135CC")

    /** General Authenticate, map nonce, Appendix I.1. */
    val MAP_NONCE: ByteArray =
        hex(
            "10 86 00 00 45 7C 43 81 41 04 7F 1D 41 0A DB 7D DB 3B 84 BF 10 30 80 09 81 A9 10 5D 74 57 B4 A3 " +
                "AD E0 02 38 4F 30 86 C6 7E DE 1A B8 89 10 4A 27 DB 6D 84 2B 01 90 20 FB F3 CE AC B0 DC 62 7F 7B " +
                "DC AC 29 96 9E 19 D0 E5 53 C1 00",
        )

    /** The response to [MAP_NONCE] with the chip's mapping key `PK_Map,IC`, Appendix I.1. */
    val MAP_NONCE_RESPONSE: ByteArray =
        hex(
            "7C 43 82 41 04 A2 34 23 6A A9 B9 62 1E 8E FB 73 B5 24 5C 0E 09 D2 57 6E 52 77 18 3C 12 08 BD D5 " +
                "52 80 CA E8 B3 04 F3 65 71 3A 35 6E 65 A4 51 E1 65 EC C9 AC 0A C4 6E 37 71 34 2C 8F E5 AE DD 09 " +
                "26 85 33 8E 23 90 00",
        )

    /** The terminal's private key of the key agreement, Appendix I.1. */
    val AGREEMENT_PRIVATE_KEY: ByteArray =
        hex("76ECFDAA 9841C323 A3F5FC5E 88B88DB3 EFF7E35E BF57A7E6 946CB630 006C2120")

    /** General Authenticate, key agreement, Appendix I.1. */
    val KEY_AGREEMENT: ByteArray =
        hex(
            "10 86 00 00 45 7C 43 83 41 04 44 6C 93 40 84 D9 DA B8 63 94 4F 21 95 20 07 6C 29 EE 3F 7A E6 72 " +
                "2B 11 FF 31 9E C1 C7 72 8F 95 54 83 40 0B FF 60 BF 0C 59 29 27 00 09 27 7D C2 A5 15 E1 25 75 01 " +
                "0A D9 BA 91 6C F1 BF 86 FE FC 00",
        )

    /** The response to [KEY_AGREEMENT] with the chip's ephemeral public key, Appendix I.1. */
    val KEY_AGREEMENT_RESPONSE: ByteArray =
        hex(
            "7C 43 84 41 04 02 AD 56 6F 3C 6E C7 F9 32 45 09 AD 50 A5 1F A5 20 30 78 2A 49 68 FC FE DF 73 7D " +
                "AE A9 93 33 31 11 C3 B9 B4 C2 28 77 89 BD 13 7E 7F 8A A8 82 E2 A3 C6 33 CC D6 EC C2 C6 3C 57 AD " +
                "40 1A 09 C2 E1 90 00",
        )

    /** `KS_Enc`, Appendix I.1. */
    val ENCRYPTION_KEY: ByteArray = hex("0A9DA4DB 03BDDE39 FC5202BC 44B2E89E")

    /** `KS_MAC`, Appendix I.1. */
    val MAC_KEY: ByteArray = hex("4B1C0649 1ED5140C A2B537D3 44C6C0B1")

    /** General Authenticate, mutual authentication, Appendix I.1. */
    val MUTUAL_AUTHENTICATION: ByteArray = hex("00 86 00 00 0C 7C 0A 85 08 E8 6B D0 60 18 A1 CD 3B 00")

    /** The chip's token `86`, Appendix I.1. */
    val CHIP_TOKEN: ByteArray = hex("8596CF05 5C67C1A3")

    /** The Encrypted Chip Authentication Data `A_IC`, the value of `8A`, Appendix I.1. */
    val ENCRYPTED_CHIP_AUTHENTICATION_DATA: ByteArray =
        hex(
            "1EEA964D AAE372AC 990E3EFD E6333353 BFC89A67 04D93DA8 798CF77F 5B7A54BD " +
                "10CBA372 B42BE0B9 B5F28AA8 DE2F4F92",
        )

    /** The response to [MUTUAL_AUTHENTICATION] with `86` and `8A`, Appendix I.1. */
    val MUTUAL_AUTHENTICATION_RESPONSE: ByteArray =
        hex(
            "7C 3C 86 08 85 96 CF 05 5C 67 C1 A3 8A 30 1E EA 96 4D AA E3 72 AC 99 0E 3E FD E6 33 33 53 BF C8 " +
                "9A 67 04 D9 3D A8 79 8C F7 7F 5B 7A 54 BD 10 CB A3 72 B4 2B E0 B9 B5 F2 8A A8 DE 2F 4F 92 90 00",
        )

    /** The decrypted Chip Authentication Data `CA_IC`, Appendix I.1. */
    val CHIP_AUTHENTICATION_DATA: ByteArray =
        hex("85DC3FA9 3D0952BF A82F5FD1 89EE75BD 82F11D1F 0B8ED4BF 5319AC9B 53C426B3")

    /**
     * The IV `E(KS_Enc, -1)`, Appendix I.1. The appendix prints it as `F6A3B75A1 E933941 DD7A13E2 520779DF`, with the
     * first space one digit late; the 32 digits are the same.
     */
    val CHIP_AUTHENTICATION_IV: ByteArray = hex("F6A3B75A 1E933941 DD7A13E2 520779DF")

    /** The chip's static public key `PK_IC`, Appendix I.1, as an uncompressed point. */
    val CHIP_PUBLIC_KEY: ByteArray =
        hex(
            "04 18727094 94399E74 70A6431B E25E83EE E24FEA56 8C2ED28D B48E05DB 3A610DC8 " +
                "84D256A4 0E35EFCB 59BF6753 D3A489D2 8C7A4D97 3C2DA138 A6E7A4A0 8F68E16F",
        )

    /** The `ChipAuthenticationPublicKeyInfo` of EF.CardSecurity with `PK_IC` and keyID 13, Appendix I.1. */
    val CHIP_AUTHENTICATION_PUBLIC_KEY_INFO: ByteArray =
        hex(
            "30620609 04007F00 07020201 02305230 0C060704 007F0007 01020201 0D034200 " +
                "04187270 9494399E 7470A643 1BE25E83 EEE24FEA 568C2ED2 8DB48E05 DB3A610D " +
                "C884D256 A40E35EF CB59BF67 53D3A489 D28C7A4D 973C2DA1 38A6E7A4 A08F68E1 6F02010D",
        )
}
