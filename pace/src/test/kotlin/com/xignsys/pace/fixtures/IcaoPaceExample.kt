package com.xignsys.pace.fixtures

/**
 * Published vectors of ICAO Doc 9303 Part 11 (8th edition), Appendix G and G.1: PACE with ECDH, Generic Mapping and
 * AES-128 on brainpoolP256r1, with the MRZ as password. Each value names its place in the appendix.
 */
internal object IcaoPaceExample {
    /** The MRZ information, Appendix G: document number T22000129 (3), date of birth 640812 (5), expiry 101031 (8). */
    const val MRZ_INFORMATION: String = "T22000129364081251010318"

    /** `K = f(pi)`, the SHA-1 hash of [MRZ_INFORMATION], Appendix G. */
    val ENCODED_PASSWORD: ByteArray = hex("7E2D2A41 C74EA0B3 8CD36F86 3939BFA8 E9032AAD")

    /** `K_pi`, Appendix G. */
    val PASSWORD_KEY: ByteArray = hex("89DED1B2 6624EC1E 634C1989 302849DD")

    /** MSE:Set AT with the MRZ, without CHAT and without `84`, Appendix G.1. */
    val MSE_SET_AT: ByteArray = hex("00 22 C1 A4 0F 80 0A 04 00 7F 00 07 02 02 04 02 02 83 01 01")

    /**
     * [MSE_SET_AT] with the domain parameter reference `84 01 0D` for brainpoolP256r1, the domain parameters of the
     * example, as the library sends it; `Lc` grows by three. Not part of the example, which leaves `84` out.
     */
    val MSE_SET_AT_WITH_DOMAIN_PARAMETER_REFERENCE: ByteArray =
        hex("00 22 C1 A4 12 80 0A 04 00 7F 00 07 02 02 04 02 02 83 01 01 84 01 0D")

    /** General Authenticate, encrypted nonce, Appendix G.1. */
    val ENCRYPTED_NONCE: ByteArray = hex("10 86 00 00 02 7C 00 00")

    /** The response to [ENCRYPTED_NONCE] with the encrypted nonce `z`, Appendix G.1. */
    val ENCRYPTED_NONCE_RESPONSE: ByteArray =
        hex("7C 12 80 10 95 A3 A0 16 52 2E E9 8D 01 E7 6C B6 B9 8B 42 C3 90 00")

    /** The decrypted nonce `s`, Appendix G.1. */
    val NONCE: ByteArray = hex("3F00C4D3 9D153F2B 2A214A07 8D899B22")

    /** The terminal's private key of the mapping, Appendix G.1. */
    val MAPPING_PRIVATE_KEY: ByteArray =
        hex("7F4EF07B 9EA82FD7 8AD689B3 8D0BC78C F21F249D 953BC46F 4C6E1925 9C010F99")

    /** General Authenticate, map nonce, Appendix G.1. */
    val MAP_NONCE: ByteArray =
        hex(
            """
            10 86 00 00 45 7C 43 81 41 04 7A CF 3E FC 98 2E C4 55 65 A4 B1 55
            12 9E FB C7 46 50 DC BF A6 36 2D 89 6F C7 02 62 E0 C2 CC 5E 54 45
            52 DC B6 72 52 18 79 91 15 B5 5C 9B AA 6D 9F 6B C3 A9 61 8E 70 C2
            5A F7 17 77 A9 C4 92 2D 00
            """,
        )

    /** The response to [MAP_NONCE] with the chip's mapping key, Appendix G.1. */
    val MAP_NONCE_RESPONSE: ByteArray =
        hex(
            """
            7C 43 82 41 04 82 4F BA 91 C9 CB E2 6B EF 53 A0 EB E7 34 2A 3B F1
            78 CE A9 F4 5D E0 B7 0A A6 01 65 1F BA 3F 57 30 D8 C8 79 AA A9 C9
            F7 39 91 E6 1B 58 F4 D5 2E B8 7A 0A 0C 70 9A 49 DC 63 71 93 63 CC
            D1 3C 54 90 00
            """,
        )

    /** The shared secret point `H` of the mapping, Appendix G.1, as an uncompressed point. */
    val SHARED_POINT_H: ByteArray =
        hex(
            """
            04
            60332EF2 450B5D24 7EF6D386 8397D398 852ED6E8 CAF6FFEE F6BF85CA 57057FD5
            0840CA74 15BAF3E4 3BD414D3 5AA4608B 93A2CAF3 A4E3EA4E 82C9C13D 03EB7181
            """,
        )

    /** The mapped generator `G'`, Appendix G.1, as an uncompressed point. */
    val MAPPED_GENERATOR: ByteArray =
        hex(
            """
            04
            8CED63C9 1426D4F0 EB1435E7 CB1D74A4 6723A0AF 21C89634 F65A9AE8 7A9265E2
            8C879506 743F8611 AC33645C 5B985C80 B5F09A0B 83407C1B 6A4D857A E76FE522
            """,
        )

    /** The terminal's private key of the key agreement, Appendix G.1. */
    val AGREEMENT_PRIVATE_KEY: ByteArray =
        hex("A73FB703 AC1436A1 8E0CFA5A BB3F7BEC 7A070E7A 6788486B EE230C4A 22762595")

    /** General Authenticate, perform key agreement, Appendix G.1. */
    val KEY_AGREEMENT: ByteArray =
        hex(
            """
            10 86 00 00 45 7C 43 83 41 04 2D B7 A6 4C 03 55 04 4E C9 DF 19
            05 14 C6 25 CB A2 CE A4 87 54 88 71 22 F3 A5 EF 0D 5E DD 30 1C
            35 56 F3 B3 B1 86 DF 10 B8 57 B5 8F 6A 7E B8 0F 20 BA 5D C7 BE
            1D 43 D9 BF 85 01 49 FB B3 64 62 00
            """,
        )

    /** The response to [KEY_AGREEMENT] with the chip's ephemeral public key, Appendix G.1. */
    val KEY_AGREEMENT_RESPONSE: ByteArray =
        hex(
            """
            7C 43 84 41 04 9E 88 0F 84 29 05 B8 B3 18 1F 7A F7 CA A9 F0 EF
            B7 43 84 7F 44 A3 06 D2 D2 8C 1D 9E C6 5D F6 DB 77 64 B2 22 77
            A2 ED DC 3C 26 5A 9F 01 8F 9C B8 52 E1 11 B7 68 B3 26 90 4B 59
            A0 19 37 76 F0 94 90 00
            """,
        )

    /** The shared secret `K` of the key agreement, Appendix G.1. */
    val SHARED_SECRET: ByteArray =
        hex("28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925")

    /** `KS_Enc`, Appendix G.1. */
    val ENCRYPTION_KEY: ByteArray = hex("F5F0E35C 0D7161EE 6724EE51 3A0D9A7F")

    /** `KS_MAC`, Appendix G.1. */
    val MAC_KEY: ByteArray = hex("FE251C78 58B356B2 4514B3BD 5F4297D1")

    /** General Authenticate, mutual authentication, with the terminal's token `T_IFD`, Appendix G.1. */
    val MUTUAL_AUTHENTICATION: ByteArray = hex("00 86 00 00 0C 7C 0A 85 08 C2 B0 BD 78 D9 4B A8 66 00")

    /** The response to [MUTUAL_AUTHENTICATION] with the chip's token `T_IC`, Appendix G.1. */
    val MUTUAL_AUTHENTICATION_RESPONSE: ByteArray = hex("7C 0A 86 08 3A BB 96 74 BC E9 3C 08 90 00")

    /** The chip's ephemeral public key, the value of `84` in [KEY_AGREEMENT_RESPONSE]. */
    val CHIP_PUBLIC_KEY: ByteArray = KEY_AGREEMENT_RESPONSE.copyOfRange(4, 4 + 65)

    /** The terminal's ephemeral public key, the value of `83` in [KEY_AGREEMENT]. */
    val TERMINAL_PUBLIC_KEY: ByteArray = KEY_AGREEMENT.copyOfRange(9, 9 + 65)
}
