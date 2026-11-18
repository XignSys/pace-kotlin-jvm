package com.xignsys.pace.fixtures

/**
 * Published vectors of the BSI EAC2 Worked Example v1.02 (2011-08-03), copied from its hex dumps. Each value names
 * its section.
 */
internal object WorkedExample {
    /**
     * EF.CardAccess, section 3: TerminalAuthenticationInfo, ChipAuthenticationInfo, PACEInfo
     * (id-PACE-ECDH-GM-AES-CBC-CMAC-128, version 2, parameter ID 13), ChipAuthenticationDomainParameterInfo, CardInfo
     * and PrivilegedTerminalInfo with a nested set. Encoded from the table of section 3, which prints every byte.
     */
    val EF_CARD_ACCESS: ByteArray =
        hex(
            """
            31 81 C6
            30 0D 06 08 04 00 7F 00 07 02 02 02 02 01 02
            30 12 06 0A 04 00 7F 00 07 02 02 03 02 02 02 01 02 02 01 01
            30 12 06 0A 04 00 7F 00 07 02 02 04 02 02 02 01 02 02 01 0D
            30 1C 06 09 04 00 7F 00 07 02 02 03 02 30 0C 06 07 04 00 7F 00 07 01 02 02 01 0D 02 01 01
            30 2F 06 08 04 00 7F 00 07 02 02 06 16 23
            68 74 74 70 73 3A 2F 2F 77 77 77 2E 68 6A 70 2D 63 6F 6E 73 75 6C 74 69 6E 67 2E 63 6F 6D 2F 68 6F 6D 65
            30 3E 06 08 04 00 7F 00 07 02 02 08 31 32
            30 12 06 0A 04 00 7F 00 07 02 02 03 02 02 02 01 02 02 01 02
            30 1C 06 09 04 00 7F 00 07 02 02 03 02 30 0C 06 07 04 00 7F 00 07 01 02 02 01 0D 02 01 02
            """,
        )

    /** MSE:Set AT for PACE, section 3.1: short form with `Lc` and data, no `Le` (case 3). */
    val MSE_SET_AT: ByteArray =
        hex(
            """
            00 22 C1 A4 27 80 0A 04 00 7F 00 07 02 02 04 02
            02 83 01 03 7F 4C 12 06 09 04 00 7F 00 07 03 01
            02 02 53 05 00 00 00 01 10 84 01 0D
            """,
        )

    /** General Authenticate (Get Nonce), section 3.2: command chaining, short form, `Le` `00` (case 4). */
    val GENERAL_AUTHENTICATE_GET_NONCE: ByteArray = hex("10 86 00 00 02 7C 00 00")

    /** The response to [GENERAL_AUTHENTICATE_GET_NONCE], section 3.2: the encrypted nonce and `90 00`. */
    val GENERAL_AUTHENTICATE_GET_NONCE_RESPONSE: ByteArray =
        hex("7C 12 80 10 CE 83 4C DE 69 FF BB 1D 1E B2 15 85 CD 70 9F 18 90 00")

    /** PSO:Verify Certificate, section 4.2, plain: extended `Lc` `00 01 66`, no `Le` (case 3). */
    val PSO_VERIFY_CERTIFICATE_PLAIN: ByteArray =
        hex(
            """
            00 2A 00 BE 00 01 66 7F 4E 81 DE 5F 29 01 00 42
            0D 44 45 43 56 43 41 41 54 30 30 30 30 31 7F 49
            81 90 06 0A 04 00 7F 00 07 02 02 02 02 05 86 81
            81 04 5B 6E C0 28 FA BA A3 88 53 1E 46 DA 2D 1E
            4D F2 DA 21 90 3A A2 FF 00 BD 22 32 5C 25 D7 CD
            46 24 C5 52 4E E1 EC 35 F3 15 18 45 EF 29 AC 40
            BF 71 F4 57 6B 82 7F 79 EB EC BB 54 60 E2 2C 2F
            38 72 0E B6 A0 5A CA 69 43 88 88 5F 53 D4 62 30
            6F 98 CE CC 5D DC B6 43 4F 81 BE 01 53 FC 1E 4E
            6B A2 71 16 F7 FB 06 FE 5C B6 F4 A3 A2 87 A4 9B
            F4 A4 DA F9 DB BD 8A B6 38 EE 8E 66 AC 72 FA 76
            98 AF 5F 20 0D 44 45 54 45 53 54 44 56 44 45 30
            31 39 7F 4C 12 06 09 04 00 7F 00 07 03 01 02 02
            53 05 80 1F FF FF 10 5F 25 06 01 00 00 09 03 00
            5F 24 06 01 00 01 00 03 00 5F 37 81 80 34 EA 28
            28 25 23 1B F9 EF 84 DC D1 5A F7 72 A9 26 B0 A4
            78 CA 96 5A 7F 8E 9E 0D 90 CD 7D E6 18 30 53 0F
            D9 15 47 8E 68 56 39 9F E7 8A B2 D6 F3 BD E5 0D
            9A 56 25 EC B6 51 D7 58 77 34 77 13 6F 70 A5 90
            81 E5 30 D8 29 28 C7 34 AF 02 BA A9 E3 03 E9 6B
            BD A6 06 DC 6E F9 9A 40 28 62 DD 72 7E 96 4E 19
            64 DA 09 49 B5 84 60 20 C3 26 7A EA 6C F0 26 E5
            4C 7E 9E 83 73 67 DF 17 1C C7 B2 C8 91
            """,
        )

    /** PSO:Verify Certificate, section 4.2, protected: extended `Lc` `00 01 7F` and `Le` `00 00` (case 4). */
    val PSO_VERIFY_CERTIFICATE_PROTECTED: ByteArray =
        hex(
            """
            0C 2A 00 BE 00 01 7F 87 82 01 71 01 BB 99 CB 14
            CA 8D AB 03 80 8E 10 A4 05 24 A8 A6 5C 86 FD 7B
            67 4A E4 3B 2A FE 41 94 47 B1 EB AD 05 D8 AE 6E
            34 7E E1 81 A8 36 28 F5 C1 79 B4 91 37 A2 E6 78
            B9 81 8D 86 79 99 C6 E3 7E F7 F3 F6 8D AB 41 36
            A1 49 1C 91 5B 61 6B EB 83 5A FE DE A7 92 61 C7
            F5 CE 5C 63 87 BD 72 06 90 AB 90 9D 13 CE 36 15
            C9 CD A7 16 70 26 B3 D8 28 13 5B 8C 54 F0 F1 1A
            F8 DB 65 B9 F4 35 BB 2C CF 41 71 F8 2C 45 72 3A
            88 B5 FF A3 40 9F 09 ED F9 A2 46 E8 4C 21 5F 0E
            F1 A8 BB 27 18 35 0A 4F 96 32 C7 06 8C B9 C9 FA
            4E 0A 75 40 87 5D 4B 73 D2 8A E0 5C 28 D5 23 B4
            2C 6D 4C 1A 4F 64 78 F6 6E 86 EE 42 1B C8 DB 68
            34 12 0B EC B9 12 B1 50 AB AC 9D 80 6D 66 AC 1F
            7B EF 14 C5 40 F0 A2 53 E1 C1 83 03 27 B9 37 5F
            6B DA 79 A8 B2 77 DD EF 63 D7 EE 25 52 53 1E 2C
            9E 44 B7 15 29 84 A5 77 E2 E8 A5 C3 21 3F BC B4
            BF 7F 0D F3 EC F9 EB D5 0C 48 EF 2D 01 C3 B3 03
            AF 58 39 26 4A A5 34 D5 58 76 AF 81 CA B1 73 F7
            08 4E BF 46 3D 8F 0A F1 6A B9 7A DB 9D 4C 65 68
            8D D4 32 A9 EC 3B 3F 8D 9A 68 5B A8 48 4B 5E A2
            1A F7 39 CD A4 D6 3C 2A 98 74 B9 61 F5 30 06 97
            70 64 83 05 90 E2 76 1F 88 AA 6E 4D 65 08 8A E4
            C7 C8 4D E8 AE 62 B6 8E 55 7D CD F5 8E 08 E3 8A
            CD A4 4E 50 3C E5 00 00
            """,
        )

    /**
     * The Certificate Holder Authorization Template of MSE:Set AT, section 3.1: `id-AT` with the discretionary data
     * `00 00 00 01 10`.
     */
    val PACE_CHAT: ByteArray = hex("7F 4C 12 06 09 04 00 7F 00 07 03 01 02 02 53 05 00 00 00 01 10")

    /** `K_pi`, derived from the PIN 123456, section 3. */
    val PACE_PASSWORD_KEY: ByteArray = hex("59 14 68 CD A8 3D 65 21 9C CC B8 56 02 33 60 0F")

    /** The terminal's private key of the mapping, section 3.3. */
    val PACE_MAPPING_PRIVATE_KEY: ByteArray =
        hex(
            """
            75 22 87 F5 B0 2D E3 C4 BC 3E 17 94 51 18 C5 1B
            23 C9 72 78 E4 CD 74 80 48 AC 56 BA 5B DC 3D 46
            """,
        )

    /** General Authenticate, map nonce, section 3.3. */
    val PACE_MAP_NONCE: ByteArray =
        hex(
            """
            10 86 00 00 45 7C 43 81 41 04 3D D2 9B BE 59 07
            FD 21 A1 52 AD A4 89 5F AA E7 AC C5 5F 5E 50 EF
            BF DE 5A B0 C6 EB 54 F1 98 D6 15 91 36 35 F0 FD
            F5 BE B3 83 E0 03 55 F8 2D 3C 41 ED 0D F2 E2 83
            63 43 3D FB 73 85 6A 15 DC 9F 00
            """,
        )

    /** The response to [PACE_MAP_NONCE] with the chip's mapping key, section 3.3. */
    val PACE_MAP_NONCE_RESPONSE: ByteArray =
        hex(
            """
            7C 43 82 41 04 9C FC F7 58 2A C9 86 D0 DD 52 FA
            53 12 34 14 C3 E1 B9 6B 4D 00 AB A8 E5 74 67 9B
            70 EF B5 BC 3B 45 D2 F1 37 29 CC 2A E1 78 E7 E2
            41 B4 43 21 35 33 B7 7D BB 44 64 9A 81 5D DC 4A
            23 84 BA 42 2A 90 00
            """,
        )

    /** The shared secret point `H` of the mapping, section 3.3. */
    val PACE_SHARED_POINT_H: ByteArray =
        hex(
            """
            04 71 85 0C FD 80 FB 47 59 47 E5 B1 AF 10 FE 8E
            66 63 96 7C 2D 26 49 35 B3 19 51 F7 63 A4 B0 3A
            57 49 16 73 88 F8 8F 52 A1 09 16 7E 3E 65 92 CA
            08 20 46 8D 11 57 A8 E7 81 D2 F7 04 91 79 B1 D1
            14
            """,
        )

    /** The mapped generator `G'`, section 3.3. */
    val PACE_MAPPED_GENERATOR: ByteArray =
        hex(
            """
            04 39 29 D2 8B A1 E5 33 9D 6C 5D AD E5 E3 3B D3
            C2 F0 BD 14 DD 77 C7 52 15 32 26 16 59 C9 18 FA
            60 14 DD 48 FA 84 E6 2B DE 43 8E DB 4C 97 71 D0
            42 CD B2 4B 77 88 BD BA B2 03 1C 45 75 1E 77 7F
            66
            """,
        )

    /**
     * The terminal's private key of the key agreement, section 3.4. The dump shows 33 bytes, a zero byte and then
     * these 32; the key is the integer, which has 32 bytes like every scalar on brainpoolP256r1.
     */
    val PACE_AGREEMENT_PRIVATE_KEY: ByteArray =
        hex(
            """
            9D 9A 32 DF 93 A5 7C CE 33 CA 3C DD 34 57 E3
            3A 97 6F 29 35 46 C7 35 50 F3 97 25 9C 93 BE 01
            20
            """,
        )

    /** General Authenticate, perform key agreement, section 3.4. */
    val PACE_KEY_AGREEMENT: ByteArray =
        hex(
            """
            10 86 00 00 45 7C 43 83 41 04 51 8B C4 E5 32 AD
            2A 9B D6 52 78 04 D5 D6 65 AB D5 10 41 03 7A 0C
            C8 AA 92 28 04 EB 50 1C 22 2B 34 27 38 85 99 AF
            AA E9 FB AC E2 DF 93 E1 3C 3C 49 79 CD 12 F0 AE
            3E 3C 01 26 02 83 91 55 45 82 00
            """,
        )

    /** The response to [PACE_KEY_AGREEMENT] with the chip's ephemeral public key, section 3.4. */
    val PACE_KEY_AGREEMENT_RESPONSE: ByteArray =
        hex(
            """
            7C 43 84 41 04 28 2C F3 80 73 03 6A FA C2 16 AF
            13 5B D9 94 DA 0C 35 7F 10 BD 4C 34 AF EA 10 42
            B2 EB 0F D6 80 4D F3 65 8B 83 5A C2 E7 13 3F 13
            69 11 84 54 2B B5 0B 10 99 63 A4 66 2A BD C0 8B
            97 63 AF 4B 5B 90 00
            """,
        )

    /** The shared secret `K` of the key agreement, section 3.4. */
    val PACE_SHARED_SECRET: ByteArray =
        hex(
            """
            6E 7D 07 7C CD 36 7C 2E AA 68 3F 1E 8E C5 34 30
            2E 2D 00 B6 AD AF 8A 87 A6 ED A7 87 40 F1 76 06
            """,
        )

    /** `K_Enc`, section 3.4. */
    val PACE_ENCRYPTION_KEY: ByteArray = hex("68 40 6B 41 62 10 05 63 D9 C9 01 A6 15 4D 29 01")

    /** `K_MAC`, section 3.4. */
    val PACE_MAC_KEY: ByteArray = hex("73 FF 26 87 84 F7 2A F8 33 FD C9 46 40 49 AF C9")

    /** General Authenticate, mutual authentication, with the terminal's token, section 3.5. */
    val PACE_MUTUAL_AUTHENTICATION: ByteArray = hex("00 86 00 00 0C 7C 0A 85 08 A2 7A E7 B3 65 73 C1 D9 00")

    /**
     * The response to [PACE_MUTUAL_AUTHENTICATION] with the chip's token and the CAR `DECVCAAT00001`, section 3.5. The
     * dump leaves out the status word `90 00` of the table below it, which is added here.
     */
    val PACE_MUTUAL_AUTHENTICATION_RESPONSE: ByteArray =
        hex(
            """
            7C 19 86 08 A2 65 8C 2F 38 60 0B 0F 87 0D 44 45
            43 56 43 41 41 54 30 30 30 30 31 90 00
            """,
        )

    /*
     * PACE Secure Messaging, sections 4 and 5, with K_Enc and K_MAC of section 3.4. The Worked Example does not print
     * the send sequence counter; it starts at 0 after PACE (ICAO 9303-11, section 9.8.7.3) and each section's commands
     * follow those before. The protected responses are printed without their status word 90 00, which is added here.
     */

    /** MSE:Set DST of section 4.1, plain (case 3), the first command after PACE: SSC 1. */
    val SM_MSE_SET_DST: ByteArray = hex("00 22 81 B6 0F 83 0D 44 45 43 56 43 41 41 54 30 30 30 30 31")

    /** MSE:Set DST of section 4.1, protected. */
    val SM_MSE_SET_DST_PROTECTED: ByteArray =
        hex(
            """
            0C 22 81 B6 1D 87 11 01 BE 90 23 7E EB 4B A0 FF
            25 3E A2 46 AE 31 C8 B8 8E 08 92 D2 1C 73 A1 DF
            E9 99 00
            """,
        )

    /** The protected response to MSE:Set DST, section 4.1 (SSC 2), status word added. */
    val SM_MSE_SET_DST_RESPONSE_PROTECTED: ByteArray = hex("99 02 90 00 8E 08 A8 95 70 A6 86 64 A7 D6 90 00")

    /**
     * The protected response to [PSO_VERIFY_CERTIFICATE_PROTECTED], section 4.2, the second command after PACE (SSC 3
     * for the command, 4 for the response), status word added.
     */
    val SM_PSO_VERIFY_CERTIFICATE_RESPONSE_PROTECTED: ByteArray =
        hex("99 02 90 00 8E 08 2B 06 86 4A EA 1A 10 13 90 00")

    /** Get Challenge of section 4.6, plain (case 2, `Le` 08), the sixth command after PACE: SSC 11. */
    val SM_GET_CHALLENGE: ByteArray = hex("00 84 00 00 08")

    /** Get Challenge of section 4.6, protected. */
    val SM_GET_CHALLENGE_PROTECTED: ByteArray = hex("0C 84 00 00 0D 97 01 08 8E 08 1D 21 EB BE 73 8F F4 FD 00")

    /** The protected response to Get Challenge, section 4.6, status word added. */
    val SM_GET_CHALLENGE_RESPONSE_PROTECTED: ByteArray =
        hex(
            """
            87 11 01 12 4E BD D5 70 FE 8E 05 FD 04 8B 2A 76
            5C 5E 75 99 02 90 00 8E 08 C9 40 9B 30 57 B1 B4
            3F 90 00
            """,
        )

    /** The chip's challenge, the plain response data of section 4.6. */
    val SM_GET_CHALLENGE_RESPONSE_DATA: ByteArray = hex("54 7E 4E AB 03 B2 35 D2")

    /**
     * The send sequence counter before MSE:Set AT of section 5.1. Not printed, and not the count of the commands the
     * example shows: the MACs of sections 5.1 and 5.2 verify with 39 to 42, so 38.
     */
    const val SM_SSC_BEFORE_CHIP_AUTHENTICATION: Long = 38

    /** MSE:Set AT for Chip Authentication, section 5.1, plain (case 3). */
    val SM_CA_MSE_SET_AT: ByteArray = hex("00 22 41 A4 0F 80 0A 04 00 7F 00 07 02 02 03 02 02 84 01 01")

    /** MSE:Set AT for Chip Authentication, section 5.1, protected (SSC 39). */
    val SM_CA_MSE_SET_AT_PROTECTED: ByteArray =
        hex(
            """
            0C 22 41 A4 1D 87 11 01 73 29 A5 63 CC C8 1D D1
            98 18 79 EF 55 C3 5F F4 8E 08 2F C6 BD 55 A9 1D
            5E A1 00
            """,
        )

    /** The protected response to MSE:Set AT, section 5.1 (SSC 40), status word added. */
    val SM_CA_MSE_SET_AT_RESPONSE_PROTECTED: ByteArray = hex("99 02 90 00 8E 08 28 3C F6 67 65 5C 33 A6 90 00")

    /** General Authenticate for Chip Authentication, section 5.2, plain (case 4, `Le` 00). */
    val SM_CA_GENERAL_AUTHENTICATE: ByteArray =
        hex(
            """
            00 86 00 00 45 7C 43 80 41 04 5A 7A 37 7F C9 CA
            FC 03 AC 7F F4 54 41 A8 B2 90 9D 88 EA B8 E6 B0
            17 38 47 AB 49 B9 49 DF 37 99 A3 4E E5 7E C5 52
            68 CF 8B 1C 3E C4 89 F8 BF 4C F4 C6 8D 3F D9 67
            0E 89 C0 D5 D3 FF F1 AA F8 9F 00
            """,
        )

    /** General Authenticate for Chip Authentication, section 5.2, protected (SSC 41). */
    val SM_CA_GENERAL_AUTHENTICATE_PROTECTED: ByteArray =
        hex(
            """
            0C 86 00 00 60 87 51 01 20 43 9F E1 26 64 30 D1
            7B 9D EA A0 9E 6B A5 6B F9 DC 58 A4 7E 2E 08 F4
            90 31 8B E4 90 6C 41 CD 67 6A 18 D0 D4 BF 99 52
            A4 EA 1E 81 DA FB F9 DE 89 10 2F 32 4F 14 DA A6
            D6 D3 F1 67 6D 2E AA EF E6 D1 F9 AB 34 F1 4B 1D
            9D 27 35 C3 60 2D DC 0B 97 01 00 8E 08 E1 9B 47
            4E FE AF A6 EB 00
            """,
        )

    /** The protected response to General Authenticate, section 5.2 (SSC 42), status word added. */
    val SM_CA_GENERAL_AUTHENTICATE_RESPONSE_PROTECTED: ByteArray =
        hex(
            """
            87 21 01 DA 04 8A 9D D7 BA 3A 90 1B 3F 36 49 C0
            9F E2 B6 9B 1A 4F D9 90 5A BD 51 95 78 95 EA 84
            D5 CD 2B 99 02 90 00 8E 08 6C 9C CD 20 7F 35 DE
            AD 90 00
            """,
        )

    /** The plain response data of General Authenticate, section 5.2: the chip's nonce `81` and token `82`. */
    val SM_CA_GENERAL_AUTHENTICATE_RESPONSE_DATA: ByteArray =
        hex("7C 14 81 08 42 87 B3 07 2A 3E DC 60 82 08 FF 01 17 D6 8D EE 8E 72")
}
