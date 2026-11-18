package com.xignsys.pace.fixtures

/** Published vectors of ICAO Doc 9303, 8th edition. Each value names its part and section. */
internal object IcaoExamples {
    /** SELECT of the master file, Part 10, section 3.6.1.1, Table 1: no `Lc`, no data, no `Le` (case 1). */
    val SELECT_MASTER_FILE: ByteArray = hex("00 A4 00 0C")

    /** SELECT of EF.COM, Part 11, Appendix D.4, unprotected: `Lc` and data, no `Le` (case 3, short). */
    val SELECT_EF_COM: ByteArray = hex("00 A4 02 0C 02 01 1E")

    /** READ BINARY of 18 bytes from offset 4, Part 11, Appendix D.4, unprotected: `Le` only (case 2, short). */
    val READ_BINARY_FROM_OFFSET_4: ByteArray = hex("00 B0 00 04 12")

    /** READ BINARY of the first four bytes, Part 11, Appendix D.4, protected: `Lc`, data, `Le` `00` (case 4). */
    val READ_BINARY_PROTECTED: ByteArray = hex("0C B0 00 00 0D 97 01 04 8E 08 ED 67 05 41 7E 96 BA 55 00")

    /** MSE:Set AT of the ECDH example, Part 11, Appendix G.1 (case 3, short). */
    val MSE_SET_AT_ECDH: ByteArray = hex("00 22 C1 A4 0F 80 0A 04 00 7F 00 07 02 02 04 02 02 83 01 01")

    /** PACEInfo of Part 11, Appendix G.1: ECDH, Generic Mapping, AES-128, version 2, parameter ID 13. */
    val PACE_INFO_ECDH_GM: ByteArray = hex("30 12 06 0A 04 00 7F 00 07 02 02 04 02 02 02 01 02 02 01 0D")

    /** PACEInfo of Part 11, Appendix G.2: DH, Generic Mapping, AES-128, version 2, parameter ID 0. */
    val PACE_INFO_DH_GM: ByteArray = hex("30 12 06 0A 04 00 7F 00 07 02 02 04 01 02 02 01 02 02 01 00")

    /** PACEInfo of Part 11, Appendix I.1: ECDH, Chip Authentication Mapping, AES-128, version 2, parameter ID 13. */
    val PACE_INFO_ECDH_CAM: ByteArray = hex("30 12 06 0A 04 00 7F 00 07 02 02 04 06 02 02 01 02 02 01 0D")

    /**
     * The brainpoolP256r1 domain parameters as an `AlgorithmIdentifier` with `id-ecPublicKey`, Part 11, Appendix G.1,
     * given there "for convenience" next to the PACEInfo.
     */
    val BRAINPOOL_P256R1_ALGORITHM_IDENTIFIER: ByteArray =
        hex(
            """
            30 81 EC 06 07 2A 86 48 CE 3D 02 01 30 81 E0 02 01 01
            30 2C 06 07 2A 86 48 CE 3D 01 01 02 21 00
            A9 FB 57 DB A1 EE A9 BC 3E 66 0A 90 9D 83 8D 72 6E 3B F6 23 D5 26 20 28 20 13 48 1D 1F 6E 53 77
            30 44 04 20
            7D 5A 09 75 FC 2C 30 57 EE F6 75 30 41 7A FF E7 FB 80 55 C1 26 DC 5C 6C E9 4A 4B 44 F3 30 B5 D9
            04 20
            26 DC 5C 6C E9 4A 4B 44 F3 30 B5 D9 BB D7 7C BF 95 84 16 29 5C F7 E1 CE 6B CC DC 18 FF 8C 07 B6
            04 41 04
            8B D2 AE B9 CB 7E 57 CB 2C 4B 48 2F FC 81 B7 AF B9 DE 27 E1 E3 BD 23 C2 3A 44 53 BD 9A CE 32 62
            54 7E F8 35 C3 DA C4 FD 97 F8 46 1A 14 61 1D C9 C2 77 45 13 2D ED 8E 54 5C 1D 54 C7 2F 04 69 97
            02 21 00
            A9 FB 57 DB A1 EE A9 BC 3E 66 0A 90 9D 83 8D 71 8C 39 7A A3 B5 61 A6 F7 90 1E 0E 82 97 48 56 A7
            02 01 01
            """,
        )
}
