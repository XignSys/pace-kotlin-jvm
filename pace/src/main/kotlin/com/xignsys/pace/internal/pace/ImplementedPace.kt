package com.xignsys.pace.internal.pace

import com.xignsys.pace.cardaccess.PaceDomainParameterInfo
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.internal.crypto.AesKey
import com.xignsys.pace.internal.crypto.EcDomain
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers

/**
 * The PACE variants the library implements, each a protocol with standardized domain parameters, and the order a
 * default choice prefers them in.
 *
 * Today these are PACE with ECDH, Generic Mapping or Chip Authentication Mapping and AES-128, AES-192 or AES-256 on the
 * standardized domain parameters with the Brainpool curves of RFC 5639 and the NIST curves of RFC 5114, every ECDH ID
 * of TR-03110 Part 3, Table 4 (ICAO 9303-11, sections 4.4.3.2 and 9.5.1).
 */
internal object ImplementedPace {
    /** The only `PACEInfo` version implemented (ICAO 9303-11, section 9.2.1; TR-03110 Part 3, A.1.1.1). */
    const val VERSION: Int = 2

    /** The standardized domain parameter ID of NIST P-192 (secp192r1), deprecated (TR-03110 Part 3, Table 4). */
    private const val NIST_P192_PARAMETER_ID = 8

    /** The standardized domain parameter ID of brainpoolP192r1, deprecated (TR-03110 Part 3, Table 4). */
    private const val BRAINPOOL_P192R1_PARAMETER_ID = 9

    /** The standardized domain parameter ID of NIST P-224 (secp224r1) (TR-03110 Part 3, Table 4). */
    private const val NIST_P224_PARAMETER_ID = 10

    /** The standardized domain parameter ID of brainpoolP224r1 (TR-03110 Part 3, Table 4). */
    private const val BRAINPOOL_P224R1_PARAMETER_ID = 11

    /** The standardized domain parameter ID of NIST P-256 (secp256r1) (TR-03110 Part 3, Table 4). */
    private const val NIST_P256_PARAMETER_ID = 12

    /** The standardized domain parameter ID of brainpoolP256r1 (TR-03110 Part 3, Table 4). */
    const val BRAINPOOL_P256R1_PARAMETER_ID: Int = 13

    /** The standardized domain parameter ID of brainpoolP320r1 (TR-03110 Part 3, Table 4). */
    private const val BRAINPOOL_P320R1_PARAMETER_ID = 14

    /** The standardized domain parameter ID of NIST P-384 (secp384r1) (TR-03110 Part 3, Table 4). */
    private const val NIST_P384_PARAMETER_ID = 15

    /** The standardized domain parameter ID of brainpoolP384r1 (TR-03110 Part 3, Table 4). */
    private const val BRAINPOOL_P384R1_PARAMETER_ID = 16

    /** The standardized domain parameter ID of brainpoolP512r1 (TR-03110 Part 3, Table 4). */
    private const val BRAINPOOL_P512R1_PARAMETER_ID = 17

    /** The standardized domain parameter ID of NIST P-521 (secp521r1) (TR-03110 Part 3, Table 4). */
    private const val NIST_P521_PARAMETER_ID = 18

    /**
     * The domain parameters of every implemented standardized ID, built on first use (TR-03110 Part 3, Table 4; RFC
     * 5639 for the Brainpool curves, RFC 5114 for the NIST curves).
     */
    private val DOMAINS: Map<Int, Lazy<EcDomain>> =
        mapOf(
            NIST_P192_PARAMETER_ID to lazy { EcDomain.nist(SECObjectIdentifiers.secp192r1) },
            BRAINPOOL_P192R1_PARAMETER_ID to lazy { EcDomain.brainpool(TeleTrusTObjectIdentifiers.brainpoolP192r1) },
            NIST_P224_PARAMETER_ID to lazy { EcDomain.nist(SECObjectIdentifiers.secp224r1) },
            BRAINPOOL_P224R1_PARAMETER_ID to lazy { EcDomain.brainpool(TeleTrusTObjectIdentifiers.brainpoolP224r1) },
            NIST_P256_PARAMETER_ID to lazy { EcDomain.nist(SECObjectIdentifiers.secp256r1) },
            BRAINPOOL_P256R1_PARAMETER_ID to lazy { EcDomain.brainpool(TeleTrusTObjectIdentifiers.brainpoolP256r1) },
            BRAINPOOL_P320R1_PARAMETER_ID to lazy { EcDomain.brainpool(TeleTrusTObjectIdentifiers.brainpoolP320r1) },
            NIST_P384_PARAMETER_ID to lazy { EcDomain.nist(SECObjectIdentifiers.secp384r1) },
            BRAINPOOL_P384R1_PARAMETER_ID to lazy { EcDomain.brainpool(TeleTrusTObjectIdentifiers.brainpoolP384r1) },
            BRAINPOOL_P512R1_PARAMETER_ID to lazy { EcDomain.brainpool(TeleTrusTObjectIdentifiers.brainpoolP512r1) },
            NIST_P521_PARAMETER_ID to lazy { EcDomain.nist(SECObjectIdentifiers.secp521r1) },
        )

    /**
     * IDs whose usage TR-03110 Part 3 deprecates (note to Table 4): implemented, because documents may still use them,
     * but never chosen by default.
     */
    private val DEPRECATED_PARAMETER_IDS: Set<Int> = setOf(NIST_P192_PARAMETER_ID, BRAINPOOL_P192R1_PARAMETER_ID)

    /**
     * The implemented protocols and the size of their AES keys (TR-03110 Part 3, A.1.1.1 and A.2.3.2; ICAO 9303-11,
     * section 4.4.3.2): Generic Mapping, then Chip Authentication Mapping.
     */
    private val PROTOCOLS: Map<PaceProtocol, AesKey.Size> =
        mapOf(
            PaceProtocol.ECDH_GM_AES_CBC_CMAC_128 to AesKey.Size.AES_128,
            PaceProtocol.ECDH_GM_AES_CBC_CMAC_192 to AesKey.Size.AES_192,
            PaceProtocol.ECDH_GM_AES_CBC_CMAC_256 to AesKey.Size.AES_256,
            PaceProtocol.ECDH_CAM_AES_CBC_CMAC_128 to AesKey.Size.AES_128,
            PaceProtocol.ECDH_CAM_AES_CBC_CMAC_192 to AesKey.Size.AES_192,
            PaceProtocol.ECDH_CAM_AES_CBC_CMAC_256 to AesKey.Size.AES_256,
        )

    /** The baseline of BSI TR-03116-2 for PACE: ECDH, Generic Mapping and AES-128 on brainpoolP256r1. */
    private val BASELINE: Pair<PaceProtocol, Int> =
        PaceProtocol.ECDH_GM_AES_CBC_CMAC_128 to BRAINPOOL_P256R1_PARAMETER_ID

    /**
     * The variants a default choice may take, the preferred first: the baseline, then Generic Mapping before Chip
     * Authentication Mapping and, for each, the longer AES keys first and, for each key size, the larger curves first,
     * which are the higher IDs of Table 4. Deprecated IDs are left out.
     */
    val VARIANTS: List<Pair<PaceProtocol, Int>> =
        listOf(BASELINE) +
            PROTOCOLS.entries
                .sortedWith(
                    compareBy<Map.Entry<PaceProtocol, AesKey.Size>> {
                        it.key.mapping == PaceProtocol.Mapping.CHIP_AUTHENTICATION
                    }.thenByDescending { it.value.bytes },
                ).flatMap { (protocol, _) ->
                    DOMAINS.keys
                        .filter { it !in DEPRECATED_PARAMETER_IDS }
                        .sortedDescending()
                        .map { protocol to it }
                }.filter { it != BASELINE }

    /** Whether the library implements [protocol], with standardized or recognized explicit domain parameters. */
    fun implements(protocol: PaceProtocol): Boolean = protocol in PROTOCOLS

    /**
     * The standardized domain parameters that the explicit ones of [info] describe, or `null` if they are none of the
     * implemented curves (see [ExplicitDomainParameters]).
     */
    fun explicitDomain(info: PaceDomainParameterInfo): EcDomain? =
        ExplicitDomainParameters.recognize(info, DOMAINS.values.map { it.value })

    /** Whether the library implements [protocol] with the standardized domain parameters [parameterId]. */
    fun supports(protocol: PaceProtocol, parameterId: Int): Boolean = protocol in PROTOCOLS && parameterId in DOMAINS

    /** The domain parameters with the standardized ID [parameterId], or `null` if they are not implemented. */
    fun domain(parameterId: Int): EcDomain? = DOMAINS[parameterId]?.value

    /**
     * The size of the AES keys of [protocol] (TR-03110 Part 3, A.2.3.2).
     *
     * @throws IllegalArgumentException if the library does not implement [protocol].
     */
    fun keySize(protocol: PaceProtocol): AesKey.Size =
        requireNotNull(PROTOCOLS[protocol]) { "The protocol is not implemented." }
}
