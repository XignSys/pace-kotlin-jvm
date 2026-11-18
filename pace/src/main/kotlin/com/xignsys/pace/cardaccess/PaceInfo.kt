package com.xignsys.pace.cardaccess

/**
 * A `PACEInfo` of EF.CardAccess: one PACE protocol the card offers (TR-03110 Part 3, A.1.1.1; ICAO 9303-11, section
 * 9.2.1).
 *
 * Built by [CardAccess.parse] only. Immutable and thread-safe.
 */
public class PaceInfo internal constructor(
    /** The protocol: mapping, key agreement and cipher. */
    public val protocol: PaceProtocol,
    /** The protocol version as the card states it; version 2 is the current one, version 1 is deprecated. */
    public val version: Int,
    /**
     * The domain parameter ID: one of [STANDARDIZED_DOMAIN_PARAMETER_IDS], or the ID of the explicit domain parameters
     * of a [PaceDomainParameterInfo]; `null` if the card leaves it out.
     */
    public val parameterId: Int?,
) {
    /** Whether [parameterId] names standardized domain parameters (TR-03110 Part 3, Table 4). */
    public val usesStandardizedDomainParameters: Boolean
        get() = parameterId?.let { it in STANDARDIZED_DOMAIN_PARAMETER_IDS } == true

    override fun equals(other: Any?): Boolean =
        other is PaceInfo && other.protocol == protocol && other.version == version && other.parameterId == parameterId

    override fun hashCode(): Int = (protocol.hashCode() * HASH_FACTOR + version) * HASH_FACTOR + (parameterId ?: -1)

    override fun toString(): String = "PaceInfo($protocol, version=$version, parameterId=$parameterId)"

    /** The range of standardized domain parameter IDs. */
    public companion object {
        /**
         * The IDs reserved for standardized domain parameters, 0 to 31 (TR-03110 Part 3, Table 4 and A.2.1); explicit
         * domain parameters must not use them.
         */
        @JvmField
        public val STANDARDIZED_DOMAIN_PARAMETER_IDS: IntRange = 0..31

        private const val HASH_FACTOR = 31
    }
}
