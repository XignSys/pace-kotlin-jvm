package com.xignsys.pace.cardaccess

import com.xignsys.pace.fixtures.CardAccessMother
import com.xignsys.pace.fixtures.CardAccessMother.ECDH_CAM
import com.xignsys.pace.fixtures.CardAccessMother.ECDH_GM_AES_128
import com.xignsys.pace.fixtures.CardAccessMother.ECDH_IM_AES_256
import com.xignsys.pace.fixtures.CardAccessMother.EC_PUBLIC_KEY
import com.xignsys.pace.fixtures.CardAccessMother.PACE
import com.xignsys.pace.fixtures.CardAccessMother.cardAccess
import com.xignsys.pace.fixtures.CardAccessMother.paceDomainParameterInfo
import com.xignsys.pace.fixtures.CardAccessMother.paceInfo
import com.xignsys.pace.fixtures.CardAccessMother.sequence
import com.xignsys.pace.fixtures.CardAccessMother.terminalAuthenticationInfo
import com.xignsys.pace.fixtures.IcaoExamples
import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.junit.jupiter.api.Test
import java.math.BigInteger

/** EF.CardAccess as TR-03110 Part 3, A.1.1.1 and A.1.2.1, and ICAO 9303-11, section 9.2, define it. */
class CardAccessTest {
    @Test
    fun parsesTheCardAccessOfTheWorkedExample() {
        // Worked Example section 3: one PACEInfo; TerminalAuthenticationInfo, ChipAuthenticationInfo,
        // ChipAuthenticationDomainParameterInfo, CardInfo and PrivilegedTerminalInfo are skipped.
        val cardAccess = CardAccess.parse(WorkedExample.EF_CARD_ACCESS)

        assertThat(cardAccess.paceInfos).containsExactly(PaceInfo(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 2, 13))
        assertThat(cardAccess.paceDomainParameterInfos).isEmpty()
        assertThat(cardAccess.encoded).isEqualTo(WorkedExample.EF_CARD_ACCESS)
    }

    @Test
    fun parsesThePaceInfosOfIcaoAppendicesGAndI() {
        // ICAO 9303-11, Appendices G.1 (ECDH, GM, ID 13), G.2 (DH, GM, ID 0) and I.1 (ECDH, CAM, ID 13), in one set.
        val cardAccess =
            CardAccess.parse(
                cardAccess(
                    IcaoExamples.PACE_INFO_ECDH_GM,
                    IcaoExamples.PACE_INFO_DH_GM,
                    IcaoExamples.PACE_INFO_ECDH_CAM,
                ),
            )

        assertThat(cardAccess.paceInfos).containsExactly(
            PaceInfo(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 2, 13),
            PaceInfo(PaceProtocol.DH_GM_AES_CBC_CMAC_128, 2, 0),
            PaceInfo(PaceProtocol.ECDH_CAM_AES_CBC_CMAC_128, 2, 13),
        )
        assertThat(cardAccess.paceInfo(PaceProtocol.DH_GM_AES_CBC_CMAC_128, 0)).isNotNull()
        assertThat(cardAccess.paceInfo(PaceProtocol.DH_GM_AES_CBC_CMAC_128, 13)).isNull()
        assertThat(cardAccess.paceInfos.all { it.usesStandardizedDomainParameters }).isTrue()
    }

    @Test
    fun keepsPaceInfosThatAreOnlyUnusable() {
        // Version 1 is deprecated (TR-03110 Part 3, A.1.1.1) and the parameter ID optional; PACE refuses them later.
        val cardAccess =
            CardAccess.parse(
                cardAccess(paceInfo(version = 1), paceInfo(ECDH_IM_AES_256, parameterId = null)),
            )

        assertThat(cardAccess.paceInfos).containsExactly(
            PaceInfo(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 1, 13),
            PaceInfo(PaceProtocol.ECDH_IM_AES_CBC_CMAC_256, 2, null),
        )
        assertThat(cardAccess.paceInfos[1].usesStandardizedDomainParameters).isFalse()
    }

    @Test
    fun acceptsAFileWithoutPace() {
        // ICAO 9303-11, section 4.2, step 1: without PACE parameters the inspection system falls back to Basic Access Control.
        val cardAccess = CardAccess.parse(cardAccess(terminalAuthenticationInfo()))

        assertThat(cardAccess.paceInfos).isEmpty()
        assertThat(cardAccess.paceDomainParameterInfos).isEmpty()
    }

    @Test
    fun parsesExplicitDomainParameters() {
        // TR-03110 Part 3, A.1.1.1 and A.2.1.2; the brainpoolP256r1 parameters of ICAO 9303-11, Appendix G.1.
        val cardAccess =
            CardAccess.parse(
                cardAccess(
                    paceInfo(parameterId = 32),
                    paceDomainParameterInfo(parameterId = 32),
                    paceDomainParameterInfo(parameterId = 33, family = ECDH_CAM),
                ),
            )
        val first = cardAccess.paceDomainParameterInfos[0]

        assertThat(cardAccess.paceDomainParameterInfos).hasSize(2)
        assertThat(first.family).isEqualTo(PaceProtocol.Family.ECDH_GM)
        assertThat(first.algorithm).isEqualTo("1.2.840.10045.2.1")
        assertThat(first.parameterId).isEqualTo(32)
        assertThat(first.domainParameter).isEqualTo(IcaoExamples.BRAINPOOL_P256R1_ALGORITHM_IDENTIFIER)
        assertThat(cardAccess.paceDomainParameterInfos[1].family).isEqualTo(PaceProtocol.Family.ECDH_CAM)
        assertThat(cardAccess.paceInfos.single().usesStandardizedDomainParameters).isFalse()
    }

    @Test
    fun acceptsOnePaceDomainParameterInfoWithoutParameterId() {
        // TR-03110 Part 3, A.1.1.1: the ID MUST be used only if the chip provides several explicit sets.
        val cardAccess = CardAccess.parse(cardAccess(paceInfo(parameterId = null), paceDomainParameterInfo(null)))

        assertThat(cardAccess.paceDomainParameterInfos.single().parameterId).isNull()
    }

    @Test
    fun acceptsBer() {
        // The Worked Example's file with an indefinite-length SET instead of 31 81 C6 (BER, X.690 section 8.1.3.6).
        val definite = WorkedExample.EF_CARD_ACCESS
        val indefinite = hex("31 80") + definite.copyOfRange(3, definite.size) + hex("00 00")
        val cardAccess = CardAccess.parse(indefinite)

        assertThat(cardAccess.paceInfos).containsExactly(PaceInfo(PaceProtocol.ECDH_GM_AES_CBC_CMAC_128, 2, 13))
        assertThat(cardAccess.encoded).isEqualTo(indefinite)
    }

    @Test
    fun refusesWhatIsNotASetOfSecurityInfos() {
        assertMalformed(ByteArray(0), "not a SET")
        assertMalformed(hex("30 00"), "not a SET")
        assertMalformed(WorkedExample.EF_CARD_ACCESS + hex("00"), "single ASN.1 object")
        assertMalformed(hex("31 05 30 03 02 01"), "ASN.1")
    }

    @Test
    fun refusesSecurityInfosThatAreNotWellFormed() {
        assertMalformed(cardAccess(ASN1Integer(1)), "not a SEQUENCE")
        assertMalformed(cardAccess(sequence(ECDH_GM_AES_128)), "two or three elements")
        assertMalformed(
            cardAccess(sequence(ECDH_GM_AES_128, ASN1Integer(2), ASN1Integer(13), ASN1Integer(1))),
            "two or three elements",
        )
        assertMalformed(cardAccess(sequence(ASN1Integer(2), ASN1Integer(13))), "OBJECT IDENTIFIER")
    }

    @Test
    fun skipsSecurityInfosOfOtherProtocols() {
        // ICAO 9303-11, section 9.2: the inspection system MAY discard any unknown entry; id-PACE itself is neither a
        // protocol nor a family.
        val cardAccess =
            CardAccess.parse(cardAccess(terminalAuthenticationInfo(), sequence(PACE, ASN1Integer(2)), paceInfo()))

        assertThat(cardAccess.paceInfos).hasSize(1)
    }

    @Test
    fun refusesPaceInfosThatAreNotWellFormed() {
        assertMalformed(cardAccess(sequence(ECDH_GM_AES_128, DEROctetString(hex("02")))), "version is not an INTEGER")
        assertMalformed(cardAccess(paceInfo(version = -1)), "non-negative 32-bit")
        assertMalformed(
            cardAccess(sequence(ECDH_GM_AES_128, ASN1Integer(2), ASN1Integer(BigInteger.ONE.shiftLeft(31)))),
            "non-negative 32-bit",
        )
        assertMalformed(cardAccess(sequence(ECDH_GM_AES_128, ASN1Integer(2), DEROctetString(hex("0D")))), "INTEGER")
    }

    @Test
    fun refusesPaceDomainParameterInfosThatAreNotWellFormed() {
        val family = CardAccessMother.ECDH_GM

        assertMalformed(cardAccess(sequence(family, ASN1Integer(1))), "not a SEQUENCE")
        assertMalformed(cardAccess(sequence(family, DERSequence())), "one or two elements")
        assertMalformed(cardAccess(sequence(family, sequence(ASN1Integer(1)))), "no algorithm OID")
        assertMalformed(
            cardAccess(sequence(family, sequence(EC_PUBLIC_KEY, ASN1Integer(0), ASN1Integer(0)))),
            "one or two elements",
        )
        assertMalformed(cardAccess(paceDomainParameterInfo(parameterId = -1)), "non-negative 32-bit")
    }

    @Test
    fun refusesAmbiguousPaceInfos() {
        // MSE:Set AT names PACE by protocol and domain parameter ID (TR-03110 Part 3, B.14.1).
        assertMalformed(cardAccess(paceInfo(), paceInfo(version = 1)), "same protocol and parameter ID")
        assertMalformed(
            cardAccess(paceInfo(parameterId = null), paceInfo(parameterId = null)),
            "same protocol and parameter ID",
        )
    }

    @Test
    fun refusesAmbiguousPaceDomainParameterInfos() {
        // TR-03110 Part 3, A.1.1.1, and ICAO 9303-11, section 9.2.2: with several explicit sets, each has an ID.
        assertMalformed(cardAccess(paceDomainParameterInfo(32), paceDomainParameterInfo(null)), "each must have")
        assertMalformed(cardAccess(paceDomainParameterInfo(null), paceDomainParameterInfo(null)), "each must have")
        assertMalformed(cardAccess(paceDomainParameterInfo(32), paceDomainParameterInfo(32)), "same parameter ID")
    }

    @Test
    fun refusesExplicitDomainParametersWithAStandardizedId() {
        // TR-03110 Part 3, A.2.1: explicit domain parameters MUST NOT use the IDs of Table 4, 0 to 31.
        assertMalformed(cardAccess(paceDomainParameterInfo(31)), "reserved for standardized")
        assertMalformed(cardAccess(paceDomainParameterInfo(0)), "reserved for standardized")
        assertThat(CardAccess.parse(cardAccess(paceDomainParameterInfo(32))).paceDomainParameterInfos).hasSize(1)
    }

    @Test
    fun copiesTheFileInAndOut() {
        val encoded = WorkedExample.EF_CARD_ACCESS.copyOf()
        val cardAccess = CardAccess.parse(encoded)

        encoded[0] = 0
        cardAccess.encoded[1] = 0

        assertThat(cardAccess.encoded).isEqualTo(WorkedExample.EF_CARD_ACCESS)
    }

    @Test
    fun showsCountsOnlyInToString() {
        assertThat(CardAccess.parse(WorkedExample.EF_CARD_ACCESS).toString())
            .isEqualTo("CardAccess(paceInfos=1, paceDomainParameterInfos=0)")
        assertThat(
            CardAccess
                .parse(cardAccess(paceDomainParameterInfo()))
                .paceDomainParameterInfos
                .single()
                .toString(),
        ).isEqualTo(
            "PaceDomainParameterInfo(ECDH_GM, algorithm=1.2.840.10045.2.1, parameterId=32, domainParameterLength=239)",
        )
    }

    private fun assertMalformed(encoded: ByteArray, message: String) {
        assertThatThrownBy { CardAccess.parse(encoded) }
            .isInstanceOf(MalformedCardAccessException::class.java)
            .hasMessageContaining(message)
    }
}
