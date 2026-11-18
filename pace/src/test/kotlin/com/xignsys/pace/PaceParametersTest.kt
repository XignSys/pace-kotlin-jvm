package com.xignsys.pace

import com.xignsys.pace.cardaccess.CardAccess
import com.xignsys.pace.cardaccess.PaceProtocol
import com.xignsys.pace.fixtures.CardAccessMother
import com.xignsys.pace.fixtures.CertificateExtensionsMother
import com.xignsys.pace.fixtures.IcaoExamples
import com.xignsys.pace.fixtures.WorkedExample
import com.xignsys.pace.fixtures.hex
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatIllegalArgumentException
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/** The parameters of PACE and the default choice from EF.CardAccess. */
class PaceParametersTest {
    private val protocol = PaceProtocol.ECDH_GM_AES_CBC_CMAC_128

    @Test
    fun keepsACopyOfTheChat() {
        val chat = WorkedExample.PACE_CHAT.copyOf()
        val parameters = PaceParameters(protocol, 13, chat)

        chat.fill(0)
        parameters.chat?.fill(0)

        assertThat(parameters.chat).isEqualTo(WorkedExample.PACE_CHAT)
        assertThat(PaceParameters(protocol, 13).chat).isNull()
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "",
            // the Worked Example CHAT with a trailing byte, truncated, with a length that is not DER
            "7F 4C 12 06 09 04 00 7F 00 07 03 01 02 02 53 05 00 00 00 01 10 00",
            "7F 4C 12 06 09 04 00 7F 00 07 03 01 02 02 53 05 00 00 00 01",
            "7F 4C 81 12 06 09 04 00 7F 00 07 03 01 02 02 53 05 00 00 00 01 10",
            // another tag: a certificate body 7F4E, the certificate extensions 65, the content without its tag
            "7F 4E 12 06 09 04 00 7F 00 07 03 01 02 02 53 05 00 00 00 01 10",
            "65 00",
            "06 09 04 00 7F 00 07 03 01 02 02",
        ],
    )
    fun refusesAChatThatIsNotOneDerDataObject7F4C(encoded: String) {
        // TR-03110 Part 3, B.14.1 and C.1.5: the CHAT is the data object 7F4C.
        assertThatIllegalArgumentException()
            .isThrownBy { PaceParameters(protocol, 13, hex(encoded)) }
            .withMessageContaining("7F4C")
    }

    @Test
    fun keepsACopyOfTheCertificateExtensions() {
        val extensions = CertificateExtensionsMother.EID_ACCESS.copyOf()
        val parameters = PaceParameters(protocol, 13, WorkedExample.PACE_CHAT, extensions)

        extensions.fill(0)
        parameters.certificateExtensions?.fill(0)

        assertThat(parameters.certificateExtensions).isEqualTo(CertificateExtensionsMother.EID_ACCESS)
        assertThat(PaceParameters(protocol, 13, WorkedExample.PACE_CHAT).certificateExtensions).isNull()
        assertThat(
            PaceParameters(
                protocol,
                13,
                WorkedExample.PACE_CHAT,
                CertificateExtensionsMother.EID_ACCESS_AND_SPECIAL_FUNCTIONS,
            ).certificateExtensions,
        ).isEqualTo(CertificateExtensionsMother.EID_ACCESS_AND_SPECIAL_FUNCTIONS)
    }

    @Test
    fun acceptsAnyDataObjectsAfterTheObjectIdentifier() {
        // TR-03110 Part 3, C.3.2.1: the terminal sector extension id-sector (0.4.0.127.0.7.3.1.3.2) with two hashes in
        // the context-specific data objects 80 and 81.
        val sector =
            CertificateExtensionsMother.extensions(
                CertificateExtensionsMother.template(
                    hex("06 09 04 00 7F 00 07 03 01 03 02"),
                    CertificateExtensionsMother.tlv(0x80, ByteArray(32)),
                    CertificateExtensionsMother.tlv(0x81, ByteArray(32)),
                ),
            )

        assertThat(
            PaceParameters(protocol, 13, WorkedExample.PACE_CHAT, sector).certificateExtensions,
        ).isEqualTo(sector)
    }

    @ParameterizedTest
    @ValueSource(
        strings = [
            "",
            // no template, a template without the object identifier, a template with the object identifier only
            "65 00",
            "65 05 73 03 53 01 80",
            "65 08 73 06 53 01 80 53 01 80",
            "65 0E 73 0C 06 0A 04 00 7F 00 07 03 01 02 02 01",
            // a template 74 instead of 73, a primitive 45 instead of the constructed 65, another outer tag 64
            "65 11 74 0F 06 0A 04 00 7F 00 07 03 01 02 02 02 53 01 80",
            "45 11 73 0F 06 0A 04 00 7F 00 07 03 01 02 02 02 53 01 80",
            "64 11 73 0F 06 0A 04 00 7F 00 07 03 01 02 02 02 53 01 80",
            // a trailing byte, a length that is not DER, two data objects 65
            "65 11 73 0F 06 0A 04 00 7F 00 07 03 01 02 02 02 53 01 80 00",
            "65 81 11 73 0F 06 0A 04 00 7F 00 07 03 01 02 02 02 53 01 80",
            "65 03 73 01 00 65 03 73 01 00",
        ],
    )
    fun refusesCertificateExtensionsThatBreakTheirStructure(encoded: String) {
        // TR-03110 Part 3, C.3: 65 holds discretionary data templates 73, each an object identifier followed by data
        // objects.
        assertThatIllegalArgumentException()
            .isThrownBy { PaceParameters(protocol, 13, WorkedExample.PACE_CHAT, hex(encoded)) }
            .withMessage(
                "The certificate extensions must be exactly one DER-encoded data object with the tag 65 that holds " +
                    "discretionary data templates 73, each an object identifier followed by data objects.",
            )
    }

    @Test
    fun refusesCertificateExtensionsWithoutAChat() {
        // TR-03110 Part 3, B.14.1: both serve Terminal Authentication version 2.
        assertThatIllegalArgumentException()
            .isThrownBy { PaceParameters(protocol, 13, null, CertificateExtensionsMother.EID_ACCESS) }
            .withMessage("Certificate extensions need a CHAT.")
        assertThatIllegalArgumentException()
            .isThrownBy {
                PaceParameters.defaultFor(
                    CardAccess.parse(WorkedExample.EF_CARD_ACCESS),
                    null,
                    CertificateExtensionsMother.EID_ACCESS,
                )
            }.withMessage("Certificate extensions need a CHAT.")
    }

    @Test
    fun refusesWhatDoesNotFitMseSetAtInShortLength() {
        // TR-03110 Part 3, B.12.2; the limit of 200 bytes beside the Worked Example CHAT is derived in PaceCommandsTest.
        PaceParameters(protocol, 13, WorkedExample.PACE_CHAT, CertificateExtensionsMother.ofSize(200))

        assertThatIllegalArgumentException()
            .isThrownBy {
                PaceParameters(
                    protocol,
                    13,
                    WorkedExample.PACE_CHAT,
                    CertificateExtensionsMother.ofSize(201),
                )
            }.withMessage("The CHAT and the certificate extensions are too long for MSE:Set AT in short length.")
        // An ID that does not fit one byte is not checked here; PACE refuses it as not supported.
        PaceParameters(protocol, 256, WorkedExample.PACE_CHAT, CertificateExtensionsMother.ofSize(201))
    }

    @Test
    fun refusesANegativeDomainParameterId() {
        assertThatIllegalArgumentException().isThrownBy { PaceParameters(protocol, -1) }
    }

    @Test
    fun choosesTheImplementedPaceInfoOfTheWorkedExample() {
        // Worked Example section 3: one PACEInfo, ECDH, Generic Mapping, AES-128, version 2, ID 13.
        val parameters = checkNotNull(PaceParameters.defaultFor(CardAccess.parse(WorkedExample.EF_CARD_ACCESS)))

        assertThat(parameters.protocol).isEqualTo(protocol)
        assertThat(parameters.domainParameterId).isEqualTo(13)
        assertThat(parameters.chat).isNull()
    }

    @Test
    fun choosesByTheLibrarysPreferenceNotByFileOrder() {
        // ICAO 9303-11, Appendices I.1 and G.1: Chip Authentication Mapping listed before Generic Mapping on ID 13.
        val cardAccess =
            CardAccess.parse(
                CardAccessMother.cardAccess(IcaoExamples.PACE_INFO_ECDH_CAM, IcaoExamples.PACE_INFO_ECDH_GM),
            )
        val parameters = checkNotNull(PaceParameters.defaultFor(cardAccess, WorkedExample.PACE_CHAT))

        assertThat(parameters.protocol).isEqualTo(protocol)
        assertThat(parameters.domainParameterId).isEqualTo(13)
        assertThat(parameters.chat).isEqualTo(WorkedExample.PACE_CHAT)
    }

    @Test
    fun choosesNothingWhenTheCardOffersNothingImplemented() {
        // ICAO 9303-11, Appendix G.2 (DH); a PACEInfo of version 1 (section 9.2.1: MUST be 2); ID 19 (RFU, Table 4).
        val offers =
            listOf(
                CardAccessMother.cardAccess(IcaoExamples.PACE_INFO_DH_GM),
                CardAccessMother.cardAccess(CardAccessMother.paceInfo(version = 1)),
                CardAccessMother.cardAccess(CardAccessMother.paceInfo(parameterId = 19)),
                CardAccessMother.cardAccess(CardAccessMother.terminalAuthenticationInfo()),
            )

        for (offer in offers) {
            assertThat(PaceParameters.defaultFor(CardAccess.parse(offer))).isNull()
        }
    }

    @Test
    fun choosesChipAuthenticationMappingWhenTheCardOffersNothingElse() {
        // ICAO 9303-11, Appendix I.1: Chip Authentication Mapping with AES-128 on ID 13 only.
        val parameters =
            checkNotNull(
                PaceParameters.defaultFor(
                    CardAccess.parse(CardAccessMother.cardAccess(IcaoExamples.PACE_INFO_ECDH_CAM)),
                ),
            )

        assertThat(parameters.protocol).isEqualTo(PaceProtocol.ECDH_CAM_AES_CBC_CMAC_128)
        assertThat(parameters.domainParameterId).isEqualTo(13)
    }

    @Test
    fun showsNoChatInToString() {
        assertThat(PaceParameters(protocol, 13, WorkedExample.PACE_CHAT).toString())
            .isEqualTo(
                "PaceParameters(ECDH_GM_AES_CBC_CMAC_128, domainParameterId=13, chat=true, certificateExtensions=false)",
            )
        assertThat(
            PaceParameters(protocol, 13, WorkedExample.PACE_CHAT, CertificateExtensionsMother.EID_ACCESS).toString(),
        ).isEqualTo(
            "PaceParameters(ECDH_GM_AES_CBC_CMAC_128, domainParameterId=13, chat=true, certificateExtensions=true)",
        )
    }
}
