package com.xignsys.pace

import com.xignsys.pace.apdu.ResponseApdu

/** The outcome of one command on the [SecureMessagingChannel]. */
public sealed class SecureMessagingResult {
    /** The card's [response], checked and unprotected, whatever its status word. */
    public class Response(
        /** The unprotected response with the status word the MAC protects. */
        public val response: ResponseApdu,
    ) : SecureMessagingResult() {
        override fun toString(): String = "Response($response)"
    }

    /** The command cannot be protected. Nothing was sent; the channel stays open and its state is unchanged. */
    public sealed class Refused : SecureMessagingResult() {
        /**
         * The class byte is not one of the first interindustry class with at most command chaining (`10`) and a
         * logical channel (`03`), or it already indicates Secure Messaging; only such a class byte can carry the
         * Secure Messaging bits `0C` (TR-03110 Part 3, F.3).
         */
        public data object UnsupportedClass : Refused()

        /**
         * The instruction byte is odd. TR-03110 Part 3, F.3, covers even instruction bytes only; ICAO 9303-11, section
         * 9.8.4, protects odd ones with data object `85`, which the library does not implement.
         */
        public data object OddInstruction : Refused()

        /**
         * The protected form of the command needs a data field of [protectedDataLength] bytes, more than the length
         * form of the command allows: more than 255 bytes in short length or, despite the name, more than 65 535 bytes
         * in extended length (ISO/IEC 7816-4 length fields). The library keeps the length form the caller chose; for a
         * command in short length, the caller may build it in extended length where the card allows it (TR-03110 Part
         * 3, B.12.2).
         */
        public class TooLongForShortLength(
            /** The length of the data field of the protected command, `Lc'`. */
            public val protectedDataLength: Int,
        ) : Refused() {
            override fun equals(other: Any?): Boolean =
                other is TooLongForShortLength && other.protectedDataLength == protectedDataLength

            override fun hashCode(): Int = protectedDataLength

            override fun toString(): String = "TooLongForShortLength(protectedDataLength=$protectedDataLength)"
        }
    }

    /**
     * The response did not pass Secure Messaging: it has no Secure Messaging data objects, as when the card has aborted
     * Secure Messaging (TR-03110 Part 3, F.6; ICAO 9303-11, section 9.8.5), or its structure, MAC, status word or
     * padding is wrong. The response is not passed on; the channel is closed and the keys are overwritten.
     */
    public data object Failed : SecureMessagingResult()
}
