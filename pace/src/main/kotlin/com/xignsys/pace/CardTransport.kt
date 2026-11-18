package com.xignsys.pace

import java.io.IOException

/**
 * The byte-level connection to a contactless card, for example `android.nfc.tech.IsoDep` or a `javax.smartcardio`
 * channel. The caller implements it; the library sends command APDUs through it and reads the response APDUs.
 *
 * Calls block until the card answers. To abort a running call, close the connection, so that the call throws
 * [IOException].
 */
public fun interface CardTransport {
    /**
     * Sends the command APDU [command] to the card and returns its response APDU, the response data followed by the
     * status word `SW1 SW2`.
     *
     * @throws IOException if the connection to the card fails or has been closed.
     */
    @Throws(IOException::class)
    public fun transceive(command: ByteArray): ByteArray
}
