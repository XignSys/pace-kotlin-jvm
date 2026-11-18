package com.xignsys.pace.fixtures

import com.xignsys.pace.CardTransport
import java.io.IOException

/**
 * A card that expects exactly the given [exchanges] in order: each command must equal the expected one byte for byte,
 * and the card then answers or fails as scripted. Any other command fails the test with an [AssertionError].
 */
internal class FakeCardTransport(vararg exchanges: Exchange) : CardTransport {
    private val remaining = ArrayDeque(exchanges.toList())

    /** Copies of the commands received, in order. */
    val commands: MutableList<ByteArray> = mutableListOf()

    /** Whether every scripted exchange has taken place. */
    val isExhausted: Boolean
        get() = remaining.isEmpty()

    override fun transceive(command: ByteArray): ByteArray {
        commands.add(command.copyOf())

        val next = remaining.removeFirstOrNull() ?: throw AssertionError("Unexpected command ${commands.size}.")

        if (!next.command.contentEquals(command)) {
            throw AssertionError("Command ${commands.size} differs from the expected one.")
        }

        return when (next) {
            is Exchange.Respond -> next.response.copyOf()
            is Exchange.Fail -> throw IOException("The connection to the card was lost.")
        }
    }

    /** One scripted command and the card's reaction. */
    sealed class Exchange(val command: ByteArray) {
        /** The card answers [command] with [response]. */
        class Respond(command: ByteArray, val response: ByteArray) : Exchange(command)

        /** The connection fails when [command] is sent. */
        class Fail(command: ByteArray) : Exchange(command)
    }
}
