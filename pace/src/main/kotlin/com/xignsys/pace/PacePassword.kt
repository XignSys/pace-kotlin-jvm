package com.xignsys.pace

import com.xignsys.pace.internal.crypto.wipe

/**
 * A password for PACE: the card access number ([Can]), the data of the machine readable zone ([Mrz]), the [Pin] or the
 * [Puk]. The type selects the password the card checks (TR-03110 Part 3, B.14.1).
 *
 * Every password and every input value checks its own rules when it is built: input that breaks a rule of the
 * specifications throws [IllegalArgumentException] at once, before anything is sent to a card. The messages are part of
 * the API: each factory and constructor lists the messages it throws, so that an application can show them or map them
 * to its own texts. They name the rule, never the characters, and a change to one is noted in the changelog.
 *
 * **Ownership:** a password takes over the characters it is built from. A `CharArray` passed in is not copied; it is
 * overwritten with `U+0000` when it is refused, when [wipe] is called, and when the PACE call that uses the password
 * ends, whatever its outcome. The caller must not read, change or reuse such an array afterwards. A password serves one
 * PACE call; a password that is no longer needed, for example because the user cancelled, should be wiped.
 *
 * [toString] never shows the characters. Not thread-safe: do not call [wipe] while PACE runs with the password.
 */
public sealed class PacePassword {
    /** The password reference of MSE:Set AT, data object `83` (TR-03110 Part 3, B.14.1). */
    internal abstract val reference: Int

    /**
     * The characters the password encoding is computed from (TR-03110 Part 3, Table 5), not a copy. No password accepts
     * `U+0000` and none is empty, so characters that have been overwritten are recognised by the first one.
     */
    internal abstract val characters: CharArray

    /** Overwrites the characters with `U+0000`; PACE then refuses the password. Can be called more than once. */
    public fun wipe() {
        characters.wipe()
    }
}
