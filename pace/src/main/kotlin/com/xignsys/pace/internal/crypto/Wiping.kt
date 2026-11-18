package com.xignsys.pace.internal.crypto

import org.bouncycastle.util.Arrays

/** Overwrites every byte with zero. Used for keys, nonces, shared secrets and encoded passwords. */
internal fun ByteArray.wipe() {
    fill(0)
}

/** Overwrites every character with `U+0000`. Used for passwords and their input values. */
internal fun CharArray.wipe() {
    fill(Char.MIN_VALUE)
}

/**
 * Like [require]: throws [IllegalArgumentException] with the result of [message] if [condition] is false, but
 * overwrites this array first, so that a refused password does not stay in memory.
 */
internal inline fun CharArray.requireOrWipe(condition: Boolean, message: () -> String) {
    if (!condition) {
        wipe()

        throw IllegalArgumentException(message())
    }
}

/**
 * Compares two arrays in time that does not depend on where they differ, with Bouncy Castle. Used for authentication
 * tokens and MACs. Arrays of different length are not equal.
 */
internal fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = Arrays.constantTimeAreEqual(a, b)
