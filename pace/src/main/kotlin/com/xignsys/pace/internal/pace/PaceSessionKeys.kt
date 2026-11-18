package com.xignsys.pace.internal.pace

import com.xignsys.pace.internal.crypto.AesCbc
import com.xignsys.pace.internal.crypto.AesCmac

/**
 * The PACE session keys, ready for Secure Messaging: `K_Enc` in [encryption] and `K_MAC` in [mac] (TR-03110 Part 3,
 * A.2.3). The holder owns them and calls [destroy] when it no longer needs them. Not thread-safe.
 */
internal class PaceSessionKeys(
    /** AES-CBC with `K_Enc`. */
    val encryption: AesCbc,
    /** AES-CMAC with `K_MAC`. */
    val mac: AesCmac,
) {
    /** Overwrites both keys. Later calls have no effect. */
    fun destroy() {
        encryption.destroy()
        mac.destroy()
    }

    override fun toString(): String = "PaceSessionKeys"
}
