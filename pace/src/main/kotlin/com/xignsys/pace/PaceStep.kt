package com.xignsys.pace

/** The commands of PACE, in the order they are sent (TR-03110 Part 3, B.1; ICAO 9303-11, section 4.4.4). */
public enum class PaceStep {
    /** MSE:Set AT, which selects the protocol, the password, the domain parameters and the CHAT. */
    SET_AUTHENTICATION_TEMPLATE,

    /** General Authenticate, step 1: the chip's encrypted nonce. */
    ENCRYPTED_NONCE,

    /** General Authenticate, step 2: the mapping of the nonce. */
    MAP_NONCE,

    /** General Authenticate, step 3: the key agreement with the ephemeral public keys. */
    KEY_AGREEMENT,

    /** General Authenticate, step 4: the authentication tokens and the CA references. */
    MUTUAL_AUTHENTICATION,
}
