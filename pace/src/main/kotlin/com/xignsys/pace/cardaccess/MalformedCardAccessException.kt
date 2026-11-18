package com.xignsys.pace.cardaccess

/**
 * The content of EF.CardAccess breaks a structural rule of TR-03110 Part 3, A.1, or ICAO 9303-11, section 9.2, or is
 * ambiguous. The message names the rule, never content of the file.
 */
public class MalformedCardAccessException internal constructor(message: String, cause: Throwable? = null) :
    Exception(message, cause)
