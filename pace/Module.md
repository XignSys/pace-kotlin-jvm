# Module pace

Password Authenticated Connection Establishment (PACE) and PACE Secure Messaging for contactless
cards that implement PACE, such as electronic identity cards and electronic passports (BSI TR-03110,
ICAO Doc 9303 Part 11), for Kotlin and the JVM.

The library reaches the card through a byte-level transport that the caller implements, for
example on top of Android's `IsoDep` or `javax.smartcardio`. It uses no platform API, so it runs on
Android (API level 26 or newer) and on any JVM (Java 17 or newer).

## Where to start

1. Read EF.CardAccess from the card and parse it with `CardAccess.parse`.
2. Choose the PACE to run with `PaceParameters.defaultFor`, or build `PaceParameters` from one of
   the card's `PaceInfo` entries.
3. Build the password: `Can`, `Mrz`, `Pin` or `Puk`.
4. Call `Pace.establish` with a `CardTransport`. It returns a `PaceResult`: `Established` with a
   `SecureMessagingChannel`, or a failure that names the `PaceStep` it happened in.
5. Send every further command through the channel, which protects it and checks the response.

## What to rely on

- The public API is in the three packages below. Everything under `com.xignsys.pace.internal` is
  not part of it and can change in any release.
- No type of Bouncy Castle appears in a public signature, although the library computes with it.
- The library logs and prints nothing.
- Passwords and keys are overwritten when they are no longer needed. The `toString` of a class
  that holds secret or card data never shows it.
- Whatever a card answers, PACE and Secure Messaging end with a typed result. The only exceptions
  are the transport's `IOException`, which is passed on unchanged, and those documented for wrong
  use, such as a password that has been used before.

# Package com.xignsys.pace

Running PACE, its passwords and the Secure Messaging channel that follows.

`Pace.establish` runs PACE through a `CardTransport` with `PaceParameters` and a password, and
returns a `PaceResult`. `PaceResult.Established` holds the chip's ephemeral public key, the
Certification Authority References the card returned and the `SecureMessagingChannel`. After PACE
with Chip Authentication Mapping it also holds the `ChipAuthenticationData`, with which the caller
verifies the chip's static public key. A second `Pace.establish` through an open channel resumes a
suspended PIN or PUK.

The sealed `PacePassword` has `Can`, `Mrz`, `Pin` and `Puk`. Every password is checked when it is
built, so that wrong input fails before anything is sent to a card. The MRZ password is built from
the document number and the two dates, from the MRZ information, or from the whole machine readable
zone of a TD1 size document; the library computes or verifies the check digits. A password serves
one call and is overwritten afterwards.

`SecureMessagingChannel.transceive` protects a command, sends it and returns a
`SecureMessagingResult` with the checked, unprotected response. `handOver` ends Secure Messaging
without sending anything and returns the transport, so that the caller can continue on the same
connection.

# Package com.xignsys.pace.apdu

Command and response APDUs and status words (ISO/IEC 7816-4).

`CommandApdu` covers all four cases in short or extended length, and is parsed and encoded in the
form it was given. `ResponseApdu` splits a response into its data and its `StatusWord`. Data is
copied in and out and never shown by `toString`.

# Package com.xignsys.pace.cardaccess

EF.CardAccess and its PACE entries (TR-03110 Part 3, A.1; ICAO 9303-11, section 9.2).

`CardAccess.parse` reads the file and keeps its bytes, the `PaceInfo` and
`PaceDomainParameterInfo` entries and the protocol identifiers as `PaceProtocol`. A file that is
malformed or ambiguous throws `MalformedCardAccessException`; entries the library cannot use are
kept, so that the caller sees everything the card offers.

EF.CardAccess is not protected. After PACE, compare `CardAccess.encoded` with the protected copy
on the card (TR-03110 Part 2, section 2.3.4; ICAO 9303-11, section 4.2).
