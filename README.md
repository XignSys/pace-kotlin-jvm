# PACE for Kotlin and the JVM

Password Authenticated Connection Establishment (PACE) and PACE Secure Messaging for contactless
cards that implement PACE, such as electronic identity cards and electronic passports (BSI TR-03110,
ICAO Doc 9303 Part 11).

**Status:** PACE with ECDH, Generic Mapping or Chip Authentication Mapping and AES-128, AES-192 or
AES-256 on every standardized ECDH domain parameter ID and PACE Secure Messaging with AES are
implemented.

## What it does

- Runs PACE with a card: MSE:Set AT, the General Authenticate chain, the key derivation and the
  authentication tokens (TR-03110 Part 3, A.3, B.1 and B.14; ICAO 9303-11, section 4.4).
- Afterwards, protects commands the caller builds with PACE Secure Messaging and returns the
  verified, unprotected responses (TR-03110 Part 3, F; ICAO 9303-11, section 9.8). Secure
  Messaging can be ended without sending anything, so that the caller can continue on the same
  connection.
- Parses EF.CardAccess (PACEInfo, PACEDomainParameterInfo).

The library talks to the card through a byte-level transport that the caller implements, for
example on top of Android's `IsoDep` or `javax.smartcardio`. It uses no platform API, so it runs on
Android and on any JVM.

Not part of it: Terminal Authentication, Chip Authentication, Passive Authentication and reading
data groups.

## Supported PACE variants

| Variant | Status |
|---|---|
| ECDH, Generic Mapping, AES-128, AES-192 and AES-256 on every standardized ECDH domain parameter ID: the Brainpool curves of RFC 5639 (IDs 9, 11, 13, 14, 16, 17) and the NIST curves of RFC 5114 (IDs 8, 10, 12, 15, 18) | implemented: `PACEInfo` version 2, nonces of whole blocks up to the length of the group order, Secure Messaging with AES (even INS only). IDs 8 and 9 are deprecated by TR-03110 and never chosen by `defaultFor` |
| CHAT and certificate extensions in MSE:Set AT | implemented: given by the caller, checked for their structure and for MSE:Set AT in short length |
| passwords: MRZ, CAN, PIN, PUK | implemented, with the retry counter, suspended, blocked and deactivated passwords, and PACE through an open channel to resume a suspended one |
| Chip Authentication Mapping (ICAO 9303-11), on the same curves and key sizes | implemented: the Encrypted Chip Authentication Data is decrypted during PACE and verified against the chip's static public key with `chipAuthentication.verify`; Passive Authentication stays with the caller |
| explicit ECDH domain parameters (`PACEDomainParameterInfo`, local IDs 32 to 255) | implemented only for parameters that are one of the curves above, with an uncompressed generator: EF.CardAccess is not protected, and explicit parameters must not be used unless known to be secure (TR-03110 Part 3, A.2.1.3); PACE then runs on the library's copy of the curve. Never chosen by `defaultFor` |
| 3DES | not planned: deprecated by TR-03110 Part 3, A.1.1.1, and listed by BSI TR-03116-2 only for documents still in circulation |
| DH | not planned: Bouncy Castle's modular exponentiation is not constant time, and PACE exponents are secret |
| Integrated Mapping | not planned: Bouncy Castle has no implementation of the point encoding of ICAO 9303-11, Appendix B, and the DH variant falls with DH |

The variants that are not implemented are refused as `ParametersNotSupported` before anything is
sent.

## Requirements

- Java 17 or newer; on Android, `minSdk` 26 or newer, without core library desugaring.
- Kotlin 2.2 or newer for Kotlin consumers.
- Runtime dependencies: the Kotlin standard library and Bouncy Castle (`bcprov-jdk18on`).

## Coordinates

```kotlin
dependencies {
    implementation("com.xignsys.pace:pace:1.0.0")
}
```

The library is published on Maven Central, with its sources and its API documentation.

## Usage

The passwords are checked when they are built, so that wrong input fails before anything is sent
to a card:

```kotlin
// The card access number printed on the document.
val can = Can(canDigits) // a CharArray; overwritten by the library

// The MRZ password from the fields of the document; the library computes the check digits.
val mrz =
    Mrz(
        documentNumber = Mrz.DocumentNumber.of("L898902C"),
        dateOfBirth = Mrz.Date.of(LocalDate.of(1969, 8, 6)),
        dateOfExpiry = Mrz.Date.parse("940623"),
    )

// Or the MRZ information as read from the machine readable zone; its check digits are verified.
val read = Mrz.fromMrzInformation(mrzInformation) // e.g. "L898902C<369080619406236"

// Or the whole zone of a TD1 size document such as an ID card, three lines of 30 characters, for
// example as a camera read it; line breaks between the lines are accepted.
val scanned = Mrz.fromMachineReadableZone(zone) // a CharArray; overwritten by the library
```

Invalid input throws `IllegalArgumentException` with a message that names the rule, never the
characters. The values in the example are the specimen data of ICAO Doc 9303 Part 11, Appendix D.

EF.CardAccess, read from the card by the caller before PACE, tells which PACE the card offers:

```kotlin
val cardAccess = CardAccess.parse(efCardAccess) // throws MalformedCardAccessException
val offered = cardAccess.paceInfos.filter { it.version == 2 && it.usesStandardizedDomainParameters }
```

PACE runs through a `CardTransport`, a function from command bytes to response bytes. The call
blocks until the card has answered every command, so run it off the main thread:

```kotlin
val transport = CardTransport { command -> isoDep.transceive(command) }

// The parameters a caller chose from EF.CardAccess, or the library's default choice. For Terminal Authentication
// version 2 afterwards, pass the CHAT 7F4C and, if the card supports Authorization Extensions, the certificate
// extensions 65 the terminal asks for (TR-03110 Part 3, B.14.1).
val parameters = PaceParameters.defaultFor(cardAccess) ?: return // nothing the library implements

when (val result = Pace.establish(transport, cardAccess, parameters, can)) {
    is PaceResult.Established ->
        result.channel.use { channel ->
            val chipKey = result.chipEphemeralPublicKey
            val references = result.certificationAuthorityReferences // octets, with a CHAT, for Terminal Authentication

            when (val answer = channel.transceive(CommandApdu.of(0x00, 0xB0, 0x81, 0x00, ne = 4))) {
                is SecureMessagingResult.Response -> answer.response // checked and unprotected
                is SecureMessagingResult.Refused -> {} // nothing sent, for example an odd INS
                SecureMessagingResult.Failed -> {} // the channel is closed, the keys are overwritten
            }
        }
    is PaceResult.Failed.AuthenticationFailed -> {} // usually a wrong password; result.remainingTries for PIN, PUK
    is PaceResult.Failed.PasswordNotUsable -> {} // result.state: suspended, blocked or deactivated
    is PaceResult.Failed.CardError -> {} // any other status word: result.step, result.statusWord
    is PaceResult.Failed -> {} // parameters not offered or not supported, malformed response, invalid key or token
}
```

After PACE with Chip Authentication Mapping, `Established.chipAuthentication` checks the chip's
static public key `PK_IC` from the `ChipAuthenticationPublicKeyInfo` of EF.CardSecurity, whose
`keyId` equals the `parameterId` of the `PACEInfo` (ICAO 9303-11, sections 4.4.3.5 and 9.2.1). The
chip is genuine only together with Passive Authentication of EF.CardSecurity, which the caller
performs:

```kotlin
val genuineKey = result.chipAuthentication?.verify(chipPublicKey) == true // and Passive Authentication
```

`Pace.establish` throws the transport's `IOException` unchanged. A password serves one call: its
characters are overwritten when the call ends, and using it again throws `IllegalStateException`
before anything is sent, so that a used PIN never counts as a wrong attempt.

A PIN or PUK with one try left is suspended (TR-03110 Part 2, section 2.2.3): the card accepts it
again only after PACE with the CAN, followed by PACE with the PIN through the channel of that run.
The second run's commands are protected with the first run's keys; on success the first channel is
closed and the new one carries on, otherwise the first channel stays open. In the second run the
card may still answer MSE:Set AT with the warning `63 C1`, because the retry counter is reset only
by the correct PIN; the library goes on, and a card that has not resumed the PIN refuses General
Authenticate:

```kotlin
val first = Pace.establish(transport, cardAccess, canParameters, can) as? PaceResult.Established ?: return
val second = Pace.establish(first.channel, cardAccess, pinParameters, pin)
```

Wipe a password or MRZ field that is no longer needed, for example when the user cancels before
PACE runs: `wipe()` overwrites its characters, and PACE then refuses it like a used one.

The `IllegalArgumentException` of a refused input names the rule it breaks, never the characters.
Each factory and constructor lists its messages, so that an application can show them or map them
to its own texts; a change to a message is noted in the changelog.

The `SecureMessagingChannel` of `Established` owns the session keys. It protects every command in
the length form it was built in, checks every response (MAC first, then the status word, then the
decryption) and never passes on a response without Secure Messaging. A command it cannot protect is
refused without sending anything. `handOver()` ends Secure Messaging without sending anything,
overwrites the keys and returns the transport; `close()` overwrites the keys.

## Security notes

- The library logs nothing.
- Passwords, nonces, shared secrets and session keys are held in memory only and overwritten as
  soon as they are no longer needed, and when Secure Messaging ends. A password or MRZ field that
  is never used is overwritten by `wipe()`. Bouncy Castle computes with
  immutable `BigInteger` and point objects and keeps derived key schedules inside its engines;
  these copies cannot be overwritten and are released for garbage collection instead.
- Randomness comes from a `SecureRandom` the caller can pass in.
- EF.CardAccess is read before PACE and is not protected: an attacker between the terminal and the
  card can change it, for example to make the terminal choose a weaker PACE. After PACE, compare
  it (`CardAccess.encoded`) with the protected copy of the card, the `SecurityInfos` of
  EF.CardSecurity or of EF.DG14, once that file has passed Passive Authentication (TR-03110 Part 2,
  section 2.3.4; ICAO 9303-11, section 4.2). The library does not read or verify these files.
- Multiplications with secret scalars and comparisons of MACs use the Bouncy Castle operations
  written to run in constant time. On a JVM this is best effort, not a guarantee.
- Whatever a card answers, PACE and Secure Messaging end with a typed failure, not with an
  exception of the parser.
- Cryptography uses the Bouncy Castle lightweight API only; no JCA provider is registered.

To report a vulnerability, see the [security policy](SECURITY.md).

## Building

```shell
./gradlew check
```

`check` fails on unformatted sources; `./gradlew spotlessApply` formats them. Every resolved
dependency is verified against `gradle/verification-metadata.xml`. Every test run writes a JaCoCo
coverage report to `pace/build/reports/jacoco/test/` (`html/index.html` to read, an XML file for
tools). `./gradlew :pace:dokkaGeneratePublicationHtml` writes the API documentation to
`pace/build/dokka/html/`.

## Licence

Apache License 2.0, see [LICENSE](LICENSE).
