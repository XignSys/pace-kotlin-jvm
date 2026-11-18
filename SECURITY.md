# Security policy

This library implements a security protocol, so reports of vulnerabilities are welcome and are
handled with priority.

## Supported versions

Security fixes are released for the latest published version only. While the version is `0.x`,
there are no maintenance releases for older versions.

## Reporting a vulnerability

Report a suspected vulnerability privately to **sec@groups.xignsys.com**. Do not open a public
issue or pull request for it.

Please include:

- the version of the library, and the Java or Android version it ran on;
- what goes wrong and what an attacker gains from it;
- the steps or a small program that reproduces it, if you have one.

Never send data read from a real document: no passwords (CAN, MRZ, PIN, PUK), no personal data and
no files of a card. Use the specimen data of the public specifications or made-up values instead,
or describe the data.

## What to expect

- We confirm that we received the report within 5 working days.
- We tell you whether we can reproduce it and how we rate it, and keep you informed until it is
  fixed.
- We publish the fix in a new release with an entry in the changelog, and name you there if you
  wish.
- We ask you not to publish details before the fix is released, or before 90 days have passed
  since your report, whichever comes first.

## Scope

In scope are flaws in this library, for example:

- an error in PACE or in Secure Messaging that weakens the authentication, the confidentiality or
  the integrity the protocol provides;
- a response that is passed to the caller although it failed a check;
- passwords, keys or other secrets that are logged, shown by `toString` or kept longer than
  documented;
- input from a card or from the caller that causes an exception that is not documented, or a
  denial of service.

Out of scope:

- vulnerabilities of Bouncy Castle, the Kotlin standard library or the Java runtime; report these
  to their maintainers. Tell us if this library uses them in an unsafe way;
- weaknesses of the PACE protocol itself or of a card;
- limits the README states in its security notes, such as copies of secrets inside Bouncy Castle
  that cannot be overwritten, or constant time being best effort on a JVM;
- what the library leaves to the caller: comparing EF.CardAccess with its protected copy, Passive
  Authentication, Terminal Authentication and Chip Authentication.
