package com.xignsys.pace.architecture

import com.tngtech.archunit.base.DescribedPredicate.not
import com.tngtech.archunit.core.domain.JavaClass.Predicates.equivalentTo
import com.tngtech.archunit.core.domain.JavaClass.Predicates.resideInAnyPackage
import com.tngtech.archunit.core.domain.JavaClasses
import com.tngtech.archunit.core.domain.JavaCodeUnit
import com.tngtech.archunit.core.domain.JavaField
import com.tngtech.archunit.core.domain.JavaMember
import com.tngtech.archunit.core.importer.ClassFileImporter
import com.tngtech.archunit.core.importer.ImportOption
import com.tngtech.archunit.lang.ArchCondition
import com.tngtech.archunit.lang.ConditionEvents
import com.tngtech.archunit.lang.SimpleConditionEvent
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.members
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses
import com.xignsys.pace.CardTransport
import com.xignsys.pace.PacePassword
import com.xignsys.pace.SecureMessagingChannel
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.security.SecureRandom

/**
 * Rules for the classes of the library. The rules are allowed to match no class, so that they apply from the first
 * class on.
 */
class ArchitectureTest {
    private val classes: JavaClasses =
        ClassFileImporter()
            .withImportOption(ImportOption.DoNotIncludeTests())
            .importPackages(ROOT_PACKAGE)

    @Test
    fun checksTheLibraryClassesWithoutTheTests() {
        assertThat(classes.contain(PacePassword::class.java)).isTrue()
        assertThat(classes.contain(ArchitectureTest::class.java)).isFalse()
    }

    @Test
    fun publicSignaturesExposeNoBouncyCastleType() {
        // Bouncy Castle stays a runtime dependency that can change without an API change. Kotlin compiles internal
        // members to public bytecode; internal functions and property accessors carry a '$' in their name and are
        // skipped, internal constructors cannot be told apart and are checked as well.
        members()
            .that()
            .arePublic()
            .and()
            .haveNameNotContaining("$")
            .and()
            .areDeclaredInClassesThat()
            .arePublic()
            .and()
            .areDeclaredInClassesThat()
            .resideOutsideOfPackage("$ROOT_PACKAGE.internal..")
            .should(exposeNoTypeOf(BOUNCY_CASTLE_PACKAGE))
            .allowEmptyShould(true)
            .check(classes)
    }

    @Test
    fun cryptographyUsesOnlyTheBouncyCastleLightweightApi() {
        // No JCA provider is registered or used; SecureRandom is the only source of randomness.
        noClasses()
            .should()
            .dependOnClassesThat(
                resideInAnyPackage(
                    "javax.crypto..",
                    "java.security..",
                    "org.bouncycastle.jce..",
                    "org.bouncycastle.jcajce..",
                ).and(not(equivalentTo(SecureRandom::class.java))),
            ).allowEmptyShould(true)
            .check(classes)
    }

    @Test
    fun noPlatformApiIsUsed() {
        // The library runs on any JVM; a card is reached through the transport the caller implements.
        noClasses()
            .should()
            .dependOnClassesThat()
            .resideInAnyPackage("android..", "androidx..", "javax.smartcardio..")
            .allowEmptyShould(true)
            .check(classes)
    }

    @Test
    fun dependenciesAreOnlyTheJdkKotlinAndBouncyCastle() {
        // The Kotlin compiler adds the nullability annotations of org.jetbrains.annotations to public signatures.
        classes()
            .should()
            .onlyDependOnClassesThat()
            .resideInAnyPackage(
                "java..",
                "kotlin..",
                "org.jetbrains.annotations..",
                "org.bouncycastle..",
                "$ROOT_PACKAGE..",
            ).allowEmptyShould(true)
            .check(classes)
    }

    @Test
    fun onlyThePaceStepsAndTheSecureMessagingChannelSendToTheCard() {
        // Every command reaches the card through the transport; only the PACE steps and the Secure Messaging channel
        // send, so that no command bypasses them and nothing is sent unprotected after PACE.
        noClasses()
            .that()
            .resideOutsideOfPackage("$ROOT_PACKAGE.internal.pace..")
            .and()
            .doNotBelongToAnyOf(SecureMessagingChannel::class.java)
            .should()
            .callMethod(CardTransport::class.java, "transceive", ByteArray::class.java)
            .allowEmptyShould(true)
            .check(classes)
    }

    @Test
    fun nothingIsLogged() {
        // Passwords, keys, nonces and APDU payloads must never reach a log or the console.
        noClasses()
            .should()
            .dependOnClassesThat()
            .resideInAPackage("java.util.logging..")
            .orShould()
            .dependOnClassesThat()
            .belongToAnyOf(System.Logger::class.java)
            .orShould()
            .accessField(System::class.java, "out")
            .orShould()
            .accessField(System::class.java, "err")
            .orShould()
            .callMethod(Throwable::class.java, "printStackTrace")
            .orShould()
            .dependOnClassesThat()
            .haveFullyQualifiedName(KOTLIN_CONSOLE)
            .allowEmptyShould(true)
            .check(classes)
    }

    private fun exposeNoTypeOf(packagePrefix: String): ArchCondition<JavaMember> =
        object : ArchCondition<JavaMember>("expose no type of $packagePrefix") {
            override fun check(member: JavaMember, events: ConditionEvents) {
                val types =
                    when (member) {
                        is JavaField -> listOf(member.rawType)
                        is JavaCodeUnit -> member.rawParameterTypes + member.rawReturnType
                        else -> emptyList()
                    }

                types
                    .filter { it.baseComponentType.packageName.startsWith(packagePrefix) }
                    .forEach {
                        events.add(
                            SimpleConditionEvent.violated(member, "${member.fullName} exposes ${it.name}"),
                        )
                    }
            }
        }

    private companion object {
        const val ROOT_PACKAGE = "com.xignsys.pace"

        const val BOUNCY_CASTLE_PACKAGE = "org.bouncycastle"

        /** The class of Kotlin's `print`, `println` and `readln`. */
        const val KOTLIN_CONSOLE = "kotlin.io.ConsoleKt"
    }
}
