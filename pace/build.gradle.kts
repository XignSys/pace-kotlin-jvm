import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    `java-library`
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.animalsniffer)
    alias(libs.plugins.dokka)
    `maven-publish`
    signing
    jacoco
}

/** A release version is signed and can be bundled for Maven Central; a snapshot version is neither. */
val isRelease = !version.toString().endsWith("-SNAPSHOT")

/** Where the project and its source code are published; required by Maven Central. */
val projectUrl = providers.gradleProperty("pace.projectUrl").orNull.orEmpty()

/** Who publishes the library, and their web address; required by Maven Central. */
val developerName = providers.gradleProperty("pace.developerName").orNull.orEmpty()
val developerUrl = providers.gradleProperty("pace.developerUrl").orNull.orEmpty()

/** The Maven repository layout of one release in the build directory, from which the bundle is packed. */
val stagingDirectory = layout.buildDirectory.dir("staging")

/** Bytecode level and JDK API of the library: Java 17, which Android build tools accept for apps with minSdk 26. */
val javaRelease = 17

java {
    withSourcesJar()
    withJavadocJar()
}

// The API documentation is generated from the KDoc with Dokka, with the module and package descriptions of
// Module.md, and published as the Javadoc JAR that Maven Central requires.
dokka {
    dokkaSourceSets.configureEach {
        includes.from("Module.md")
    }
}

tasks.named<Jar>("javadocJar") {
    from(tasks.dokkaGeneratePublicationHtml)
}

tasks.withType<JavaCompile>().configureEach {
    options.release = javaRelease
}

kotlin {
    explicitApi()
    coreLibrariesVersion = libs.versions.kotlinStdlib.get()
    compilerOptions {
        jvmTarget = JvmTarget.fromTarget(javaRelease.toString())
        freeCompilerArgs.add("-Xjdk-release=$javaRelease")
        allWarningsAsErrors = true
        languageVersion = KotlinVersion.KOTLIN_2_2
        apiVersion = KotlinVersion.KOTLIN_2_2
    }
}

// The library's classes may use only JDK APIs that Android offers from API level 26 on, without core library
// desugaring: the Java release flag checks the JDK version, not what Android implements.
animalsniffer {
    toolVersion = libs.versions.animalsnifferTool.get()
    sourceSets = listOf(project.sourceSets.main.get())
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
}

// Coverage of the tests, written after every test run: HTML to read, XML for tools.
tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        html.required = true
        xml.required = true
    }
}

dependencies {
    implementation(libs.bouncycastle.bcprov)

    signature(variantOf(libs.gummy.bears.api26) { artifactType("signature") })

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.assertj.core)
    testImplementation(libs.archunit)
}

publishing {
    publications {
        register<MavenPublication>("library") {
            artifactId = "pace"
            from(components["java"])
            pom {
                name = "PACE"
                description =
                    "Password Authenticated Connection Establishment (PACE) and PACE Secure Messaging for " +
                    "contactless cards, for Kotlin and the JVM."
                licenses {
                    license {
                        name = "Apache-2.0"
                        url = "https://www.apache.org/licenses/LICENSE-2.0.txt"
                        distribution = "repo"
                    }
                }
                if (projectUrl.isNotEmpty()) {
                    url = projectUrl
                    scm {
                        url = projectUrl
                        connection = "scm:git:$projectUrl.git"
                        developerConnection = "scm:git:$projectUrl.git"
                    }
                }
                if (developerName.isNotEmpty()) {
                    developers {
                        developer {
                            name = developerName
                            organization = developerName
                            if (developerUrl.isNotEmpty()) {
                                url = developerUrl
                                organizationUrl = developerUrl
                            }
                        }
                    }
                }
            }
        }
    }
    repositories {
        maven {
            name = "staging"
            url = uri(stagingDirectory)
        }
    }
}

// Signs with the local GnuPG installation and its agent, so the private key never passes through the build. The key
// is chosen with the Gradle property signing.gnupg.keyName; without it GnuPG takes its default key.
signing {
    useGpgCmd()
    sign(publishing.publications["library"])
}

tasks.withType<Sign>().configureEach {
    val release = isRelease
    onlyIf("the version is a release version") { release }
}

val cleanStaging by tasks.registering(Delete::class) {
    delete(stagingDirectory)
}

tasks.named("publishLibraryPublicationToStagingRepository") {
    dependsOn(cleanStaging)
}

// The bundle to upload to the Maven Central publisher portal: the release in the Maven repository layout, with its
// signatures and checksums. The repository's own index files are not part of a bundle.
tasks.register<Zip>("centralBundle") {
    group = "publishing"
    description = "Packs the signed release for the upload to Maven Central."

    val release = isRelease
    val missing =
        listOf(
            "pace.projectUrl" to projectUrl,
            "pace.developerName" to developerName,
            "pace.developerUrl" to developerUrl,
        ).filter { it.second.isEmpty() }
            .map { it.first }
    doFirst {
        check(release) { "A snapshot version cannot be published to Maven Central." }
        check(missing.isEmpty()) { "Maven Central requires the Gradle properties $missing." }
    }

    dependsOn("publishLibraryPublicationToStagingRepository")
    from(stagingDirectory)
    exclude("**/maven-metadata.xml*")
    archiveFileName = "pace-$version-bundle.zip"
    destinationDirectory = layout.buildDirectory.dir("central")
}
