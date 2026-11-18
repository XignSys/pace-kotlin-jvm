import groovy.json.JsonOutput
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.Base64
import java.util.UUID

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

// A bundle built with -Ppace.skipSigning has no signatures: it shows what a release contains, and Maven Central
// refuses it.
tasks.withType<Sign>().configureEach {
    val signed = isRelease && !providers.gradleProperty("pace.skipSigning").isPresent
    onlyIf("the version is a release version and signing is not skipped") { signed }
}

val cleanStaging =
    tasks.register<Delete>("cleanStaging") {
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

// The tasks below call the publisher API of the Maven Central portal with a user token of the portal. The token is
// given outside the repository, as the Gradle properties mavenCentralUsername and mavenCentralPassword or as the
// environment variables ORG_GRADLE_PROJECT_mavenCentralUsername and ORG_GRADLE_PROJECT_mavenCentralPassword. It is
// never printed, and the tasks are kept out of the configuration cache so that it is not stored there.
val portalApi = "https://central.sonatype.com/api/v1/publisher"
val portalUsername = providers.gradleProperty("mavenCentralUsername")
val portalPassword = providers.gradleProperty("mavenCentralPassword")

/** The deployment of the last upload; another one is chosen with the Gradle property pace.deploymentId. */
val deploymentIdFile = layout.buildDirectory.file("central/deployment-id.txt")
val deploymentIdProperty = providers.gradleProperty("pace.deploymentId")

fun portalRequest(path: String): HttpRequest.Builder {
    check(portalUsername.isPresent && portalPassword.isPresent) {
        "The portal's user token is missing: set the Gradle properties mavenCentralUsername and mavenCentralPassword."
    }
    val token = Base64.getEncoder().encodeToString("${portalUsername.get()}:${portalPassword.get()}".toByteArray())
    return HttpRequest.newBuilder(URI.create(portalApi + path)).header("Authorization", "Bearer $token")
}

fun sendToPortal(request: HttpRequest, expectedStatus: Int): String {
    val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
    check(response.statusCode() == expectedStatus) {
        "The portal answered ${response.statusCode()} instead of $expectedStatus: ${response.body()}"
    }
    return response.body()
}

fun deploymentId(): String {
    val file = deploymentIdFile.get().asFile
    check(deploymentIdProperty.isPresent || file.exists()) {
        "No deployment is known: run centralUpload first, or name one with -Ppace.deploymentId=<id>."
    }
    return deploymentIdProperty.orNull ?: file.readText().trim()
}

tasks.register("centralUpload") {
    group = "publishing"
    description = "Uploads the bundle to the Maven Central portal, where it is validated but not published."
    notCompatibleWithConfigurationCache("uses the portal's user token")

    val bundle = tasks.named<Zip>("centralBundle").flatMap { it.archiveFile }
    inputs.file(bundle)
    doLast {
        val file = bundle.get().asFile
        val boundary = "bundle-" + UUID.randomUUID()
        val head =
            "--$boundary\r\n" +
                "Content-Disposition: form-data; name=\"bundle\"; filename=\"${file.name}\"\r\n" +
                "Content-Type: application/octet-stream\r\n\r\n"
        val body = head.toByteArray() + file.readBytes() + "\r\n--$boundary--\r\n".toByteArray()
        val name = URLEncoder.encode(file.nameWithoutExtension, Charsets.UTF_8)
        val request =
            portalRequest("/upload?name=$name&publishingType=USER_MANAGED")
                .header("Content-Type", "multipart/form-data; boundary=$boundary")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build()
        val id = sendToPortal(request, HttpURLConnection.HTTP_CREATED).trim()
        deploymentIdFile.get().asFile.writeText(id)
        logger.lifecycle("Uploaded ${file.name} as deployment $id. Check it with centralStatus.")
    }
}

tasks.register("centralStatus") {
    group = "publishing"
    description = "Shows the state of the uploaded deployment and, if its validation failed, the reasons."
    notCompatibleWithConfigurationCache("uses the portal's user token")

    doLast {
        val request = portalRequest("/status?id=${deploymentId()}").POST(HttpRequest.BodyPublishers.noBody()).build()
        logger.lifecycle(JsonOutput.prettyPrint(sendToPortal(request, HttpURLConnection.HTTP_OK)))
    }
}

tasks.register("centralPublish") {
    group = "publishing"
    description = "Publishes the validated deployment to Maven Central. This cannot be undone."
    notCompatibleWithConfigurationCache("uses the portal's user token")

    doLast {
        val id = deploymentId()
        val request = portalRequest("/deployment/$id").POST(HttpRequest.BodyPublishers.noBody()).build()
        sendToPortal(request, HttpURLConnection.HTTP_NO_CONTENT)
        logger.lifecycle("Deployment $id is being published. Follow it with centralStatus.")
    }
}

tasks.register("centralDrop") {
    group = "publishing"
    description = "Drops the deployment, validated or failed, without publishing it."
    notCompatibleWithConfigurationCache("uses the portal's user token")

    doLast {
        val id = deploymentId()
        sendToPortal(portalRequest("/deployment/$id").DELETE().build(), HttpURLConnection.HTTP_NO_CONTENT)
        logger.lifecycle("Deployment $id is dropped.")
    }
}
