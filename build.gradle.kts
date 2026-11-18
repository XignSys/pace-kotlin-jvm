plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.animalsniffer) apply false
    alias(libs.plugins.dokka) apply false
    alias(libs.plugins.spotless)
}

spotless {
    val ktlintVersion = libs.versions.ktlint.get()
    val editorConfig = rootProject.file(".editorconfig")

    kotlin {
        target("pace/src/**/*.kt")
        ktlint(ktlintVersion).setEditorConfigPath(editorConfig)
    }
    kotlinGradle {
        target("*.gradle.kts", "pace/*.gradle.kts")
        ktlint(ktlintVersion).setEditorConfigPath(editorConfig)
    }
}
