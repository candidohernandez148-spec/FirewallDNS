plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.firewalldns.diagnostic"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.firewalldns.diagnostic"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    // Must be byte-for-byte the same signing identity as :app.
    val releaseKeystorePath = providers.environmentVariable("KEYSTORE_PATH").orNull
    val releaseKeystore = releaseKeystorePath?.let { rootProject.file(it) }?.takeIf { it.isFile }
    val releaseStorePassword = providers.environmentVariable("KEYSTORE_PASSWORD").orNull
    val releaseKeyAlias = providers.environmentVariable("KEY_ALIAS").orNull
    val releaseKeyPassword = providers.environmentVariable("KEY_PASSWORD").orNull
        ?: releaseStorePassword

    signingConfigs {
        if (releaseKeystore != null) {
            create("sharedRelease") {
                storeFile = releaseKeystore
                storePassword = requireNotNull(releaseStorePassword) { "KEYSTORE_PASSWORD is required" }
                keyAlias = requireNotNull(releaseKeyAlias) { "KEY_ALIAS is required" }
                keyPassword = requireNotNull(releaseKeyPassword) { "KEY_PASSWORD (or KEYSTORE_PASSWORD) is required" }
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("sharedRelease")
                ?: throw GradleException(
                    "Release requires the shared signing keystore. Set KEYSTORE_PATH, " +
                        "KEYSTORE_PASSWORD, KEY_ALIAS and KEY_PASSWORD. Debug builds remain available."
                )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(project(":engine-core"))
    implementation(project(":engine-runtime"))
    implementation(project(":android-adapter"))
    implementation("androidx.core:core:1.15.0")
}
