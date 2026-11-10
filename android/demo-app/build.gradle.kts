import java.time.LocalDate
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.fortguarddemo"
    compileSdk = 35

    defaultConfig {
        // Must be on the FortGuard server's allowed list (fortguard/config.py ALLOWED_APP_IDS).
        applicationId = "com.example.mobilebank"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-demo"
        // The build date shown on the login screen, set when this APK is built.
        buildConfigField("String", "BUILD_DATE", "\"${LocalDate.now()}\"")
    }
    buildFeatures {
        buildConfig = true
    }
    buildTypes {
        debug {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    implementation(project(":fortguard-sdk"))
}
