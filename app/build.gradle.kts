import org.cyclonedx.model.Component
import com.android.build.api.variant.BuildConfigField

plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.compose.compiler)
  alias(libs.plugins.kotlin.serialization)
  id("com.google.devtools.ksp")
  id("org.cyclonedx.bom") version "3.6.1"
}

val disableSafeBrowsing = providers
    .gradleProperty("QRSG_DISABLE_SAFE_BROWSING")
    .map { it.toBooleanStrict() }
    .orElse(true)
    .get()

val safeBrowsingKey = if (disableSafeBrowsing) {
    ""
} else {
    providers.gradleProperty("QRSG_SAFE_BROWSING_API_KEY")
        .orElse(providers.environmentVariable("QRSG_SAFE_BROWSING_API_KEY"))
        .orElse("")
        .get()
}

val qrsgBuildConfigLiteral = if (disableSafeBrowsing) {
    "\"\""
} else {
    "\"" + safeBrowsingKey
        .replace("\\", "\\\\")
        .replace("\"", "\\\"") + "\""
}

android {
    namespace = "com.qrsg.app"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.qrsg.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        buildConfigField(
            "String",
            "QRSG_SAFE_BROWSING_API_KEY",
            "\"\""
        )
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
      compose = true
      aidl = false
      buildConfig = true
      shaders = false
    }

    packaging {
      resources {
        excludes += "/META-INF/{AL2.0,LGPL2.1}"
      }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("com.google.protobuf:protobuf-javalite:4.36.2")
  val composeBom = platform(libs.androidx.compose.bom)
  implementation(composeBom)
  androidTestImplementation(composeBom)

  // Core Android dependencies
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.lifecycle.runtime.ktx)
  implementation(libs.androidx.activity.compose)

  // Arch Components
  implementation(libs.androidx.lifecycle.runtime.compose)
  implementation(libs.androidx.lifecycle.viewmodel.compose)

  // Compose
  implementation(libs.androidx.compose.ui)
  implementation(libs.androidx.compose.ui.tooling.preview)
  implementation(libs.androidx.compose.material3)
  
  // Tooling
  debugImplementation(libs.androidx.compose.ui.tooling)
  
  // Instrumented tests
  androidTestImplementation(libs.androidx.compose.ui.test.junit4)
  debugImplementation(libs.androidx.compose.ui.test.manifest)

  // Local tests: jUnit, coroutines, Android runner
  testImplementation(libs.junit)
  testImplementation("org.json:json:20240303") // JVM test of Android org.json parser
  testImplementation(libs.kotlinx.coroutines.test)

  // Instrumented tests: jUnit rules and runners
  androidTestImplementation(libs.androidx.test.core)
  androidTestImplementation(libs.androidx.test.ext.junit)
  androidTestImplementation(libs.androidx.test.runner)
  androidTestImplementation(libs.androidx.test.espresso.core)
  
  // Navigation
  implementation(libs.androidx.navigation3.ui)
  implementation(libs.androidx.navigation3.runtime)
  implementation(libs.androidx.lifecycle.viewmodel.navigation3)

  // CameraX
implementation("androidx.camera:camera-camera2:1.4.2")
implementation("androidx.camera:camera-lifecycle:1.4.2")
implementation("androidx.camera:camera-view:1.7.0")

// Google ML Kit — QR/barcode recognition
implementation("com.google.mlkit:barcode-scanning:17.3.0")

//Room
implementation("androidx.room:room-runtime:2.8.5")
ksp("androidx.room:room-compiler:2.8.5")
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

// Resolved production runtime dependencies (not debug/test/build tooling).
tasks.cyclonedxDirectBom {
    includeConfigs = listOf("releaseRuntimeClasspath")
    projectType = Component.Type.APPLICATION
    componentName = "QR Security Gateway"
    componentGroup = "com.qrsg.app"
    componentVersion = "1.0"
}

androidComponents {
    onVariants(selector().all()) { variant ->
        if (!disableSafeBrowsing && safeBrowsingKey.isNotEmpty()) {
            checkNotNull(variant.buildConfigFields).put(
                "QRSG_SAFE_BROWSING_API_KEY",
                BuildConfigField(
                    "String",
                    qrsgBuildConfigLiteral,
                    null
                )
            )
        }
    }
}