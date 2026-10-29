plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.zeyanlin.mfa"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.zeyanlin.mfa"
        minSdk = 29      // Android 10: Keystore StrongBox, scoped storage, SAF
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    // No cloud backup: the vault key is in the Keystore and cannot leave the
    // device, so a backed-up vault file would be unreadable anyway. Moving
    // device goes through the encrypted backup file or a sync target.
    //
    // (Also set in the manifest; both are needed.)

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }

    sourceSets {
        getByName("main") {
            // Where ./scripts/build-android.sh puts the core.
            jniLibs.srcDirs("src/main/jniLibs", "../../build/android/jniLibs")
            // And the generated Kotlin bindings.
            java.srcDirs("../../build/android/kotlin")
        }
    }

    packaging {
        resources.excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1")
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.documentfile)
    implementation(libs.androidx.biometric)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)

    implementation(libs.camera.core)
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.zxing.core)

    implementation(libs.okhttp)

    // The @aar classifier matters: the plain jar has no Android native libs
    // and the generated bindings fail to load at runtime with it.
    implementation(variantOf(libs.jna) { artifactType("aar") })
}
