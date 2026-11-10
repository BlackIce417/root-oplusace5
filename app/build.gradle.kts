plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    packagingOptions { jniLibs { useLegacyPackaging = true } }
    namespace = "com.oplusace5.root"
    ndkVersion = "28.2.13676358"

    compileSdk {
        version = release(37) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.oplusace5.root"
        minSdk = 31
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            // The chain, its offsets and the embedded su are arm64-only.
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
    externalNativeBuild {
        cmake {
            path = file("CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

// Package the standalone native executable under a .so name so Android
// extracts it into nativeLibraryDir with execute permission.  The one-click
// controller execs this clean process for KernelSnitch instead of creating
// thousands of pthreads in a post-fork ART child.
val syncDebugGlshellExec by tasks.registering(Sync::class) {
    dependsOn("buildCMakeDebug[arm64-v8a]")
    from(fileTree(layout.buildDirectory.dir("intermediates/cxx/Debug")) {
        include("**/obj/arm64-v8a/glshell")
    })
    eachFile {
        relativePath = org.gradle.api.file.RelativePath(true, name)
    }
    into(layout.buildDirectory.dir("generated/glshell/arm64-v8a"))
    rename { "libglshell_exec.so" }
}

android.sourceSets.getByName("main").jniLibs.srcDir(
    layout.buildDirectory.dir("generated/glshell").get().asFile
)

tasks.configureEach {
    if (name == "mergeDebugJniLibFolders" || name == "mergeDebugNativeLibs") {
        dependsOn(syncDebugGlshellExec)
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
