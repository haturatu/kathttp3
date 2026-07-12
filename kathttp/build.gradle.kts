plugins { id("com.android.library"); kotlin("android") }

android {
    namespace = "dev.kathttp"
    compileSdk = 36
    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
        val configuredAbis = (project.findProperty("kathttpAbis") as String?)
            ?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }
            ?: listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        externalNativeBuild { cmake { arguments("-DKATHTTP_BUILD_TESTS=OFF", "-DKATHTTP_BUILD_JNI=ON", "-DKATHTTP_DEPS_ROOT=${project.findProperty("kathttpDepsRoot") ?: rootProject.file("third_party/android-deps")}"); abiFilters += configuredAbis } }
    }
    ndkVersion = "27.0.12077973"
    externalNativeBuild { cmake { path = file("../CMakeLists.txt"); version = "3.22.1" } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { buildConfig = false }
}

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
}
