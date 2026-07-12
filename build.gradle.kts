plugins {
    id("com.android.library") version "8.10.1" apply false
    id("com.android.application") version "9.2.1" apply false
    kotlin("android") version "2.1.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.21" apply false
}

val nativeDepsAbi = providers.gradleProperty("androidNativeDepsAbi")
val nativeDepsJobs = providers.gradleProperty("androidNativeDepsJobs")

tasks.register<Exec>("buildAndroidNativeDeps") {
    group = "build"
    description = "Cross-compiles pinned BoringSSL, nghttp3, and ngtcp2 for Android"
    workingDir(rootDir)
    val command = mutableListOf("bash", "scripts/build-android-deps.sh")
    nativeDepsAbi.orNull?.takeIf { it.isNotBlank() }?.let { command += listOf("--abi", it) }
    nativeDepsJobs.orNull?.takeIf { it.isNotBlank() }?.let { command += listOf("--jobs", it) }
    commandLine(command)
    inputs.file("scripts/build-android-deps.sh")
    inputs.file("third_party/versions.env")
    inputs.file("third_party/versions.cmake")
    outputs.dir("third_party/android-deps")
}
