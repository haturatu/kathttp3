plugins {
    id("com.android.library") version "9.2.1" apply false
    id("com.android.application") version "9.2.1" apply false
    // AGP 9 supplies Kotlin support itself.  Keep only the Compose compiler
    // plugin, which is intentionally paired with its Kotlin 2.4 release.
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.0" apply false
}

val nativeDepsAbi = providers.gradleProperty("androidNativeDepsAbi")
val nativeDepsJobs = providers.gradleProperty("androidNativeDepsJobs")
val nativeDepsParallelAbis = providers.gradleProperty("androidNativeDepsParallelAbis")

tasks.register<Exec>("buildAndroidNativeDeps") {
    group = "build"
    description = "Cross-compiles pinned BoringSSL, nghttp3, and ngtcp2 for Android"
    workingDir(rootDir)
    val command = mutableListOf("bash", "scripts/build-android-deps.sh")
    nativeDepsAbi.orNull?.takeIf { it.isNotBlank() }?.let { command += listOf("--abi", it) }
    nativeDepsJobs.orNull?.takeIf { it.isNotBlank() }?.let { command += listOf("--jobs", it) }
    nativeDepsParallelAbis.orNull?.takeIf { it.isNotBlank() }?.let {
        command += listOf("--parallel-abis", it)
    }
    commandLine(command)
    inputs.file("scripts/build-android-deps.sh")
    inputs.file("third_party/versions.env")
    inputs.file("third_party/versions.cmake")
    inputs.dir("third_party/patches")
    outputs.dir("third_party/android-deps")
}
