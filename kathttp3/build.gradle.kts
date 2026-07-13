plugins {
    id("com.android.library")
    id("maven-publish")
}

android {
    namespace = "dev.kathttp3"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")

        val configuredAbis =
            (project.findProperty("kathttp3Abis") as String?)
                ?.split(',')
                ?.map(String::trim)
                ?.filter(String::isNotEmpty)
                ?: listOf(
                    "arm64-v8a",
                    "armeabi-v7a",
                    "x86_64",
                    "x86",
                )

        externalNativeBuild {
            cmake {
                arguments(
                    "-DKATHTTP3_BUILD_TESTS=OFF",
                    "-DKATHTTP3_BUILD_JNI=ON",
                    // NDK r27 needs this opt-in to produce 16 KB page-size
                    // compatible ELF shared libraries on Android 15+.
                    "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON",
                    "-DKATHTTP3_DEPS_ROOT=${
                        project.findProperty("kathttp3DepsRoot")
                            ?: rootProject.file("third_party/android-deps")
                    }",
                )
                abiFilters += configuredAbis
            }
        }
    }

    ndkVersion = "27.0.12077973"

    externalNativeBuild {
        cmake {
            path = file("../CMakeLists.txt")
            version = "3.22.1"
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = false
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])

                groupId = "com.github.haturatu"
                artifactId = "kathttp3"
                version =
                    System.getenv("JITPACK_TAG")
                        ?: project.findProperty("VERSION")?.toString()
                        ?: "0.0.0-SNAPSHOT"

                pom {
                    name.set("KatHttp3")
                    description.set("Native HTTP/3 client library for Android")
                    url.set("https://github.com/haturatu/kathttp3")

                    licenses {
                        license {
                            name.set("BSD 2-Clause License")
                            distribution.set("repo")
                        }
                    }

                    scm {
                        connection.set("scm:git:git://github.com/haturatu/kathttp3.git")
                        developerConnection.set("scm:git:ssh://github.com/haturatu/kathttp3.git")
                        url.set("https://github.com/haturatu/kathttp3")
                    }
                }
            }
        }
    }
}

tasks.named("preBuild") {
    dependsOn(rootProject.tasks.named("buildAndroidNativeDeps"))
}

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
}
