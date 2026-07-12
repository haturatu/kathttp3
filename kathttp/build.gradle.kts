plugins {
    id("com.android.library")
    kotlin("android")
    id("maven-publish")
}

android {
    namespace = "dev.kathttp"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")

        val configuredAbis =
            (project.findProperty("kathttpAbis") as String?)
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
                    "-DKATHTTP_BUILD_TESTS=OFF",
                    "-DKATHTTP_BUILD_JNI=ON",
                    "-DKATHTTP_DEPS_ROOT=${
                        project.findProperty("kathttpDepsRoot")
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

    kotlinOptions {
        jvmTarget = "17"
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
                artifactId = "kathttp"
                version =
                    System.getenv("JITPACK_TAG")
                        ?: project.findProperty("VERSION")?.toString()
                        ?: "0.0.0-SNAPSHOT"

                pom {
                    name.set("Kathttp")
                    description.set("Native HTTP/3 client library for Android")
                    url.set("https://github.com/haturatu/kathttp")

                    licenses {
                        license {
                            name.set("BSD 2-Clause License")
                            distribution.set("repo")
                        }
                    }

                    scm {
                        connection.set("scm:git:git://github.com/haturatu/kathttp.git")
                        developerConnection.set("scm:git:ssh://github.com/haturatu/kathttp.git")
                        url.set("https://github.com/haturatu/kathttp")
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
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
}
