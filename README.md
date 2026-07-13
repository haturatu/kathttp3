# Kathttp

Kathttp is an experimental HTTP/3 client for Android (API 26+) with a C++20 core, stable C ABI, JNI bridge, coroutine Kotlin API, and a Jetpack Compose example. The transport stack is `ngtcp2 1.24.0 + nghttp3 1.17.0 + BoringSSL`.

> Status: the host core/JNI and Android builds compile, core/Kotlin unit tests pass, and the four-ABI debug example APK has been assembled and installed on an arm64 Android device. On Android, certificate verification now uses the platform `X509TrustManager` by default (no bundled CA file required) and live HTTP/3 requests to public servers succeed; this is not production-ready.

## Architecture and ownership

```text
Kotlin public API
  -> JNI bridge
    -> C ABI (opaque client/request handles)
      -> C++ Engine / per-origin QuicClient worker
        -> nghttp3 (HTTP/3 frames and QPACK)
        -> ngtcp2 (QUIC transport, recovery and flow control)
        -> BoringSSL (TLS 1.3 and packet protection)
          -> non-blocking UDP socket
```

Kotlin owns immutable request values and copies callback data. A JNI callback owns one global reference until one terminal callback. `kathttp_client_execute` transfers request ownership to native code; callback buffers are valid only during the callback. Engine owns request registry, cookies and connection pool. Each connection worker exclusively owns its UDP fd, TLS session, ngtcp2 connection and nghttp3 connection. `close`, cancellation and terminal delivery are idempotent at their public boundaries.

ngtcp2 owns QUIC packet parsing/generation, loss recovery, congestion and transport flow control. nghttp3 owns HTTP/3 framing, SETTINGS and QPACK encoding/decoding. BoringSSL owns TLS 1.3 and cryptography. Kathttp owns DNS, UDP/timer driving, SNI/ALPN/certificate policy, critical stream creation, request lifecycle, redirects/cookies, and language bindings.

## Host build and tests

Prerequisites are CMake 3.22+, C++20, pkg-config, and matching development packages for ngtcp2/nghttp3. The tested host versions are ngtcp2 1.24.0 and nghttp3 1.17.0.

```sh
cmake -S . -B build -DKATHTTP_BUILD_TESTS=ON -DKATHTTP_BUILD_JNI=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Sanitizers:

```sh
cmake -S . -B build-asan -DKATHTTP_SANITIZE=ON
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

## Android dependencies and build

Prerequisites:

- Android SDK with platform 36 and build-tools 36.0.0
- Android NDK `27.0.12077973`
- CMake 3.22.1 or newer, Git, Go, and Java 17. Ninja is recommended; Unix Makefiles are used automatically when Ninja is unavailable.

Set `ANDROID_HOME` or `ANDROID_SDK_ROOT`. An explicit `ANDROID_NDK_HOME` is also accepted. Kathttp deliberately does not link Android's private platform BoringSSL ABI. The checked-in build script downloads fixed upstream sources and cross-compiles these static libraries:

```text
third_party/android-deps/<ABI>/lib/libngtcp2.a
third_party/android-deps/<ABI>/lib/libngtcp2_crypto_boringssl.a
third_party/android-deps/<ABI>/lib/libnghttp3.a
third_party/android-deps/<ABI>/lib/libssl.a
third_party/android-deps/<ABI>/lib/libcrypto.a
```

Build every supported ABI:

```sh
./gradlew buildAndroidNativeDeps
```

Build only one ABI or rebuild from clean state:

```sh
scripts/build-android-deps.sh --abi arm64-v8a --jobs 8
scripts/build-android-deps.sh --clean --abi arm64-v8a
# Build two independent ABIs at once, with two compiler jobs per ABI.
scripts/build-android-deps.sh --parallel-abis 2 --jobs 2
```

The script is incremental and safe to run repeatedly. Sources are kept under `third_party/src`, intermediate files under `third_party/build-android`, and installed headers/libraries under `third_party/android-deps/<ABI>`. Supported ABIs are `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`; all target Android API 26.

## CI cache

The GitHub Actions workflows cache Gradle state, the pinned Android SDK/NDK/CMake
packages, pinned dependency source checkouts, and generated
`third_party/android-deps` static libraries. The source-cache key is based on
the pinned revisions; the library-cache key additionally includes the build
script. The build script validates each cached ABI (headers, all five libraries,
API level, revisions, and recipe version) before skipping it, so an incomplete
cache is rebuilt rather than used.

The Android example workflow uses a four-ABI GitHub Actions matrix
(`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`), so each ABI's dependency and APK
build runs independently. The AAR workflow still produces one combined AAR and
builds two ABI dependency sets concurrently with one compiler job per set,
avoiding CPU oversubscription on hosted runners. The Gradle build cache and
parallel project execution are enabled in `gradle.properties`.

Build the APK after dependencies:

```sh
./gradlew buildAndroidNativeDeps
./gradlew :example:assembleDebug
ls -l example/build/outputs/apk/debug/example-debug.apk
```

## Native code quality checks

GitHub Actions runs native formatting, clang-tidy, cppcheck, and the host core
tests under AddressSanitizer and UndefinedBehaviorSanitizer.  The default
clang-tidy profile is deliberately staged: it reports selected bug-prone,
analyzer, performance, portability, and low-noise modernize/readability checks
without treating the existing baseline as errors.

```sh
# Formatting check / automatic formatting (generated CA bundle is excluded).
find src include tests -type f ! -name ca_bundle.h \( -name '*.cc' -o -name '*.cpp' -o -name '*.c' -o -name '*.h' -o -name '*.hpp' \) -print0 | xargs -0 clang-format --dry-run --Werror
find src include tests -type f ! -name ca_bundle.h \( -name '*.cc' -o -name '*.cpp' -o -name '*.c' -o -name '*.h' -o -name '*.hpp' \) -print0 | xargs -0 clang-format -i

# Compilation database and clang-tidy/cppcheck without linking transport deps.
cmake -S . -B build-tidy -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DKATHTTP_ANALYSIS_ONLY=ON -DKATHTTP_BUILD_JNI=OFF
run-clang-tidy -p build-tidy -quiet
cppcheck --project=build-tidy/compile_commands.json --enable=warning,style,performance,portability --inline-suppr --suppress=missingIncludeSystem --error-exitcode=1

# ASan + UBSan for the core test suite.
cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug -DKATHTTP_ANALYSIS_ONLY=ON -DKATHTTP_SANITIZE=ON -DKATHTTP_BUILD_JNI=OFF
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure
```

Include What You Use is intentionally opt-in because external QUIC/TLS headers
need project-specific mappings.  Install `include-what-you-use` and configure
with `-DKATHTTP_ENABLE_IWYU=ON` when running this manual audit.

The module uses compile SDK 36, minimum SDK 26, and Java/Kotlin JVM target 17.

### Publishing and consuming

The `:kathttp` module is configured with `maven-publish`. Building the release
AAR first runs `buildAndroidNativeDeps` automatically (wired through `preBuild`),
so a single command cross-compiles the pinned native dependencies for all four
ABIs and packages `libkathttp.so` into the AAR:

```sh
./gradlew :kathttp:publishReleasePublicationToMavenLocal
```

The same command runs on JitPack via [`jitpack.yml`](jitpack.yml). Add JitPack as
a repository and depend on the tag you want:

```kotlin
repositories { maven("https://jitpack.io") }
dependencies { implementation("com.github.haturatu:kathttp:v0.1.0") }
```

For stable releases, build the AAR once in CI (`[Android AAR]` workflow), publish
it to Maven Central, and depend on `dev.kathttp:kathttp:<version>` instead.


Pinned dependencies and licenses:

| Library | Version | License |
| --- | --- | --- |
| BoringSSL | `3c6315e00ab02d7bc9b8922aff1f85d8f81ee130` | ISC-style/BSD-style; see upstream `LICENSE` |
| nghttp3 | `v1.17.0` | MIT |
| ngtcp2 | `v1.24.0` | MIT |

These revisions are defined once in [`third_party/versions.env`](third_party/versions.env), which `scripts/build-android-deps.sh` sources and `third_party/versions.cmake` loads. Edit `versions.env` to bump a dependency.

### Certificate trust

Peer and hostname verification are enabled by default. The default trust mode is `KATHTTP_TRUST_PLATFORM`, which on Android delegates to the platform `X509TrustManager` through `android.net.http.X509TrustManagerExtensions` (BoringSSL's custom-verify callback forwards the peer chain, server name and key type). This automatically inherits the Android system trust store and Network Security Config, so public-server use works out of the box without a bundled CA file.

Three trust modes are selectable through `kathttp_trust_mode`:

| Mode | Meaning |
| --- | --- |
| `KATHTTP_TRUST_PLATFORM` (default) | Use the OS/platform trust provider (Android `X509TrustManagerExtensions`; host OpenSSL default paths). |
| `KATHTTP_TRUST_EMBEDDED_MOZILLA` | Verify against the built-in Mozilla CA bundle (`ca_bundle.h`). |
| `KATHTTP_TRUST_CUSTOM_CA` | Verify against a caller-supplied PEM CA file (`ca_cert_file`). |

`insecure_cert` disables verification entirely; it is debug-only and must never be enabled in shipped builds.

Verification failure is fatal and surfaced with a distinct error code rather than a generic transport error: `KATHTTP_ERR_TLS` (-4) for handshake-level failures, `KATHTTP_ERR_CERTIFICATE_VERIFY` (-5), `KATHTTP_ERR_HOSTNAME_MISMATCH` (-6), and `KATHTTP_ERR_NO_TRUST_PROVIDER` (-7) when no trust provider is configured. The Kotlin API throws `TlsHandshakeException`, `CertificateVerificationException`, or `QuicTransportException` accordingly; transport errors remain `KATHTTP_ERR_QUIC` (-3) / `QuicTransportException`. Kathttp does not silently disable verification. Key logging is debug-only and must never be enabled in shipped builds.

## Kotlin usage

```kotlin
KatHttpClient().use { client ->
    val response = client.get("https://your-http3-server.example/resource")
    println("${response.status}: ${response.body.decodeToString()}")
}
```

POST and cancellation:

```kotlin
val job = lifecycleScope.launch {
    client.post(
        "https://your-http3-server.example/items",
        "{\"name\":\"kat\"}".encodeToByteArray(),
        listOf(KatHttpHeader("content-type", "application/json")),
    )
}
job.cancel() // propagated to RESET_STREAM / STOP_SENDING
```

`execute` buffers at most `maxBufferedBodyBytes` (16 MiB by default). `executeStreaming` exposes a bounded `Flow<KatHttpStreamEvent>`; close/cancel its `KatHttpCall` when abandoning collection.

`KatHttpClientConfig` has independent monotonic deadlines for DNS, connect,
handshake, response headers, read-idle, write-idle, and the complete call.
`callTimeoutMillis` is an absolute request deadline; read/write timeouts reset
only when the corresponding direction makes progress. Timeout failures are
reported as `KathttpException.Timeout` with a `KatHttpTimeoutPhase`.

## Example app

The local-module Compose app is in `example/` and uses `implementation(project(":kathttp"))`. Install `example/build/outputs/apk/debug/example-debug.apk`, enter an HTTPS URL served over HTTP/3, select GET, POST, PUT, DELETE, PATCH, or HEAD, then press the single `Send <method>` button. POST, PUT, PATCH, and DELETE expose an editable UTF-8 body; headers are entered as lowercase `name: value` lines. Cancel cancels the coroutine and native request. The app shows status, headers, HTTP/3-over-QUIC protocol information, duration, byte count, and errors; response rendering is capped at 16,000 characters to keep the UI responsive. No public endpoint is hard-coded and cleartext traffic is disabled.

With one Android device connected through adb, the example can be built and installed from its directory:

```sh
cd example
make adbinstall
```

By default dependencies are read from `third_party/android-deps`; override this with `KATHTTP_DEPS_ROOT=/absolute/path` when needed. When multiple devices are connected, add `DEVICE_SERIAL=<adb-serial>`. The target runs `:example:assembleDebug`, verifies the APK, and installs it with `adb install -r`.

## Tests

- `tests/core/core_tests.cc`: URL and port validation, HTTPS policy, header lookup, redirect resolution, cookie matching.
- `kathttp/src/test`: Kotlin model/config/header/request validation.
- External-network and local ngtcp2-server tests are intentionally separate and are not run by ordinary unit tests.

## Protocol notes

The worker drives `ngtcp2_conn_get_expiry2`/`ngtcp2_conn_handle_expiry` with monotonic nanoseconds and drains non-blocking UDP. After 1-RTT keys are available, it creates the nghttp3 client plus one control and two QPACK unidirectional streams. Requests use client bidirectional streams with `:method`, `:scheme`, `:authority`, and `:path`. Cancellation requests both read and write shutdown.

## C ABI compatibility

The C ABI uses `kathttp_client_config` (an alias of the retained
`kathttp_client_options`) with `struct_size` and `abi_version`. Initialize it
with `kathttp_client_config_init`. KatHttp accepts known smaller structs and
defaults appended fields; it rejects future ABI versions. During the 0.x line,
existing enum values and fields are not reordered and optional fields are
appended only. Symbols are hidden by default except `kathttp_*` exports.

## Known limitations

- Certificate trust defaults to the Android platform provider (`X509TrustManagerExtensions`); the embedded Mozilla bundle and a caller-supplied CA file are also available via `kathttp_trust_mode`.
- Live GET/POST interoperability has not been verified against a local HTTP/3 server.
- DNS, connect, handshake, response-header, read-idle, write-idle and call
  deadlines use the monotonic QUIC clock.
- Graceful GOAWAY draining, response Content-Length validation, trailer exposure, strict response-field validation and robust packet send backpressure are incomplete.
- Streaming uses a bounded JNI-to-Kotlin channel but native QUIC flow-control credit is currently returned on callback delivery, not downstream Flow consumption.
- DNS lookups run in a bounded two-thread resolver pool rather than on a QUIC
  worker. Cancellation and DNS deadlines discard late results. IPv6 and IPv4
  records are interleaved in RFC 8305 order; connection attempts are still
  sequential, so fully parallel, timed Happy Eyeballs racing is not yet
  provided.
- Redirects reject HTTPS-to-HTTP downgrades and strip Authorization,
  Proxy-Authorization, Cookie, and Host on cross-origin hops. The cookie jar
  is experimental and disabled by default (`enableCookies = true` is explicit
  opt-in). It has no public-suffix database, so it must not be treated as a
  browser-equivalent cookie implementation.
- HTTP response caching is not provided. A former disconnected implementation
  is intentionally excluded from production builds; a future cache must cover
  Cache-Control, Vary, Age, Date, Expires, ETag/Last-Modified revalidation,
  304 merging, no-store, stale-if-error, privacy, and Authorization semantics.
- 0-RTT is disabled by default and session resumption persistence is not complete.
- C ABI `destroy` requires a live handle; callers must null their handle after destroy. JNI detects stale/double-destroy handles.

## Source layout

```text
CMakeLists.txt                  host/Android native build
include/kathttp/kathttp.h       public include forwarder
src/core/                       QUIC/HTTP3 engine and C ABI
src/jni/kathttp_jni.cc          JNI bridge
kathttp/                        Android library and Kotlin API
example/                        Compose sample app
tests/core/                     host unit tests
scripts/build-android-deps.sh   pinned Android dependency cross-build
third_party/android-deps/       generated per-ABI headers and static libraries
```
