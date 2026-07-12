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
```

The script is incremental and safe to run repeatedly. Sources are kept under `third_party/src`, intermediate files under `third_party/build-android`, and installed headers/libraries under `third_party/android-deps/<ABI>`. Supported ABIs are `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`; all target Android API 26.

Build the APK after dependencies:

```sh
./gradlew buildAndroidNativeDeps
./gradlew :example:assembleDebug
ls -l example/build/outputs/apk/debug/example-debug.apk
```

The module uses compile SDK 36, minimum SDK 26, and Java/Kotlin JVM target 17.

Pinned dependencies and licenses:

| Library | Version | License |
| --- | --- | --- |
| BoringSSL | `3c6315e00ab02d7bc9b8922aff1f85d8f81ee130` | ISC-style/BSD-style; see upstream `LICENSE` |
| nghttp3 | `v1.17.0` | MIT |
| ngtcp2 | `v1.24.0` | MIT |

These exact revisions are present both in `scripts/build-android-deps.sh` and `third_party/versions.cmake`.

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

## Example app

The local-module Compose app is in `example/` and uses `implementation(project(":kathttp"))`. Install `example/build/outputs/apk/debug/example-debug.apk`, enter an HTTPS URL served over HTTP/3, select a method, and press GET or POST. Cancel cancels the coroutine and native request. It shows status, headers, protocol, duration, byte count, errors and the first 64,000 body characters. No public endpoint is hard-coded and cleartext traffic is disabled.

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

## Known limitations

- Certificate trust defaults to the Android platform provider (`X509TrustManagerExtensions`); the embedded Mozilla bundle and a caller-supplied CA file are also available via `kathttp_trust_mode`.
- Live GET/POST interoperability has not been verified against a local HTTP/3 server.
- Request deadline enforcement, graceful GOAWAY draining, response Content-Length validation, trailer exposure, strict response-field validation and robust packet send backpressure are incomplete.
- Streaming uses a bounded JNI-to-Kotlin channel but native QUIC flow-control credit is currently returned on callback delivery, not downstream Flow consumption.
- DNS uses blocking `getaddrinfo`; it enumerates IPv6/IPv4 candidates sequentially but does not implement timed Happy Eyeballs or cancellable resolution.
- Redirect handling is partial; cross-origin sensitive-header policy needs further hardening. The cookie jar is intentionally minimal and has no public-suffix database.
- The cache implementation is disconnected and experimental because it is not a compliant HTTP cache.
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
