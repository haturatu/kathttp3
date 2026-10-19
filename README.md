# KatHttp3

KatHttp3 is a native HTTP/3 client library for Android 8.0 (API 26) and later. It provides a coroutine-based Kotlin API backed by a C++20 HTTP/3 engine, without depending on Cronet. A Jetpack Compose example application is included.

The Android transport uses **ngtcp2 1.24.0**, **nghttp3 1.17.0**, and a pinned BoringSSL revision. Host builds can instead use ngtcp2's OpenSSL crypto integration. The native core is also available through a versioned C ABI.

**Status:** Host unit tests, an HTTP/3 interoperability smoke test, and Android library/example builds run in CI. Passing these checks does not establish interoperability with every HTTP/3 server or behavior on every Android network. In particular, uploads, redirects, cancellation, and migration should be tested on the intended devices and servers.

## Getting started

### Requirements

| Component | Requirement |
| --- | --- |
| Android runtime | API 26 or later |
| Android build | Android SDK platform 37, NDK `27.0.12077973`, CMake 3.22.1 or newer |
| Build tools | JDK 17, Git, Gradle wrapper included in this repository |
| Native core | C++20, ngtcp2, nghttp3, BoringSSL |
| Native Android targets | `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` |

The example application targets Android API 36, while the library and example compile against SDK 37. Set `ANDROID_HOME` or `ANDROID_SDK_ROOT` to the Android SDK path. `ANDROID_NDK_HOME` may be set to select an NDK explicitly. Ninja is recommended; the native dependency script can fall back to Unix Makefiles.

### Build the Android library and example

Clone the repository and build its pinned native dependencies:

```sh
git clone https://github.com/haturatu/kathttp3.git
cd kathttp3
./gradlew buildAndroidNativeDeps
./gradlew :kathttp3:assembleRelease :example:assembleDebug
```

The release AAR is generated under `kathttp3/build/outputs/aar/`. The example APK is generated at `example/build/outputs/apk/debug/example-debug.apk`.

Building `:kathttp3` invokes the native dependency build through its `preBuild` task; the explicit `buildAndroidNativeDeps` command above is useful when diagnosing or preparing the dependencies separately.

To install the example on a connected device:

```sh
cd example
make adbinstall
```

The Makefile builds the APK and invokes `adb install -r`. Set `DEVICE_SERIAL=<adb-serial>` if multiple devices are connected. The target does not merely launch a previously built APK; it runs the build and installation steps.

### Add the library to an Android project

For a local checkout, include `:kathttp3` in the consuming build's `settings.gradle.kts` and add a project dependency:

```kotlin
dependencies {
    implementation(project(":kathttp3"))
}
```

To create a locally published Maven artifact:

```sh
./gradlew :kathttp3:publishReleasePublicationToMavenLocal
```

The project also contains a `jitpack.yml` publishing recipe. For a repository tag built by JitPack, configure its repository and use that tag as the dependency version:

Add the repository in the consumer's `settings.gradle.kts` (rather than a module build file when centralized repository management is enabled):

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://jitpack.io")
    }
}
```

Then add the dependency in the app module:

```kotlin
dependencies {
    implementation("com.github.haturatu:kathttp3:<tag>")
}
```

Replace `<tag>` with an existing tag. This example describes the publishing configuration; it does not claim that a particular tag or Maven Central artifact is currently available. Native Android libraries are bundled into the AAR for the configured ABIs.

## Kotlin API

### Send a request

These examples use suspend functions and must run in a coroutine or another suspend context.

```kotlin
import dev.kathttp3.KatHttp3Client
import dev.kathttp3.get

KatHttp3Client().use { client ->
    val response = client.get("https://your-http3-server.example/resource")
    println(response.status)
    println(response.body.decodeToString())
}
```

KatHttp3 requires HTTPS URLs. There is no automatic HTTP/1.1 or HTTP/2 fallback when an endpoint does not support HTTP/3.

To send a JSON POST request:

```kotlin
import dev.kathttp3.KatHttp3Header
import dev.kathttp3.post

KatHttp3Client().use { client ->
    val response = client.post(
        "https://your-http3-server.example/items",
        """{"name":"kat"}""".encodeToByteArray(),
        listOf(KatHttp3Header("content-type", "application/json")),
    )
    println(response.status)
}
```

The same client exposes `get`, `post`, `put`, `delete`, `patch`, and `head` convenience functions, as well as `execute(KatHttp3Request(...))` for general requests. A `KatHttp3Response` contains the status, headers, body, and protocol name.

**Note:** `execute` buffers the response body in memory, up to `maxBufferedBodyBytes` (16 MiB by default). Use the streaming interface for larger or incrementally processed responses. `decodeContent()` is available for supported encoded response bodies; the buffered `saveTo(file)` helper writes an already-buffered body to a file.

### Cancel a request

The following examples assume an existing, longer-lived `client`. Cancellation of a coroutine executing a request is propagated to the native request and requests stream shutdown.

```kotlin
val job = lifecycleScope.launch {
    client.get("https://your-http3-server.example/resource")
}

job.cancel()
```

Closing a `KatHttp3Client` cancels its active requests. Use `use { ... }` or otherwise call `close()` when the client is no longer needed. Reuse a client across related requests to benefit from connection reuse.

### Stream a response

`executeStreaming` returns a `KatHttp3Call` with a `Flow<KatHttp3StreamEvent>`. The call must be closed if collection stops early:

```kotlin
import dev.kathttp3.KatHttp3Request
import dev.kathttp3.KatHttp3StreamEvent

val call = client.executeStreaming(
    KatHttp3Request("GET", "https://your-http3-server.example/large-file"),
)

try {
    call.events.collect { event ->
        when (event) {
            is KatHttp3StreamEvent.Headers -> println(event.status)
            is KatHttp3StreamEvent.Body -> processBytes(event.bytes)
        }
    }
} finally {
    call.close()
}
```

`processBytes` represents application code that handles a received chunk. The Kotlin response queue has byte limits per stream and across the client. JNI copies the callback data before returning receive-window credit; that credit does **not** mean downstream application processing has finished.

For uploads, `KatHttp3RequestBody.Bytes`, `FileBody`, and `Stream` accept an in-memory body, a file, or a producer `Flow<ByteArray>`. File and producer uploads use a bounded native queue (4 MiB). A producer must not emit an empty chunk.

### Configure the client

`KatHttp3ClientConfig` sets limits independently. The most commonly adjusted settings are:

| Property | Default | Purpose |
| --- | --- | --- |
| `callTimeoutMillis` | 30,000 | Deadline for the complete native call |
| `dnsTimeoutMillis` | 10,000 | DNS resolution |
| `connectTimeoutMillis` | 10,000 | Connection setup |
| `handshakeTimeoutMillis` | 10,000 | QUIC/TLS handshake |
| `responseHeadersTimeoutMillis` | 30,000 | Waiting for response headers |
| `readTimeoutMillis` / `writeTimeoutMillis` | 30,000 / 30,000 | Time without progress in the corresponding direction |
| `maxBufferedBodyBytes` | 16 MiB | Maximum buffered response body |
| `maxStreamingBufferedBodyBytes` | 4 MiB | Request-body stream buffer limit passed to the native client |
| `maxStreamingBufferedBytesPerStream` | 1 MiB | Pending Kotlin body bytes for one streaming call |
| `maxStreamingBufferedBytesPerConnection` | 16 MiB | Shared Kotlin streaming-response budget |
| `maxActiveStreamsPerOrigin` | 8 | Local active-call limit per origin |
| `maxQueuedRequestsPerOrigin` | 64 | Local waiting-call limit per origin |
| `queueTimeoutMillis` | 30,000 | Time a request may wait for a local permit |
| `maxConnectionWorkers` | 32 | Upper bound on native connection workers |

The scheduler limits are **local admission controls**, not the QUIC peer's advertised `MAX_STREAMS` value. Waiting for a permit does not consume the response-header, read-idle, or write-idle deadline. Priority follows RFC 9218 urgency values: 0 is most urgent, 7 is background. Requests with the same urgency are queued FIFO. A supplied `priority` header takes precedence over the generated header; changing priority after submission is not supported.

```kotlin
import dev.kathttp3.KatHttp3ClientConfig

val config = KatHttp3ClientConfig(
    callTimeoutMillis = 20_000,
    maxBufferedBodyBytes = 8L * 1024 * 1024,
    maxActiveStreamsPerOrigin = 8,
    maxQueuedRequestsPerOrigin = 32,
)
val client = KatHttp3Client(config)
```

`callTimeoutMillis` is an absolute request deadline. Read and write idle timers reset only when the corresponding operation makes progress. The API reports timeouts through `KatHttp3Exception.Timeout` and `KatHttp3TimeoutPhase`.

### Retries and errors

The default client **does not retry requests**. For policy-based retries, add `PolicyRetryInterceptor` to `KatHttp3ClientConfig.interceptors`. This policy restricts retries to allowed idempotent methods and connection failures. Cancellation and certificate failures are not retried; neither are application-level HTTP failures by default.

```kotlin
import dev.kathttp3.PolicyRetryInterceptor

val config = KatHttp3ClientConfig(
    interceptors = listOf(PolicyRetryInterceptor()),
)
```

The less restrictive `RetryInterceptor` also exists. Review its policy before enabling it for requests with side effects.

Common exceptions include:

| Exception | Meaning |
| --- | --- |
| `KatHttp3Exception.Dns` | Name resolution failed |
| `KatHttp3Exception.Timeout` | A named timeout phase elapsed |
| `CertificateVerificationException` | Certificate trust or hostname verification failed |
| `TlsHandshakeException` | TLS handshake failed |
| `QuicTransportException` | QUIC transport failed |
| `KatHttp3Exception.BodyTooLarge` | Buffered response exceeded its limit |
| `KatHttp3Exception.StreamingBufferLimitExceeded` | Streaming response exhausted its Kotlin byte budget |
| `KatHttp3Exception.ConsumerStallTimeout` | A streaming consumer stopped making progress |
| `KatHttp3Exception.NetworkLost` | The selected network path was lost |
| `KatHttp3Exception.RequestQueueFull` / `RequestQueueTimeout` | Local scheduler rejected or expired a waiting request |

When `expectSuccess = true`, buffered HTTP responses with status 400 or above raise `ResponseException`. Otherwise, non-2xx HTTP statuses are returned to the caller as ordinary responses.

## Security and HTTP behavior

### Certificate verification

Peer certificate and hostname verification are enabled by default. The trust provider is selected with `trustMode`:

| Mode | Behavior |
| --- | --- |
| `TrustMode.PLATFORM` (default) | Android's platform `X509TrustManager` and Network Security Config; system trust paths on host |
| `TrustMode.EMBEDDED_MOZILLA` | Bundled Mozilla CA certificates |
| `TrustMode.CUSTOM_CA` | Caller-provided PEM bundle at `caCertificateFile` |

The Android platform verifier uses `X509TrustManagerExtensions` through the JNI bridge. `insecureCert = true` disables verification entirely.

**Warning:** Never enable `insecureCert` or TLS key logging in production. If the platform trust provider is unavailable, certificate verification fails rather than silently falling back to insecure behavior.

Redirects reject HTTPS-to-HTTP downgrades. Cross-origin redirects remove sensitive headers, including Authorization, Proxy-Authorization, Cookie, and Host.

### Cookies, 0-RTT, and cache

The cookie jar is experimental and disabled by default (`enableCookies = false`). It does not implement a public suffix list and is **not** a browser-equivalent cookie implementation.

0-RTT is enabled by default (`enable0Rtt = true`), but early data is limited to credential-free, bodyless GET/HEAD requests. TLS session tickets and QUIC transport parameters are cached in memory for the client lifetime. Rejected early data is replayed after handshake confirmation using fresh HTTP/3 state. Tickets are not persisted to disk.

The optional private response cache is also disabled by default:

```kotlin
val config = KatHttp3ClientConfig(
    enableHttpCache = true,
    httpCacheMaxEntries = 128,
    httpCacheMaxBytes = 32L * 1024 * 1024,
    httpCacheMaxEntryBytes = 4L * 1024 * 1024,
)
```

This is a per-client, in-memory cache. It initially stores only complete, buffered GET responses with status 200 and explicit freshness. Requests with Range, Authorization, or Cookie bypass storage. Streaming, oversized, and partial responses also bypass the cache. It handles `Vary`, `Age`, validators (ETag / Last-Modified), 304 merging, cache directives, stale-if-error, and LRU eviction. Cached responses omit `Set-Cookie`.

The native dispatcher bounds pending cache-hit deliveries to 128 and accounts for response bytes within `httpCacheMaxBytes`. If it cannot queue a delivery, the operation fails with `KATHTTP3_ERR_NOMEM` rather than allocating without limit. Disk persistence, heuristic freshness, and range-response caching are not implemented.

### Android network changes

Pass an application `Context` to enable the internal ConnectivityManager observer:

```kotlin
val client = KatHttp3Client(
    config = KatHttp3ClientConfig(),
    applicationContext = applicationContext,
)
```

With `NetworkChangePolicy.ATTEMPT_MIGRATION` (the default), a confirmed connection attempts migration to a new Android default network. The client binds a new UDP socket and validates the new path. Existing HTTP/3 streams remain associated with that connection if migration succeeds.

If no replacement network is available or migration cannot complete, affected calls fail with `KatHttp3Exception.NetworkLost`. An explicitly configured retry policy may then retry replay-safe requests. DNS state is partitioned by Android network generation. KatHttp3 does **not** bind the entire Android process to a network.

`NetworkChangePolicy.CLOSE_AND_RECONNECT` selects reconnect behavior instead of migration.

## Build and development

### Android native dependencies

The build script downloads pinned sources instead of using Android's private BoringSSL ABI. The revisions are maintained in `third_party/versions.env`:

| Dependency | Revision | License |
| --- | --- | --- |
| ngtcp2 | `v1.24.0` | MIT |
| nghttp3 | `v1.17.0` | MIT |
| BoringSSL | `3c6315e00ab02d7bc9b8922aff1f85d8f81ee130` | ISC/BSD-style; refer to the upstream license |

The script produces `libngtcp2.a`, `libngtcp2_crypto_boringssl.a`, `libnghttp3.a`, `libssl.a`, and `libcrypto.a` under `third_party/android-deps/<ABI>/lib/`, alongside the corresponding headers.

To build only one ABI or rebuild its dependencies:

```sh
scripts/build-android-deps.sh --abi arm64-v8a --jobs 8
scripts/build-android-deps.sh --clean --abi arm64-v8a
scripts/build-android-deps.sh --parallel-abis 2 --jobs 2
```

The last command builds two ABI sets concurrently with two compiler jobs each. Sources are stored under `third_party/src/` and intermediates under `third_party/build-android/`. Cached outputs are checked against dependency revisions, the recipe, expected static libraries, and the Android API level before reuse.

The project uses the Gradle 9.8.1 wrapper, Android Gradle Plugin 9.4.1, and Compose compiler plugin 2.4.21. Build tooling versions should be checked against the repository's Gradle files rather than copied from old release notes.

### Host core build and tests

On Linux, install CMake 3.22.1 or newer, a C++20 compiler, pkg-config, and compatible development packages for ngtcp2, nghttp3, and `libngtcp2_crypto_ossl` (the default host TLS integration). To use BoringSSL on host builds, configure the corresponding ngtcp2 crypto integration and BoringSSL include/library paths. The host configuration does not require JNI for the ordinary core tests.

```sh
cmake -S . -B build -DKATHTTP3_BUILD_TESTS=ON -DKATHTTP3_BUILD_JNI=OFF
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

For AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
cmake -S . -B build-sanitize -DKATHTTP3_SANITIZE=ON -DKATHTTP3_BUILD_JNI=OFF
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure
```

The test suite includes URL, redirect, cookie, resolver, Happy Eyeballs, cache parsing, freshness and revalidation tests, together with Kotlin model/configuration tests. The CI pipeline additionally exercises a pinned HTTP/3 interoperability smoke test against an ngtcp2 example server. These checks do not replace testing on real Android networks and application endpoints.

### Formatting and static analysis

Formatting, clang-tidy, cppcheck, sanitizer builds and Kotlin lint run in CI. To inspect the native code locally:

```sh
find src include tests -type f ! -name ca_bundle.h \
  \( -name '*.cc' -o -name '*.cpp' -o -name '*.c' -o -name '*.h' -o -name '*.hpp' \) \
  -print0 | xargs -0 -r clang-format --dry-run --Werror

cmake -S . -B build-tidy -G Ninja \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DKATHTTP3_ANALYSIS_ONLY=ON -DKATHTTP3_BUILD_JNI=OFF
run-clang-tidy -p build-tidy -quiet
cppcheck --project=build-tidy/compile_commands.json \
  --enable=warning,style,performance,portability \
  --inline-suppr --suppress=missingIncludeSystem --error-exitcode=1
```

`ca_bundle.h` is generated and excluded from formatting. Include What You Use is optional (`-DKATHTTP3_ENABLE_IWYU=ON`); external QUIC/TLS headers may need project-specific mappings.

### Example app

The application under `example/` uses `implementation(project(":kathttp3"))`. It can issue GET, POST, PUT, DELETE, PATCH, and HEAD requests, edit HTTPS URLs and headers, and cancel an active call. It shows response status, headers, protocol, duration, transferred bytes, and errors. Response text display is limited to 16,000 characters.

By default its URL points at `https://nghttp2.org/httpbin`. Replace it with an HTTP/3-capable endpoint when testing another server. Cleartext HTTP is disabled in the example manifest.

## Diagnostics and troubleshooting

### Build fails

- **Android SDK or NDK not found:** Check `ANDROID_HOME` / `ANDROID_SDK_ROOT`, the installed SDK platform and the NDK version. Run the native dependency task separately to isolate its failures.
- **Missing libraries for an ABI:** Re-run `scripts/build-android-deps.sh --abi <ABI>`, then build the AAR. If an alternate output location is used, configure `KATHTTP3_DEPS_ROOT` for the example or `kathttp3DepsRoot` for Gradle.
- **Host build cannot find QUIC libraries:** Check the ngtcp2/nghttp3 pkg-config packages and selected TLS linkage. `KATHTTP3_ANALYSIS_ONLY=ON` is for source analysis, not a working HTTP/3 client.
- **No device found:** Check `adb devices`. With multiple devices, set `DEVICE_SERIAL` before `make adbinstall`.

### Request fails

- **DNS failure:** Check the hostname, resolver, Android network permissions and the selected network.
- **QUIC connection or handshake failure:** Confirm that the endpoint actually supports HTTP/3 and is reachable over UDP. KatHttp3 does not silently downgrade to TCP-based HTTP.
- **Certificate error:** Verify the host name, certificate chain and configured trust mode. Do not disable verification to work around a production certificate error.
- **RequestQueueFull / RequestQueueTimeout:** Check per-origin active/queued limits and whether callers are closing or cancelling abandoned streams.
- **BodyTooLarge / StreamingBufferLimitExceeded:** Increase the appropriate budget only if memory usage permits, or switch to streaming and consume events promptly.
- **NetworkLost:** Confirm that an application Context was supplied if automatic Android network observation is needed, and test migration/retry policy on the target network.

### qlog

qlog is disabled by default. On Android, enabling `qlogEnabled` without a file prefix uses a bounded buffered Logcat destination. Set `qlogPathPrefix` to a writable app-private prefix for one mode-0600 `.qlog` file per connection; set `qlogLogcatEnabled` to use both.

```kotlin
val config = KatHttp3ClientConfig(
    qlogEnabled = true,
    qlogPathPrefix = "/data/user/0/your.application.id/files/quic",
)
```

The path is an example and must be replaced with a location the application can write to. qlog records can expose sensitive connection metadata. Do not enable qlog or TLS key logging in normal production builds. qlog output is based on ngtcp2's writer; it is not claimed to implement every current QUIC/HTTP3 qlog schema.

## Architecture and compatibility

### Component responsibilities

```text
Kotlin client and coroutine API
  -> JNI bridge
    -> stable C ABI (opaque client and request handles)
      -> native Engine and per-origin QUIC worker
        -> nghttp3 (HTTP/3 framing, SETTINGS, QPACK)
        -> ngtcp2 (QUIC packets, recovery, flow control)
        -> BoringSSL (TLS 1.3, encryption)
          -> non-blocking UDP socket
```

KatHttp3 owns DNS resolution, event-loop and timer scheduling, origin pooling, certificate policy, redirects, cookies, cache policy and language bindings. ngtcp2 manages QUIC transport; nghttp3 manages HTTP/3 frames; BoringSSL manages TLS.

Each connection worker owns its UDP descriptor and QUIC/TLS state. The engine maintains requests and the optional in-memory state. JNI callback data is valid only during the callback and is copied before publication to Kotlin. Cancellation, close, and terminal delivery are idempotent at public boundaries.

### Native C ABI

The C API is declared in `src/core/kathttp3.h` (also exposed through `include/kathttp3/kathttp3.h`). It uses opaque client/request handles and structs beginning with `struct_size` and `abi_version`.

Initialize a current-sized configuration with:

```c
kathttp3_client_config config;
kathttp3_client_config_init_size(&config, sizeof(config));
```

`kathttp3_client_config` is an alias of `kathttp3_client_options`. The legacy initializer deliberately writes only the old prefix; use the size-aware initializer when accessing newly appended fields. Known smaller structs are accepted with defaults for missing fields; future ABI versions are rejected. Existing 0.x values are not reordered and optional fields are appended. Exported symbols use the `kathttp3_*` prefix.

**Ownership:** `kathttp3_client_execute` transfers ownership of its request to the native engine. C callback buffers are valid only for the duration of the callback. Callers must not use a handle after destroy and should clear their stored pointer.

### Transport and implementation notes

- The worker drives ngtcp2 timers using monotonic time, a non-blocking UDP socket, and client control/QPACK streams created after 1-RTT keys are available.
- Native receive-window defaults use 1 MiB stream high and 512 KiB low watermarks, an 8 MiB connection limit, and 64 KiB credit batching. These are distinct from the configurable Kotlin queue limits.
- Receive credit wakes the worker promptly, while multiple pending credit operations can share a wake-up. A consumer blocked by the local queue uses the consumer-stall timeout, not a misleading network read-idle timeout.
- DNS runs in a bounded resolver pool, coalesces identical in-flight lookups, and accounts for Android network generations. Platform resolution retains the OS cache policy; a brief native success cache absorbs bursts. The bundled DoH resolver uses answer TTLs and RFC 2308 negative-cache information when available.
- Connection establishment races address families after a 250 ms stagger when both IPv4 and IPv6 are available. The handshake winner is selected before the HTTP/3 request is submitted. This is separate from migration of an established connection.
- QUIC keep-alive is active only while request streams are in use. PMTUD, send pacing, bounded UDP retry queues, and supported Linux/Android batched socket operations are implemented. If UDP GSO is not supported, the sender falls back to individual datagrams.
- Header validation rejects invalid HTTP/3 field names, forbidden connection-specific fields, invalid TE, malformed statuses, and conflicting body lengths.

### Current limitations

- Only HTTP/3 is implemented; there is no automatic HTTP/1.1 / HTTP/2 fallback.
- Response trailers and informational responses are not exposed through the Kotlin response model. GOAWAY drains existing work without a separately configurable drain deadline.
- The cookie jar is experimental and has no public suffix list. The HTTP cache is private, in-memory and intentionally narrower than a browser cache.
- Dynamic RFC 9218 PRIORITY_UPDATE after submission is not exposed.
- Uploads and connection migration still require endpoint- and device-specific interoperability testing beyond ordinary CI.
- Native UDP retry queues are bounded, but their counters are not exposed as public metrics.
- qlog support is diagnostic and does not imply full compliance with all evolving qlog schema drafts.

## Repository layout

| Path | Contents |
| --- | --- |
| `kathttp3/` | Kotlin API, Android library, JNI packaging |
| `example/` | Jetpack Compose example application |
| `src/core/` | QUIC/HTTP3 engine, transport, C ABI, caching |
| `src/jni/` | JNI bridge, Android certificate verifier, qlog |
| `include/kathttp3/` | Public C include |
| `tests/core/` | Host unit and state tests |
| `tests/interop/` | HTTP/3 smoke-test client |
| `tests/fuzz/` | Parser and protocol fuzz targets |
| `scripts/build-android-deps.sh` | Reproducible native dependency builds |
| `third_party/versions.env` | Pinned upstream revisions |
| `third_party/android-deps/` | Generated ABI-specific libraries and headers |

## License

KatHttp3 uses the [BSD 2-Clause License](LICENSE). ngtcp2, nghttp3, and BoringSSL remain subject to their respective upstream licenses.
