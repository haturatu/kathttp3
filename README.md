# KatHttp3

KatHttp3 is an independent, native HTTP/3 client library for Android (API 26+) that does not depend on Cronet. It ships its own C++20 core built directly on `ngtcp2 1.24.0 + nghttp3 1.17.0 + BoringSSL`, exposed through a stable C ABI, a JNI bridge, and a coroutine-based Kotlin API, with a Jetpack Compose example.

> Status: host core tests, an ngtcp2/nghttp3/BoringSSL HTTP/3 interoperability
> smoke test, and Android library/example builds are automated. Redirects,
> uploads, cancellation, and Android network changes still need validation
> against each target server and real device network.

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

Kotlin owns immutable request values and copies callback data. A JNI callback owns one global reference until one terminal callback. `kathttp3_client_execute` transfers request ownership to native code; callback buffers are valid only during the callback. Engine owns request registry, cookies and connection pool. Each connection worker exclusively owns its UDP fd, TLS session, ngtcp2 connection and nghttp3 connection. `close`, cancellation and terminal delivery are idempotent at their public boundaries.

ngtcp2 owns QUIC packet parsing/generation, loss recovery, congestion and transport flow control. nghttp3 owns HTTP/3 framing, SETTINGS and QPACK encoding/decoding. BoringSSL owns TLS 1.3 and cryptography. KatHttp3 owns DNS, UDP/timer driving, SNI/ALPN/certificate policy, critical stream creation, request lifecycle, redirects/cookies, and language bindings.

## Host build and tests

Prerequisites are CMake 3.22+, C++20, pkg-config, and matching development packages for ngtcp2/nghttp3. The tested host versions are ngtcp2 1.24.0 and nghttp3 1.17.0.

```sh
cmake -S . -B build -DKATHTTP3_BUILD_TESTS=ON -DKATHTTP3_BUILD_JNI=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Sanitizers:

```sh
cmake -S . -B build-asan -DKATHTTP3_SANITIZE=ON
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

## Android dependencies and build

Prerequisites:

- Android SDK with platform 36 and build-tools 36.0.0
- Android NDK `27.0.12077973`
- CMake 3.22.1 or newer, Git, and Java 17. Ninja is recommended; Unix
  Makefiles are used automatically when Ninja is unavailable.

Set `ANDROID_HOME` or `ANDROID_SDK_ROOT`. An explicit `ANDROID_NDK_HOME` is also accepted. KatHttp3 deliberately does not link Android's private platform BoringSSL ABI. The checked-in build script downloads fixed upstream sources and cross-compiles these static libraries:

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

The GitHub Actions workflows pin action commits, cancel superseded runs for the
same branch or pull request, and bound every job with a timeout. Gradle's setup
action caches Gradle state. Android and native-analysis jobs additionally cache
the fixed SDK toolchains plus pinned dependency source checkouts and generated
`third_party/android-deps` static libraries. The native-dependency cache key
includes the dependency revisions, build recipe, and every
`third_party/patches/**` input. The build script validates each cached ABI
(headers, all five libraries, API level, revisions, and recipe version) before
skipping it, so an incomplete cache is rebuilt rather than used.

The Android build produces one combined AAR and verifies that it contains
`arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86` native libraries before it
publishes the build artifact. It builds two ABI dependency sets concurrently
with two compiler jobs per set, avoiding CPU oversubscription on hosted
runners. The Gradle build cache and parallel project execution are enabled in
`gradle.properties`.

Build the APK after dependencies:

```sh
./gradlew buildAndroidNativeDeps
./gradlew :example:assembleDebug
ls -l example/build/outputs/apk/debug/example-debug.apk
```

## Native code quality checks

GitHub Actions runs native formatting, clang-tidy and cppcheck against the
project-pinned Android dependency headers, host core tests under
AddressSanitizer and UndefinedBehaviorSanitizer, and a Linux HTTP/3 smoke test
against a pinned ngtcp2 example server built with pinned nghttp3 and BoringSSL.
The Android workflow runs Kotlin unit tests, library lint, release-AAR ABI
contents verification, and the example APK build. The default
clang-tidy profile is deliberately staged: it reports selected bug-prone,
analyzer, performance, portability, and low-noise modernize/readability checks
without treating the existing baseline as errors.

```sh
# Formatting check / automatic formatting (generated CA bundle is excluded).
find src include tests -type f ! -name ca_bundle.h \( -name '*.cc' -o -name '*.cpp' -o -name '*.c' -o -name '*.h' -o -name '*.hpp' \) -print0 | xargs -0 clang-format --dry-run --Werror
find src include tests -type f ! -name ca_bundle.h \( -name '*.cc' -o -name '*.cpp' -o -name '*.c' -o -name '*.h' -o -name '*.hpp' \) -print0 | xargs -0 clang-format -i

# Compilation database and clang-tidy/cppcheck without linking transport deps.
cmake -S . -B build-tidy -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DKATHTTP3_ANALYSIS_ONLY=ON -DKATHTTP3_BUILD_JNI=OFF
run-clang-tidy -p build-tidy -quiet
cppcheck --project=build-tidy/compile_commands.json --enable=warning,style,performance,portability --inline-suppr --suppress=missingIncludeSystem --error-exitcode=1

# ASan + UBSan for the core test suite.
cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug -DKATHTTP3_ANALYSIS_ONLY=ON -DKATHTTP3_SANITIZE=ON -DKATHTTP3_BUILD_JNI=OFF
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure
```

Include What You Use is intentionally opt-in because external QUIC/TLS headers
need project-specific mappings.  Install `include-what-you-use` and configure
with `-DKATHTTP3_ENABLE_IWYU=ON` when running this manual audit.

The module uses compile SDK 36, minimum SDK 26, and Java/Kotlin JVM target 17.
The checked-in wrapper uses Gradle 9.6.1; the Android Gradle Plugin version is
9.2.1 and the Compose compiler plugin version is 2.4.0.

### Publishing and consuming

The `:kathttp3` module is configured with `maven-publish`. Building the release
AAR first runs `buildAndroidNativeDeps` automatically (wired through `preBuild`),
so a single command cross-compiles the pinned native dependencies for all four
ABIs and packages `libkathttp3.so` into the AAR:

```sh
./gradlew :kathttp3:publishReleasePublicationToMavenLocal
```

The same command runs on JitPack via [`jitpack.yml`](jitpack.yml). Add JitPack as
a repository and depend on the tag you want:

```kotlin
repositories { maven("https://jitpack.io") }
dependencies { implementation("com.github.haturatu:kathttp3:v0.1.8") }
```

For stable releases, build the AAR once in CI (`[Android AAR]` workflow), publish
it to Maven Central, and depend on `dev.kathttp3:kathttp3:<version>` instead.

Pinned dependencies and licenses:

| Library | Version | License |
| --- | --- | --- |
| BoringSSL | `3c6315e00ab02d7bc9b8922aff1f85d8f81ee130` | ISC-style/BSD-style; see upstream `LICENSE` |
| nghttp3 | `v1.17.0` | MIT |
| ngtcp2 | `v1.24.0` | MIT |

These revisions are defined once in [`third_party/versions.env`](third_party/versions.env), which `scripts/build-android-deps.sh` sources and `third_party/versions.cmake` loads. Edit `versions.env` to bump a dependency.

### Certificate trust

Peer and hostname verification are enabled by default. The default trust mode is `KATHTTP3_TRUST_PLATFORM`, which on Android delegates to the platform `X509TrustManager` through `android.net.http.X509TrustManagerExtensions` (BoringSSL's custom-verify callback forwards the peer chain, server name and key type). This automatically inherits the Android system trust store and Network Security Config, so public-server use works out of the box without a bundled CA file.

Three trust modes are selectable through `kathttp3_trust_mode`:

| Mode | Meaning |
| --- | --- |
| `KATHTTP3_TRUST_PLATFORM` (default) | Use the OS/platform trust provider (Android `X509TrustManagerExtensions`; host OpenSSL default paths). |
| `KATHTTP3_TRUST_EMBEDDED_MOZILLA` | Verify against the built-in Mozilla CA bundle (`ca_bundle.h`). |
| `KATHTTP3_TRUST_CUSTOM_CA` | Verify against a caller-supplied PEM CA file (`ca_cert_file`). |

`insecure_cert` disables verification entirely; it is debug-only and must never be enabled in shipped builds.

Verification failure is fatal and surfaced with a distinct error code rather than a generic transport error: `KATHTTP3_ERR_TLS` (-4) for handshake-level failures, `KATHTTP3_ERR_CERTIFICATE_VERIFY` (-5), `KATHTTP3_ERR_HOSTNAME_MISMATCH` (-6), and `KATHTTP3_ERR_NO_TRUST_PROVIDER` (-7) when no trust provider is configured. The Kotlin API throws `TlsHandshakeException`, `CertificateVerificationException`, or `QuicTransportException` accordingly; transport errors remain `KATHTTP3_ERR_QUIC` (-3) / `QuicTransportException`. KatHttp3 does not silently disable verification. Key logging is debug-only and must never be enabled in shipped builds.

## Kotlin usage

```kotlin
KatHttp3Client().use { client ->
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
        listOf(KatHttp3Header("content-type", "application/json")),
    )
}
job.cancel() // propagated to RESET_STREAM / STOP_SENDING
```

`execute` buffers at most `maxBufferedBodyBytes` (16 MiB by default).
`executeStreaming` exposes a bounded `Flow<KatHttp3StreamEvent>`; close/cancel
its `KatHttp3Call` when abandoning collection. Native receive-window credit is
queued from the Kotlin `Flow` delivery hook, rather than being returned directly
from the JNI body callback.

`KatHttp3ClientConfig` has independent monotonic deadlines for DNS, connect,
handshake, response headers, read-idle, write-idle, and the complete call.
`callTimeoutMillis` is an absolute request deadline; read/write timeouts reset
only when the corresponding direction makes progress. Timeout failures are
reported as `KatHttp3Exception.Timeout` with a `KatHttp3TimeoutPhase`.

`KatHttp3RequestBody.Bytes`, `FileBody`, and `Stream` support buffered,
file-backed, and producer-`Flow` uploads. `FileBody` and `Stream` use a bounded
native queue (4 MiB), and a non-empty `Stream` chunk is required. Retries are
opt-in: add `PolicyRetryInterceptor` (or `RetryInterceptor`) through
`KatHttp3ClientConfig.interceptors`; the default client does not retry.

KatHttp3 also applies local, origin-scoped admission control before a request is
created in native code. `maxActiveStreamsPerOrigin` defaults to 8,
`maxQueuedRequestsPerOrigin` to 64, and `queueTimeoutMillis` to 30 seconds.
This is a client resource limit, not QUIC's peer-advertised `MAX_STREAMS`.
Queued calls are selected by `KatHttp3Request.priority.urgency` using RFC 9218's
0 (most urgent) through 7 (background) ordering, with FIFO ordering inside one
urgency. Priority affects local admission only; applications that want to
signal the server must also provide the HTTP `priority` header.
Queue waiting does not consume response-header, read-idle, or write-idle time;
it ends with `KatHttp3Exception.RequestQueueTimeout` or
`KatHttp3Exception.RequestQueueFull` before native stream creation.

Pass an application `Context` to `KatHttp3Client` to enable its internal
`ConnectivityManager` observer. A confirmed QUIC connection is rebound to the
new Android default `Network` and uses a fresh UDP socket, connection ID and
ngtcp2 path validation while keeping its HTTP/3 streams. If no replacement
network exists, the handshake is not confirmed, socket binding fails, or path
validation fails, active calls end with `KatHttp3Exception.NetworkLost`; a
configured retry policy may retry only replay-safe methods on a new connection.
DNS is scoped to the new Android network handle and its old cache generation is
invalidated. KatHttp3 never binds the entire application process to a network.

## Example app

The local-module Compose app is in `example/` and uses `implementation(project(":kathttp3"))`.
It starts each method with an empty header/body preset and an editable
`https://nghttp2.org/httpbin` URL; replace that URL when testing another
HTTP/3-capable HTTPS server. Select GET, POST, PUT, DELETE, PATCH, or HEAD,
then press the single `Send <method>` button. POST, PUT, PATCH, and DELETE
expose an editable UTF-8 body; headers are entered as lowercase `name: value`
lines. Cancel cancels the coroutine and native request. The app shows status,
headers, HTTP/3-over-QUIC protocol information, duration, byte count, and
errors; response rendering is capped at 16,000 characters to keep the UI
responsive. Cleartext traffic is disabled.

With one Android device connected through adb, the example can be built and installed from its directory:

```sh
cd example
make adbinstall
```

By default dependencies are read from `third_party/android-deps`; override this with `KATHTTP3_DEPS_ROOT=/absolute/path` when needed. When multiple devices are connected, add `DEVICE_SERIAL=<adb-serial>`. The target runs `:example:assembleDebug`, verifies the APK, and installs it with `adb install -r`.

## Tests

- `tests/core/core_tests.cc`: URL/port validation, redirect and cookie
  matching, asynchronous resolver delivery, Happy Eyeballs candidate planning,
  and DNS-cache behavior.
- `kathttp3/src/test`: Kotlin configuration, request, and header validation.
- The Android build compiles the JNI bridge and all four configured ABIs.
- External-network and local ngtcp2-server tests are not part of this
  repository's ordinary test suite.

## Protocol notes

The worker drives `ngtcp2_conn_get_expiry2`/`ngtcp2_conn_handle_expiry` with monotonic nanoseconds and drains non-blocking UDP. After 1-RTT keys are available, it creates the nghttp3 client plus one control and two QPACK unidirectional streams. Requests use client bidirectional streams with `:method`, `:scheme`, `:authority`, and `:path`. Cancellation requests both read and write shutdown.

## C ABI compatibility

The C ABI uses `kathttp3_client_config` (an alias of the retained
`kathttp3_client_options`) with `struct_size` and `abi_version`. Initialize it
with `kathttp3_client_config_init`. KatHttp3 accepts known smaller structs and
defaults appended fields; it rejects future ABI versions. During the 0.x line,
existing enum values and fields are not reordered and optional fields are
appended only. Symbols are hidden by default except `kathttp3_*` exports.

## Known limitations

- Certificate trust defaults to the Android platform provider (`X509TrustManagerExtensions`); the embedded Mozilla bundle and a caller-supplied CA file are also available via `kathttp3_trust_mode`.
- Live interoperability is not covered by a local HTTP/3-server integration
  test in this repository.
- DNS, connect, handshake, response-header, read-idle, write-idle and call
  deadlines use the monotonic QUIC clock.
- Response trailers and informational responses are not exposed by the Kotlin
  response model. GOAWAY handling drains existing work, but there is no
  separately configurable drain deadline.
- Response header validation rejects invalid/uppercase field names,
  connection-specific fields, invalid `TE`, malformed `:status`, and invalid
  or conflicting `Content-Length`. Body length is checked at completion.
- UDP transient send failures are queued with fixed packet and byte limits;
  queue overflow is surfaced as a connection failure. There are no public
  queue metrics.
- Streaming response credit is returned when JNI callback data has been copied
  into KatHttp3's bounded Kotlin buffer, not when a Flow collector later runs.
  It is therefore not an acknowledgement that arbitrary application work after
  collection has completed.
- Kotlin queues are also guarded by byte budgets: configure
  `maxStreamingBufferedBytesPerStream` and
  `maxStreamingBufferedBytesPerConnection` (defaults: 1 MiB and 16 MiB).
  The per-stream cap is deliberate fairness control: a single slow image
  consumer cannot reserve the shared client budget needed by other streams.
- Receive-window credit is queued and wakes the QUIC worker on every accepted
  consume operation; it is never left waiting solely for a 64 KiB batch. Read,
  response-header, and write timeouts drain the affected connection from the
  pool before a retry. Automatic retries are limited to DNS, connect, and
  handshake failures; read, call, and consumer-stall timeouts are not retried.
- Deadline arithmetic uses saturating monotonic elapsed time, so callback
  progress recorded later in an event-loop iteration cannot wrap and cause an
  immediate timeout. Timeout diagnostics include the process-local connection
  ID, timestamps, configured deadline, state, pending reason, remote address,
  and address family. A connection-level timeout reports only its triggering
  request as that phase; remaining requests fail as connection errors.
- Native QUIC receive windows use fixed 1 MiB stream high / 512 KiB low
  watermarks, an 8 MiB connection limit, and 64 KiB credit batching. These
  values are not yet public configuration knobs. The same limits are applied
  to normal and Happy Eyeballs connection candidates before the winner is
  adopted. A stream or shared connection window intentionally blocked by the
  local consumer does not trigger a network read-idle timeout; a separate
  consumer-stall timeout governs abandoned streaming calls. Configure it with
  `consumerStallTimeoutMillis` (default: `readTimeoutMillis`); it is reported
  as `KatHttp3Exception.ConsumerStallTimeout`, not as a network timeout.
- While at least one request stream is active, the worker configures ngtcp2
  keep-alive at half of the peer-advertised idle timeout. It disables probes
  when no request stream is active; keep-alive is therefore not a background
  connection-pooling heartbeat.
- PMTUD is explicitly enabled through ngtcp2's built-in safe probe sequence.
  Packet generation is capped by ngtcp2's current send quantum and updates
  its pacing timestamp after each quantum. When the bounded UDP retry queue
  contains adjacent equal-sized packets, Linux/Android uses `UDP_SEGMENT` GSO
  to flush up to 16 in one syscall. Unsupported kernels permanently fall back
  to FIFO single-datagram sends; the non-GSO path remains the portable default.
- qlog is disabled by default. `KatHttp3ClientConfig(qlogEnabled = true)` enables the Android-only,
  bounded buffered Logcat destination. Set `qlogPathPrefix = "..."` to instead produce one
  mode-0600 ngtcp2 `.qlog` file per connection at an app-private writable prefix; set
  `qlogLogcatEnabled = true` to use both destinations. A core C ABI `qlog_sink_cb` is also
  available for non-Android destinations and must be non-blocking. Logcat queue contention or a
  256 KiB queue overflow drops diagnostics rather than delaying QUIC processing. Treat qlog as
  sensitive connection metadata and do not enable it in normal production builds. The current
  output is ngtcp2's qlog writer; KatHttp3 does not claim full conformance to draft-ietf-quic-qlog-main-schema-14, whose
  protocol-specific QUIC and HTTP/3 event schemas are defined in separate
  drafts.
- DNS lookups run in a bounded two-thread resolver pool rather than on a QUIC
  worker. Concurrent lookups for the same case-insensitive hostname, port,
  resolver, and Android network generation share one in-flight query; each
  caller waits asynchronously and may cancel without cancelling its peers. A
  reusable Active or Connecting origin connection is selected before a new
  client can submit DNS. When the 32-task worker queue is full, up to 128
  additional unique hosts wait in a bounded host queue; duplicate hosts still
  attach to their existing flight. Cancellation and DNS deadline expiry remove
  their waiter immediately, and work with no remaining waiters is skipped.
  Platform DNS caching remains owned by Android/libc because `InetAddress` and
  `getaddrinfo` do not expose authoritative TTLs; a five-second native success
  cache only absorbs immediate request bursts and never caches failures. The bundled DoH resolver
  caches successful A/AAAA results for the minimum answer TTL and caches
  NXDOMAIN/NODATA only when an SOA supplies the RFC 2308 negative TTL; malformed,
  timeout, and SOA-less failures are not cached. Network changes partition
  in-flight work and invalidate the previous DNS generation. Cancellation and DNS
  deadlines discard late results. When both
  address families are available, the first resolver-ordered candidate starts
  a QUIC/TLS handshake immediately and the first opposite-family candidate
  starts after 250ms (or immediately after the first candidate fails). The
  handshake winner is selected before any HTTP request stream is opened; the
  loser socket and QUIC state are released. Additional addresses retain the
  sequential fallback path. This handshake race is separate from established
  connection migration. Established Android connections use a network-bound
  replacement socket and ngtcp2's immediate migration, which sends on the new
  path while mandatory PATH_CHALLENGE/PATH_RESPONSE validation is pending; this
  is required when the old mobile or Wi-Fi path has already disappeared.
- JNI caches callback/resolver classes and method IDs at `JNI_OnLoad`. Native
  DNS and QUIC workers attach as daemon threads once, reuse their thread-local
  `JNIEnv*`, and detach when the worker exits; `JNIEnv*` is never shared across
  threads.
- Redirects reject HTTPS-to-HTTP downgrades and strip Authorization,
  Proxy-Authorization, Cookie, and Host on cross-origin hops. The cookie jar
  is experimental and disabled by default (`enableCookies = true` is explicit
  opt-in). It has no public-suffix database, so it must not be treated as a
  browser-equivalent cookie implementation.
- HTTP response caching is not provided. A former disconnected implementation
  is intentionally excluded from production builds; a future cache must cover
  Cache-Control, Vary, Age, Date, Expires, ETag/Last-Modified revalidation,
  304 merging, no-store, stale-if-error, privacy, and Authorization semantics.
- Request bodies support `ByteArray`, `File`, and a producer `Flow<ByteArray>`.
  Flow/File data is bounded to 4 MiB in native memory and only resumes nghttp3
  when chunks arrive. Empty producer chunks are rejected. HTTP/3 upload
  interoperability still requires connected-server validation.
- TLS session tickets and their matching ngtcp2 0-RTT transport parameters are
  cached in memory per origin for the lifetime of a client. `enable0Rtt` is
  enabled by default and only permits credential-free, bodyless GET/HEAD
  requests before handshake confirmation. A rejected early-data attempt
  recreates HTTP/3 state and replays those requests after 1-RTT; the cache is
  intentionally not persisted to disk or shared between clients.
- C ABI `destroy` requires a live handle; callers must null their handle after destroy. JNI detects stale/double-destroy handles.

## Source layout

```text
CMakeLists.txt                  host/Android native build
include/kathttp3/kathttp3.h       public include forwarder
src/core/                       QUIC/HTTP3 engine and C ABI
src/jni/kathttp3_jni.cc          JNI bridge
kathttp3/                        Android library and Kotlin API
example/                        Compose sample app
tests/core/                     host unit tests
scripts/build-android-deps.sh   pinned Android dependency cross-build
third_party/android-deps/       generated per-ABI headers and static libraries
```
