#ifndef KATHTTP3_KATHTTP3_H
#define KATHTTP3_KATHTTP3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * ABI versioning
 *
 * The C ABI is kept stable by versioning every struct with a
 * `struct_size` + `abi_version` header and never removing fields.
 * New optional fields are only appended.
 * ------------------------------------------------------------------ */
#define KATHTTP3_ABI_VERSION_0_1 1u
#define KATHTTP3_ABI_VERSION_CURRENT KATHTTP3_ABI_VERSION_0_1
/* Compatibility spelling retained for 0.x callers. */
#define KATHTTP3_ABI_VERSION KATHTTP3_ABI_VERSION_CURRENT

#if defined(_WIN32)
#define KATHTTP3_API __declspec(dllexport)
#else
#define KATHTTP3_API __attribute__((visibility("default")))
#endif

typedef enum {
    KATHTTP3_OK = 0,
    KATHTTP3_ERR_DNS = -1,
    /* -2 reserved */
    KATHTTP3_ERR_QUIC = -3,               /* QUIC transport error */
    KATHTTP3_ERR_TLS = -4,                /* TLS handshake failure (non-cert) */
    KATHTTP3_ERR_CERTIFICATE_VERIFY = -5, /* certificate trust failure */
    KATHTTP3_ERR_HOSTNAME_MISMATCH = -6,  /* peer cert does not match hostname */
    KATHTTP3_ERR_NO_TRUST_PROVIDER = -7,  /* no verifier available / JNI verifier failed */
    KATHTTP3_ERR_HTTP3 = -8,
    KATHTTP3_ERR_TIMEOUT = -9,
    KATHTTP3_ERR_CANCELLED = -10,
    KATHTTP3_ERR_INVALID_ARG = -11,
    KATHTTP3_ERR_NOMEM = -12,
    KATHTTP3_ERR_CLOSED = -13, /* client destroyed while request in flight */
    KATHTTP3_ERR_BODY = -14,   /* response body length mismatch / truncation */
    KATHTTP3_ERR_DNS_TIMEOUT = -15,
    KATHTTP3_ERR_CONNECT_TIMEOUT = -16,
    KATHTTP3_ERR_HANDSHAKE_TIMEOUT = -17,
    KATHTTP3_ERR_RESPONSE_HEADERS_TIMEOUT = -18,
    KATHTTP3_ERR_READ_TIMEOUT = -19,
    KATHTTP3_ERR_WRITE_TIMEOUT = -20,
    KATHTTP3_ERR_CALL_TIMEOUT = -21,
} kathttp3_error;

/* How the peer certificate is verified. Default is PLATFORM. */
typedef enum {
    KATHTTP3_TRUST_PLATFORM = 0,         /* Android: X509TrustManager;
                                          * else: system trust store */
    KATHTTP3_TRUST_EMBEDDED_MOZILLA = 1, /* bundled Mozilla CA bundle */
    KATHTTP3_TRUST_CUSTOM_CA = 2,        /* PEM bundle at ca_cert_file */
} kathttp3_trust_mode;

/* A single resolved candidate address, as returned by a custom resolver. */
typedef struct kathttp3_resolved_address {
    char ip[64]; /* textual IPv4 or IPv6 */
    uint16_t port;
    int family; /* AF_INET / AF_INET6 */
} kathttp3_resolved_address;

/* Custom name-resolution hook. `out` must be filled with up to *out_count
 * entries and *out_count updated to the count written (0 on failure).
 * Returns 0 on success. */
typedef int (*kathttp3_resolve_cb)(const char* host, uint16_t port, void* userdata,
                                   kathttp3_resolved_address* out, size_t* out_count);

/* Client construction options. Always initialize with
 * kathttp3_client_options_init() so struct_size/abi_version are set. */
typedef struct kathttp3_client_options {
    uint32_t struct_size;
    uint32_t abi_version;

    uint64_t connect_timeout_ms;
    uint64_t request_timeout_ms;
    uint64_t idle_timeout_ms;
    uint32_t max_redirects;
    uint32_t max_connections_per_origin;
    uint8_t enable_0rtt;      /* 0 = off. 0-RTT is off by default; replayable
                                 requests (GET/HEAD, no Authorization) only. */
    const char* ca_cert_file; /* PEM CA bundle; used when trust_mode ==
                                    KATHTTP3_TRUST_CUSTOM_CA. NULL otherwise. */
    uint8_t verify_cert;      /* deprecated: kept for ABI; 1 = verify peer
                               * (default). 0 is superseded by insecure_cert. */
    uint8_t insecure_cert;    /* 1 = disable verification (tests only). Takes
                               * precedence over trust_mode. */
    uint32_t trust_mode;      /* kathttp3_trust_mode; default PLATFORM */
    const char* keylog_file;  /* NULL = disabled */
    uint32_t quic_version;    /* 0 = let ngtcp2 negotiate */

    /* Custom DNS resolver hook. When non-null it overrides the built-in
     * getaddrinfo resolution (this is how a DNS-over-HTTPS / custom resolver is
     * plugged in). The callback fills `out` with up to *out_count candidate
     * addresses and sets *out_count to the number written; return 0 on success. */
    kathttp3_resolve_cb resolve_cb;
    void* resolve_cb_userdata; /* opaque, passed to resolve_cb */

    /* Phase-specific monotonic-duration timeouts.  A zero value inherits the
     * corresponding legacy timeout (connect/request/idle). */
    uint64_t dns_timeout_ms;
    uint64_t handshake_timeout_ms;
    uint64_t response_headers_timeout_ms;
    uint64_t read_timeout_ms;
    uint64_t write_timeout_ms;
    uint64_t call_timeout_ms;
    uint8_t enable_cookies; /* 0 = disabled (default); 1 = experimental jar */
    /* NULL = disabled.  When set, KatHttp3 writes one private .qlog file per
     * QUIC connection using this path as a prefix. */
    const char* qlog_path_prefix;
} kathttp3_client_options;

/* Stable name for new C callers. `kathttp3_client_options` remains source
 * compatible during 0.x. Fields are fixed-width values or create-time input
 * pointers, and future optional fields are appended only. */
typedef kathttp3_client_options kathttp3_client_config;

KATHTTP3_API uint32_t kathttp3_api_version(void);
KATHTTP3_API void kathttp3_client_options_init(kathttp3_client_options* opt);
KATHTTP3_API void kathttp3_client_config_init(kathttp3_client_config* config);

typedef struct kathttp3_client kathttp3_client;
typedef struct kathttp3_request kathttp3_request;

/* ------------------------------------------------------------------ *
 * High-level events
 *
 * The engine delivers a small number of high-level events per request.
 * It does NOT cross the JNI boundary for every UDP packet or every
 * nghttp3 callback; the C++ layer coalesces them into these events.
 *
 * Lifetimes (guaranteed by the engine):
 *  - All pointers in an event are valid only for the duration of the
 *    event callback. Copy anything you need before returning.
 *  - `request_id` is echoed in every event so the caller can map back
 *    to its own per-request state.
 *  - Exactly one terminal event (HEADERS+COMPLETE for success, or
 *    ERROR) is delivered per request_id. It is delivered at most once.
 *
 * Threading (guaranteed by the engine):
 *  - All events for a client are serialized on the engine's native
 *    thread. The callback must not re-enter the engine or call engine
 *    APIs that mutate shared state while running.
 * ------------------------------------------------------------------ */
typedef enum kathttp3_event_type {
    KATHTTP3_EVENT_HEADERS = 1,  /* status_code + names/values/header_count */
    KATHTTP3_EVENT_BODY = 2,     /* data + data_len (may be called 0..n times) */
    KATHTTP3_EVENT_COMPLETE = 3, /* success; error_code == 0 */
    KATHTTP3_EVENT_ERROR = 4,    /* failure; error_code != 0 */
} kathttp3_event_type;

typedef struct kathttp3_event {
    kathttp3_event_type type;
    int64_t request_id;

    int status_code;           /* HEADERS */
    const char* const* names;  /* HEADERS (header_count entries) */
    const char* const* values; /* HEADERS (header_count entries) */
    size_t header_count;       /* HEADERS */

    const uint8_t* data; /* BODY */
    size_t data_len;     /* BODY */

    int error_code; /* COMPLETE (0) / ERROR (non-zero) */
} kathttp3_event;

typedef void (*kathttp3_event_callback)(void* user_data, const kathttp3_event* event);

/* ------------------------------------------------------------------ *
 * Client lifecycle
 * ------------------------------------------------------------------ */
KATHTTP3_API kathttp3_client* kathttp3_client_create(const kathttp3_client_options* options);
KATHTTP3_API void kathttp3_client_close(kathttp3_client* client);
KATHTTP3_API void kathttp3_client_destroy(kathttp3_client* client);

/* A tag combined into the connection-pool key. Use it to separate
 * connections that share a (host, port) but differ in transport policy
 * (e.g. a distinct Android Network, TLS policy or proxy). Two clients
 * with different policy tags never share a QUIC connection. */
KATHTTP3_API void kathttp3_client_set_origin_policy(kathttp3_client* client,
                                                    const char* policy_tag);
KATHTTP3_API void kathttp3_client_network_changed(kathttp3_client* client, uint64_t generation);

/* ------------------------------------------------------------------ *
 * Request
 *
 * Ownership: kathttp3_client_execute() takes ownership of `request`.
 * Do not read, modify or free it after that call.
 * ------------------------------------------------------------------ */
KATHTTP3_API kathttp3_request* kathttp3_request_create(const char* method, const char* url);
KATHTTP3_API void kathttp3_request_destroy(kathttp3_request* request);
KATHTTP3_API int kathttp3_request_add_header(kathttp3_request* request, const char* name,
                                             const char* value);
KATHTTP3_API int kathttp3_request_set_body(kathttp3_request* request, const uint8_t* data,
                                           size_t len);
/* Switches a request to producer-fed body mode. content_length is -1 when
 * unknown. Chunks are appended after execute with client_request_body_append. */
KATHTTP3_API int kathttp3_request_set_streaming_body(kathttp3_request* request,
                                                     int64_t content_length);
KATHTTP3_API void kathttp3_request_set_follow_redirects(kathttp3_request* request, int enable);
KATHTTP3_API void kathttp3_request_set_streaming(kathttp3_request* request, int enable);

/* Pre-resolved address (IPv4/IPv6 string). When one or more addresses
 * are supplied the engine skips its own DNS resolution and races them
 * (happy-eyeballs). This is how an Android caller can feed IPs obtained
 * via the platform DnsResolver bound to a specific Network. */
KATHTTP3_API int kathttp3_request_add_address(kathttp3_request* request, const char* ip,
                                              uint16_t port);

/* Submit a request. `request_id` is an opaque token echoed back in
 * every event; the caller uses it to correlate events with its own
 * per-request state (e.g. a Kotlin coroutine registry entry). */
KATHTTP3_API void kathttp3_client_execute(kathttp3_client* client, kathttp3_request* request,
                                          int64_t request_id, kathttp3_event_callback cb,
                                          void* user_data);

/* Request cancellation. Safe to call from any thread. If the request
 * has already completed, this is a no-op. If still in flight, the
 * engine will stop delivering further events for `request_id`. */
KATHTTP3_API void kathttp3_client_cancel(kathttp3_client* client, int64_t request_id);

/* Streaming flow-control: acknowledge that `bytes` of a streamed response
 * body have been consumed by the application. Extends the HTTP/3 receive
 * window so the peer can send more. Safe to call from any thread. */
KATHTTP3_API void kathttp3_client_consume(kathttp3_client* client, int64_t request_id,
                                          size_t bytes);
/* Returns KATHTTP3_OK only when bytes correspond to body data that was
 * delivered to this request and has not already been consumed. */
KATHTTP3_API kathttp3_error kathttp3_client_consume_body(kathttp3_client* client,
                                                         int64_t request_id, size_t bytes);
KATHTTP3_API kathttp3_error kathttp3_client_request_body_append(kathttp3_client* client,
                                                                int64_t request_id,
                                                                const uint8_t* data, size_t len,
                                                                int finished);

#ifdef __cplusplus
}
#endif

#endif /* KATHTTP3_KATHTTP3_H */
