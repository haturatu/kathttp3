#ifndef KATHTTP_KATHTTP_H
#define KATHTTP_KATHTTP_H

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
#define KATHTTP_ABI_VERSION 1

#if defined(_WIN32)
#define KATHTTP_API __declspec(dllexport)
#else
#define KATHTTP_API __attribute__((visibility("default")))
#endif

typedef enum {
    KATHTTP_OK = 0,
    KATHTTP_ERR_DNS = -1,
    /* -2 reserved */
    KATHTTP_ERR_QUIC = -3,               /* QUIC transport error */
    KATHTTP_ERR_TLS = -4,                /* TLS handshake failure (non-cert) */
    KATHTTP_ERR_CERTIFICATE_VERIFY = -5, /* certificate trust failure */
    KATHTTP_ERR_HOSTNAME_MISMATCH = -6,  /* peer cert does not match hostname */
    KATHTTP_ERR_NO_TRUST_PROVIDER = -7,  /* no verifier available / JNI verifier failed */
    KATHTTP_ERR_HTTP3 = -8,
    KATHTTP_ERR_TIMEOUT = -9,
    KATHTTP_ERR_CANCELLED = -10,
    KATHTTP_ERR_INVALID_ARG = -11,
    KATHTTP_ERR_NOMEM = -12,
    KATHTTP_ERR_CLOSED = -13, /* client destroyed while request in flight */
    KATHTTP_ERR_BODY = -14,   /* response body length mismatch / truncation */
    KATHTTP_ERR_DNS_TIMEOUT = -15,
    KATHTTP_ERR_CONNECT_TIMEOUT = -16,
    KATHTTP_ERR_HANDSHAKE_TIMEOUT = -17,
    KATHTTP_ERR_RESPONSE_HEADERS_TIMEOUT = -18,
    KATHTTP_ERR_READ_TIMEOUT = -19,
    KATHTTP_ERR_WRITE_TIMEOUT = -20,
    KATHTTP_ERR_CALL_TIMEOUT = -21,
} kathttp_error;

/* How the peer certificate is verified. Default is PLATFORM. */
typedef enum {
    KATHTTP_TRUST_PLATFORM = 0,         /* Android: X509TrustManager;
                                         * else: system trust store */
    KATHTTP_TRUST_EMBEDDED_MOZILLA = 1, /* bundled Mozilla CA bundle */
    KATHTTP_TRUST_CUSTOM_CA = 2,        /* PEM bundle at ca_cert_file */
} kathttp_trust_mode;

/* A single resolved candidate address, as returned by a custom resolver. */
typedef struct kathttp_resolved_address {
    char ip[64]; /* textual IPv4 or IPv6 */
    uint16_t port;
    int family; /* AF_INET / AF_INET6 */
} kathttp_resolved_address;

/* Custom name-resolution hook. `out` must be filled with up to *out_count
 * entries and *out_count updated to the count written (0 on failure).
 * Returns 0 on success. */
typedef int (*kathttp_resolve_cb)(const char* host, uint16_t port, void* userdata,
                                  kathttp_resolved_address* out, size_t* out_count);

/* Client construction options. Always initialize with
 * kathttp_client_options_init() so struct_size/abi_version are set. */
typedef struct kathttp_client_options {
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
                                    KATHTTP_TRUST_CUSTOM_CA. NULL otherwise. */
    uint8_t verify_cert;      /* deprecated: kept for ABI; 1 = verify peer
                               * (default). 0 is superseded by insecure_cert. */
    uint8_t insecure_cert;    /* 1 = disable verification (tests only). Takes
                               * precedence over trust_mode. */
    uint32_t trust_mode;      /* kathttp_trust_mode; default PLATFORM */
    const char* keylog_file;  /* NULL = disabled */
    uint32_t quic_version;    /* 0 = let ngtcp2 negotiate */

    /* Custom DNS resolver hook. When non-null it overrides the built-in
     * getaddrinfo resolution (this is how a DNS-over-HTTPS / custom resolver is
     * plugged in). The callback fills `out` with up to *out_count candidate
     * addresses and sets *out_count to the number written; return 0 on success. */
    kathttp_resolve_cb resolve_cb;
    void* resolve_cb_userdata; /* opaque, passed to resolve_cb */

    /* Phase-specific monotonic-duration timeouts.  A zero value inherits the
     * corresponding legacy timeout (connect/request/idle). */
    uint64_t dns_timeout_ms;
    uint64_t handshake_timeout_ms;
    uint64_t response_headers_timeout_ms;
    uint64_t read_timeout_ms;
    uint64_t write_timeout_ms;
    uint64_t call_timeout_ms;
} kathttp_client_options;

KATHTTP_API uint32_t kathttp_api_version(void);
KATHTTP_API void kathttp_client_options_init(kathttp_client_options* opt);

typedef struct kathttp_client kathttp_client;
typedef struct kathttp_request kathttp_request;

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
typedef enum kathttp_event_type {
    KATHTTP_EVENT_HEADERS = 1,  /* status_code + names/values/header_count */
    KATHTTP_EVENT_BODY = 2,     /* data + data_len (may be called 0..n times) */
    KATHTTP_EVENT_COMPLETE = 3, /* success; error_code == 0 */
    KATHTTP_EVENT_ERROR = 4,    /* failure; error_code != 0 */
} kathttp_event_type;

typedef struct kathttp_event {
    kathttp_event_type type;
    int64_t request_id;

    int status_code;           /* HEADERS */
    const char* const* names;  /* HEADERS (header_count entries) */
    const char* const* values; /* HEADERS (header_count entries) */
    size_t header_count;       /* HEADERS */

    const uint8_t* data; /* BODY */
    size_t data_len;     /* BODY */

    int error_code; /* COMPLETE (0) / ERROR (non-zero) */
} kathttp_event;

typedef void (*kathttp_event_callback)(void* user_data, const kathttp_event* event);

/* ------------------------------------------------------------------ *
 * Client lifecycle
 * ------------------------------------------------------------------ */
KATHTTP_API kathttp_client* kathttp_client_create(const kathttp_client_options* options);
KATHTTP_API void kathttp_client_close(kathttp_client* client);
KATHTTP_API void kathttp_client_destroy(kathttp_client* client);

/* A tag combined into the connection-pool key. Use it to separate
 * connections that share a (host, port) but differ in transport policy
 * (e.g. a distinct Android Network, TLS policy or proxy). Two clients
 * with different policy tags never share a QUIC connection. */
KATHTTP_API void kathttp_client_set_origin_policy(kathttp_client* client, const char* policy_tag);

/* ------------------------------------------------------------------ *
 * Request
 *
 * Ownership: kathttp_client_execute() takes ownership of `request`.
 * Do not read, modify or free it after that call.
 * ------------------------------------------------------------------ */
KATHTTP_API kathttp_request* kathttp_request_create(const char* method, const char* url);
KATHTTP_API void kathttp_request_destroy(kathttp_request* request);
KATHTTP_API int kathttp_request_add_header(kathttp_request* request, const char* name,
                                           const char* value);
KATHTTP_API int kathttp_request_set_body(kathttp_request* request, const uint8_t* data, size_t len);
KATHTTP_API void kathttp_request_set_follow_redirects(kathttp_request* request, int enable);
KATHTTP_API void kathttp_request_set_streaming(kathttp_request* request, int enable);

/* Pre-resolved address (IPv4/IPv6 string). When one or more addresses
 * are supplied the engine skips its own DNS resolution and races them
 * (happy-eyeballs). This is how an Android caller can feed IPs obtained
 * via the platform DnsResolver bound to a specific Network. */
KATHTTP_API int kathttp_request_add_address(kathttp_request* request, const char* ip,
                                            uint16_t port);

/* Submit a request. `request_id` is an opaque token echoed back in
 * every event; the caller uses it to correlate events with its own
 * per-request state (e.g. a Kotlin coroutine registry entry). */
KATHTTP_API void kathttp_client_execute(kathttp_client* client, kathttp_request* request,
                                        int64_t request_id, kathttp_event_callback cb,
                                        void* user_data);

/* Request cancellation. Safe to call from any thread. If the request
 * has already completed, this is a no-op. If still in flight, the
 * engine will stop delivering further events for `request_id`. */
KATHTTP_API void kathttp_client_cancel(kathttp_client* client, int64_t request_id);

/* Streaming flow-control: acknowledge that `bytes` of a streamed response
 * body have been consumed by the application. Extends the HTTP/3 receive
 * window so the peer can send more. Safe to call from any thread. */
KATHTTP_API void kathttp_client_consume(kathttp_client* client, int64_t request_id, size_t bytes);

#ifdef __cplusplus
}
#endif

#endif /* KATHTTP_KATHTTP_H */
