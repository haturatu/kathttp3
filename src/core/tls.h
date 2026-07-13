#ifndef KATHTTP3_TLS_H
#define KATHTTP3_TLS_H

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cstdint>
#include <string>

#include "cert_verifier.h"
#include "kathttp3.h"

namespace kathttp3 {

/* Snapshot of a TLS failure, captured at the moment it happens
 * (not read lazily from the thread-local error queue later). */
struct TlsFailure {
    int ssl_error = 0;            /* SSL_get_error() on the failing call */
    uint64_t boringssl_error = 0; /* ERR_peek_last_error() */
    int tls_alert = 0;            /* alert sent/received, if any */
    int code = 0;                 /* KATHTTP3_ERR_* to surface */
    std::string message;          /* human-readable reason */
};

/* BoringSSL TLS 1.3 context for QUIC clients. Wraps an SSL_CTX configured
 * with ngtcp2_crypto_boringssl helpers and the chosen certificate
 * verifier. */
class TlsClientContext {
   public:
    TlsClientContext() = default;
    ~TlsClientContext();

    TlsClientContext(const TlsClientContext&) = delete;
    TlsClientContext& operator=(const TlsClientContext&) = delete;

    /* Configures the context according to the trust policy.
     * `platform_verifier` is the host-injected verifier used for
     * TRUST_PLATFORM on Android (may be null -> embedded fallback). */
    bool init(kathttp3_trust_mode trust_mode, bool insecure, const std::string& ca_cert_file,
              const std::string& keylog_file, CertificateVerifier* platform_verifier = nullptr);

    SSL_CTX* native() const {
        return ssl_ctx_;
    }
    CertificateVerifier* verifier() const {
        return verifier_;
    }

   private:
    SSL_CTX* ssl_ctx_ = nullptr;
    std::unique_ptr<CertificateVerifier> owned_verifier_;
    CertificateVerifier* verifier_ = nullptr; /* active verifier (may be
                                               * injected, not owned) */
};

/* A single QUIC connection's TLS session (one SSL object). */
class TlsClientSession {
   public:
    TlsClientSession() = default;
    ~TlsClientSession();

    TlsClientSession(const TlsClientSession&) = delete;
    TlsClientSession& operator=(const TlsClientSession&) = delete;
    TlsClientSession(TlsClientSession&& other) noexcept;
    TlsClientSession& operator=(TlsClientSession&& other) noexcept;

    /* `conn_ref` must outlive the session; it is used by the ngtcp2_crypto
     * callbacks to recover the ngtcp2_conn. */
    bool init(TlsClientContext& ctx, const std::string& server_name, bool enable_early_data,
              ngtcp2_crypto_conn_ref* conn_ref);

    SSL* native() const {
        return ssl_;
    }

    /* Human-readable BoringSSL/OpenSSL error queue (clears it). */
    const std::string& lastTlsError() const {
        return last_failure_.message;
    }

    /* The captured failure (valid after a verification / handshake error). */
    const TlsFailure& lastFailure() const {
        return last_failure_;
    }

    /* Records the result of a verifier callback. */
    void recordVerifierResult(const VerifyResult& r);

    /* Captures the current error queue for `ssl` into last_failure_,
     * choosing a KATHTTP3_ERR_* code from the message. */
    void captureLastError(SSL* ssl, int return_code);

    /* Clears any previously captured failure (call before a new attempt). */
    void resetFailure() {
        last_failure_ = TlsFailure{};
    }

   private:
    SSL* ssl_ = nullptr;
    TlsFailure last_failure_{};
};

} /* namespace kathttp3 */

#endif /* KATHTTP3_TLS_H */
