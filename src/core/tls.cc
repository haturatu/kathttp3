#include "tls.h"

#include <ngtcp2/ngtcp2_crypto.h>

#include "ca_bundle.h"
#include "cert_verifier.h"

// Backend selection:
//   - On Android we build against BoringSSL and define KATHTTP3_USE_BORINGSSL.
//   - On the host (Linux/macOS) we test against system OpenSSL via the
//     ngtcp2_crypto_ossl backend. Both expose the same ngtcp2_crypto_*
//     client-session helper, which registers the QUIC TLS callbacks.
#ifdef KATHTTP3_USE_BORINGSSL
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#else
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#endif

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <fstream>
#include <memory>
#include <vector>

#include "log.h"

namespace kathttp3 {

namespace {

constexpr uint8_t H3_ALPN[] = {'\x2', 'h', '3'};

int g_ctx_ex_index = -1;     /* SSL_CTX ex_data: active verifier */
int g_session_ex_index = -1; /* SSL ex_data: TlsClientSession* */

void ensure_ex_indices() {
    if (g_ctx_ex_index == -1)
        g_ctx_ex_index = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    if (g_session_ex_index == -1)
        g_session_ex_index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
}

/* Loads the embedded Mozilla CA bundle into the SSL_CTX trust store.
 * Returns true if at least one certificate was added. */
bool load_embedded_ca_bundle(SSL_CTX* ssl_ctx) {
    X509_STORE* store = SSL_CTX_get_cert_store(ssl_ctx);
    if (!store) return false;
    BIO* bio = BIO_new_mem_buf(kCaBundlePem, static_cast<int>(sizeof(kCaBundlePem) - 1));
    if (!bio) return false;
    X509* x;
    bool added = false;
    while ((x = PEM_read_bio_X509_AUX(bio, nullptr, nullptr, nullptr)) != nullptr) {
        if (X509_STORE_add_cert(store, x) == 1) added = true;
        X509_free(x);
    }
    BIO_free(bio);
    return added;
}

#ifdef KATHTTP3_USE_BORINGSSL
/* Peer certificate chain as DER blobs (leaf first). BoringSSL-only; the
 * custom-verify path is only used on Android (BoringSSL). This BoringSSL
 * build returns the chain as STACK_OF(CRYPTO_BUFFER) of DER blobs. */
std::vector<DerCertificate> peer_chain_der(SSL* ssl) {
    std::vector<DerCertificate> out;
    const STACK_OF(CRYPTO_BUFFER)* chain = SSL_get0_peer_certificates(ssl);
    if (!chain) return out;
    for (size_t i = 0; i < static_cast<size_t>(sk_CRYPTO_BUFFER_num(chain)); ++i) {
        const CRYPTO_BUFFER* b = sk_CRYPTO_BUFFER_value(chain, static_cast<int>(i));
        if (!b) continue;
        const uint8_t* d = CRYPTO_BUFFER_data(b);
        size_t n = CRYPTO_BUFFER_len(b);
        if (d && n) out.push_back({std::vector<uint8_t>(d, d + n)});
    }
    return out;
}

std::string servername(SSL* ssl) {
    const char* sn = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    return sn ? std::string(sn) : std::string();
}

enum ssl_verify_result_t cert_verify_cb(SSL* ssl, uint8_t* out_alert) {
    *out_alert = 42 /* bad_certificate */;
    auto* v = static_cast<CertificateVerifier*>(
        SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), g_ctx_ex_index));
    if (!v) return ssl_verify_ok;
    std::vector<DerCertificate> chain = peer_chain_der(ssl);
    if (chain.empty()) return ssl_verify_invalid;
    std::string host = servername(ssl);
    std::string auth = auth_type_from_der(chain[0].data);
    VerifyResult r = v->verify(host, chain, auth);
    auto* s = static_cast<TlsClientSession*>(SSL_get_ex_data(ssl, g_session_ex_index));
    if (s) s->recordVerifierResult(r);
    return r.ok ? ssl_verify_ok : ssl_verify_invalid;
}

void install_custom_verify(SSL_CTX* ctx, CertificateVerifier* v) {
    ensure_ex_indices();
    SSL_CTX_set_ex_data(ctx, g_ctx_ex_index, v);
    SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_PEER, cert_verify_cb);
}
#endif

}  // namespace

/* ----------------------------------------------------------------- *
 * TlsClientContext
 * ----------------------------------------------------------------- */

TlsClientContext::~TlsClientContext() {
    for (auto& entry : resumptions_) SSL_SESSION_free(entry.second.session);
    if (ssl_ctx_) SSL_CTX_free(ssl_ctx_);
}

TlsClientContext::ResumptionState TlsClientContext::acquire_resumption(
    const std::string& server_name) {
    ResumptionState result;
    std::lock_guard<std::mutex> lock(session_mutex_);
    auto it = resumptions_.find(server_name);
    if (it == resumptions_.end() || !it->second.session ||
        SSL_SESSION_up_ref(it->second.session) != 1)
        return result;
    result.session = it->second.session;
    result.transport_params = it->second.transport_params;
#ifdef KATHTTP3_USE_BORINGSSL
    result.early_data_capable = SSL_SESSION_early_data_capable(result.session) == 1;
#endif
    return result;
}

bool TlsClientContext::has_early_resumption(const std::string& server_name) {
    std::lock_guard<std::mutex> lock(session_mutex_);
    auto it = resumptions_.find(server_name);
    if (it == resumptions_.end() || !it->second.session || it->second.transport_params.empty())
        return false;
#ifdef KATHTTP3_USE_BORINGSSL
    return SSL_SESSION_early_data_capable(it->second.session) == 1;
#else
    return false;
#endif
}

void TlsClientContext::cache_resumption(const std::string& server_name, SSL* ssl,
                                        std::vector<uint8_t> transport_params) {
    if (server_name.empty()) return;
    SSL_SESSION* session = SSL_get1_session(ssl);
    if (!session) return;
    std::lock_guard<std::mutex> lock(session_mutex_);
    auto& slot = resumptions_[server_name];
    SSL_SESSION_free(slot.session);
    slot.session = session;
    slot.transport_params = std::move(transport_params);
}

bool TlsClientContext::init(kathttp3_trust_mode trust_mode, bool insecure,
                            const std::string& ca_cert_file, const std::string& keylog_file,
                            CertificateVerifier* platform_verifier) {
    ssl_ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx_) {
        KATHTTP3_LOG_ERR("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }

#ifdef KATHTTP3_USE_BORINGSSL
    if (ngtcp2_crypto_boringssl_configure_client_context(ssl_ctx_) != 0) {
        KATHTTP3_LOG_ERR("ngtcp2_crypto_boringssl_configure_client_context failed\n");
        return false;
    }
#endif

    if (SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION) != 1) {
        KATHTTP3_LOG_ERR("SSL_CTX_set_min_proto_version failed\n");
        return false;
    }
    if (SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION) != 1) {
        KATHTTP3_LOG_ERR("SSL_CTX_set_max_proto_version failed\n");
        return false;
    }

    // ALPN: advertise "h3".
    if (SSL_CTX_set_alpn_protos(ssl_ctx_, H3_ALPN, sizeof(H3_ALPN)) != 0) {
        KATHTTP3_LOG_ERR("SSL_CTX_set_alpn_protos failed\n");
        return false;
    }

    // Resolve the certificate verifier according to the trust policy.
#ifdef KATHTTP3_USE_BORINGSSL
    // On Android there is no usable system PEM path, so verification always
    // goes through a verifier (the BoringSSL custom-verify callback).
    if (trust_mode == KATHTTP3_TRUST_PLATFORM) {
        CertificateVerifier* v = platform_verifier ? platform_verifier : platform_cert_verifier();
        if (v) {
            verifier_ = v;  // injected by the host; not owned here
        } else {
            owned_verifier_ = make_verifier(KATHTTP3_TRUST_EMBEDDED_MOZILLA, false, "");
            verifier_ = owned_verifier_.get();
        }
    } else {
        owned_verifier_ = make_verifier(trust_mode, insecure, ca_cert_file);
        if (!owned_verifier_) {
            KATHTTP3_LOG_ERR("failed to build certificate verifier\n");
            return false;
        }
        verifier_ = owned_verifier_.get();
    }
    install_custom_verify(ssl_ctx_, verifier_);
#else
    // Host / non-Android: rely on the standard verifier with the chosen
    // roots loaded into the SSL_CTX trust store (no custom callback).
    if (insecure) {
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
    } else if (trust_mode == KATHTTP3_TRUST_CUSTOM_CA) {
        if (ca_cert_file.empty()) {
            KATHTTP3_LOG_ERR("TRUST_CUSTOM_CA requires ca_cert_file\n");
            return false;
        }
        if (SSL_CTX_load_verify_locations(ssl_ctx_, ca_cert_file.c_str(), nullptr) != 1) {
            KATHTTP3_LOG_ERR("SSL_CTX_load_verify_locations failed for %s\n", ca_cert_file.c_str());
            return false;
        }
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);
    } else if (trust_mode == KATHTTP3_TRUST_EMBEDDED_MOZILLA) {
        if (!load_embedded_ca_bundle(ssl_ctx_)) {
            KATHTTP3_LOG_ERR("load_embedded_ca_bundle failed\n");
        }
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);
    } else {  // TRUST_PLATFORM
        if (!ca_cert_file.empty()) {
            if (SSL_CTX_load_verify_locations(ssl_ctx_, ca_cert_file.c_str(), nullptr) != 1)
                KATHTTP3_LOG_ERR("SSL_CTX_load_verify_locations failed for %s\n",
                                 ca_cert_file.c_str());
        } else if (SSL_CTX_set_default_verify_paths(ssl_ctx_) != 1) {
            KATHTTP3_LOG_ERR(
                "SSL_CTX_set_default_verify_paths failed; using embedded "
                "bundle\n");
            load_embedded_ca_bundle(ssl_ctx_);
        }
        SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);
    }
#endif

    if (!keylog_file.empty()) {
        static std::string path = keylog_file;
        SSL_CTX_set_keylog_callback(ssl_ctx_, [](const SSL* /*ssl*/, const char* line) {
            std::ofstream f(path, std::ios::app);
            if (f) f << line << std::endl;
        });
    }

    return true;
}

/* ----------------------------------------------------------------- *
 * TlsClientSession
 * ----------------------------------------------------------------- */

TlsClientSession::~TlsClientSession() {
    if (ssl_) {
        if (context_) context_->cache_resumption(server_name_, ssl_, std::move(transport_params_));
        // Detach the conn_ref so the crypto callbacks can't reach a dead
        // ngtcp2_conn during SSL_free.
        SSL_set_app_data(ssl_, nullptr);
        SSL_free(ssl_);
    }
}

TlsClientSession::TlsClientSession(TlsClientSession&& other) noexcept
    : ssl_(other.ssl_),
      last_failure_(std::move(other.last_failure_)),
      context_(other.context_),
      server_name_(std::move(other.server_name_)),
      transport_params_(std::move(other.transport_params_)) {
    other.ssl_ = nullptr;
    other.context_ = nullptr;
    if (ssl_) {
        ensure_ex_indices();
        SSL_set_ex_data(ssl_, g_session_ex_index, this);
    }
}

TlsClientSession& TlsClientSession::operator=(TlsClientSession&& other) noexcept {
    if (this == &other) return *this;
    if (ssl_) {
        if (context_) context_->cache_resumption(server_name_, ssl_, std::move(transport_params_));
        SSL_set_app_data(ssl_, nullptr);
        SSL_free(ssl_);
    }
    ssl_ = other.ssl_;
    last_failure_ = std::move(other.last_failure_);
    context_ = other.context_;
    server_name_ = std::move(other.server_name_);
    transport_params_ = std::move(other.transport_params_);
    other.ssl_ = nullptr;
    other.context_ = nullptr;
    if (ssl_) {
        ensure_ex_indices();
        SSL_set_ex_data(ssl_, g_session_ex_index, this);
    }
    return *this;
}

bool TlsClientSession::init(TlsClientContext& ctx, const std::string& server_name,
                            SSL_SESSION* resume_session, bool* enable_early_data,
                            ngtcp2_crypto_conn_ref* conn_ref) {
    ssl_ = SSL_new(ctx.native());
    if (!ssl_) {
        SSL_SESSION_free(resume_session);
        KATHTTP3_LOG_ERR("SSL_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        return false;
    }

    // The ngtcp2_crypto client-session helper installs the QUIC TLS
    // callbacks whose conn_ref must resolve to the live ngtcp2_conn.
    SSL_set_app_data(ssl_, conn_ref);
    SSL_set_connect_state(ssl_);
    SSL_set_alpn_protos(ssl_, H3_ALPN, sizeof(H3_ALPN));
    context_ = &ctx;
    server_name_ = server_name;

    if (resume_session) {
        if (SSL_set_session(ssl_, resume_session) != 1) {
            KATHTTP3_LOG_WARN("SSL_set_session failed; using full handshake\n");
            if (enable_early_data) *enable_early_data = false;
        }
        SSL_SESSION_free(resume_session);
    } else if (enable_early_data) {
        *enable_early_data = false;
    }

    if (!server_name.empty()) {
        SSL_set_tlsext_host_name(ssl_, server_name.c_str());
        if (SSL_set1_host(ssl_, server_name.c_str()) != 1) {
            KATHTTP3_LOG_ERR("SSL_set1_host failed\n");
            return false;
        }
    }

    if (enable_early_data && *enable_early_data) {
#ifdef KATHTTP3_USE_BORINGSSL
        SSL_set_early_data_enabled(ssl_, 1);
#endif
    }

#ifdef KATHTTP3_USE_BORINGSSL
    // BoringSSL's QUIC method is installed on SSL_CTX above.
#else
    if (ngtcp2_crypto_ossl_configure_client_session(ssl_) != 0) {
        KATHTTP3_LOG_ERR("ngtcp2_crypto_ossl_configure_client_session failed\n");
        return false;
    }
#endif

    ensure_ex_indices();
    SSL_set_ex_data(ssl_, g_session_ex_index, this);
    return true;
}

void TlsClientSession::recordVerifierResult(const VerifyResult& r) {
    last_failure_ =
        TlsFailure{0, 0, 0, r.ok ? 0 : (r.code ? r.code : KATHTTP3_ERR_CERTIFICATE_VERIFY),
                   r.ok ? std::string() : r.message};
}

void TlsClientSession::captureLastError(SSL* ssl, int return_code) {
    int ssl_err = SSL_get_error(ssl, return_code);
    uint64_t e = ERR_peek_last_error();
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    std::string msg = buf;
    int code = KATHTTP3_ERR_TLS;
    if (msg.find("CERTIFICATE_VERIFY") != std::string::npos)
        code = KATHTTP3_ERR_CERTIFICATE_VERIFY;
    else if (msg.find("HOST") != std::string::npos)
        code = KATHTTP3_ERR_HOSTNAME_MISMATCH;
    last_failure_ = TlsFailure{ssl_err, e, 0, code, msg};
}

} /* namespace kathttp3 */
