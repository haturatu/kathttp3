#include "tls.h"

#include <ngtcp2/ngtcp2_crypto.h>

// Backend selection:
//   - On Android we build against BoringSSL and define KATHTPP_USE_BORINGSSL.
//   - On the host (Linux/macOS) we test against system OpenSSL via the
//     ngtcp2_crypto_ossl backend. Both expose the same ngtcp2_crypto_*
//     client-session helper, which registers the QUIC TLS callbacks.
#ifdef KATHTPP_USE_BORINGSSL
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#else
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#endif

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <fstream>

#include "log.h"

namespace kathttp {

namespace {
constexpr uint8_t H3_ALPN[] = {'\x2', 'h', '3'};
}  // namespace

TlsClientContext::~TlsClientContext() {
  if (ssl_ctx_) SSL_CTX_free(ssl_ctx_);
}

bool TlsClientContext::init(bool verify_cert, const std::string &ca_cert_file,
                            const std::string &keylog_file) {
  ssl_ctx_ = SSL_CTX_new(TLS_client_method());
  if (!ssl_ctx_) {
    KATHTPP_LOG_ERR("SSL_CTX_new: %s\n",
                     ERR_error_string(ERR_get_error(), nullptr));
    return false;
  }

#ifdef KATHTPP_USE_BORINGSSL
  if (ngtcp2_crypto_boringssl_configure_client_context(ssl_ctx_) != 0) {
    KATHTPP_LOG_ERR("ngtcp2_crypto_boringssl_configure_client_context failed\n");
    return false;
  }
#endif

  if (SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_3_VERSION) != 1) {
    KATHTPP_LOG_ERR("SSL_CTX_set_min_proto_version failed\n");
    return false;
  }
  if (SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION) != 1) {
    KATHTPP_LOG_ERR("SSL_CTX_set_max_proto_version failed\n");
    return false;
  }

  // ALPN: advertise "h3".
  if (SSL_CTX_set_alpn_protos(ssl_ctx_, H3_ALPN, sizeof(H3_ALPN)) != 0) {
    KATHTPP_LOG_ERR("SSL_CTX_set_alpn_protos failed\n");
    return false;
  }

  if (!ca_cert_file.empty()) {
    if (SSL_CTX_load_verify_locations(ssl_ctx_, ca_cert_file.c_str(),
                                      nullptr) != 1) {
      KATHTPP_LOG_ERR("SSL_CTX_load_verify_locations failed for %s\n",
                       ca_cert_file.c_str());
      return false;
    }
  } else {
    if (SSL_CTX_set_default_verify_paths(ssl_ctx_) != 1) {
      KATHTPP_LOG_ERR("SSL_CTX_set_default_verify_paths failed\n");
      // Not fatal: certificate verification will simply have no roots.
    }
  }

  if (verify_cert) {
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);
  } else {
    // Intentionally NOT the default. Callers must opt in. Real builds
    // ship with verify_cert == true.
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_NONE, nullptr);
  }

  if (!keylog_file.empty()) {
    static std::string path = keylog_file;
    SSL_CTX_set_keylog_callback(
        ssl_ctx_, [](const SSL * /*ssl*/, const char *line) {
          static std::ofstream f(path, std::ios::out | std::ios::app);
          if (f) {
            f.write(line, static_cast<std::streamsize>(strlen(line)));
            f.put('\n');
          }
        });
  }

  return true;
}

TlsClientSession::~TlsClientSession() {
  if (ssl_) {
    // Detach the conn_ref so the crypto callbacks can't reach a dead
    // ngtcp2_conn during SSL_free.
    SSL_set_app_data(ssl_, nullptr);
    SSL_free(ssl_);
  }
}

bool TlsClientSession::init(TlsClientContext &ctx,
                            const std::string &server_name,
                            bool enable_early_data,
                            ngtcp2_crypto_conn_ref *conn_ref) {
  ssl_ = SSL_new(ctx.native());
  if (!ssl_) {
    KATHTPP_LOG_ERR("SSL_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
    return false;
  }

  // The ngtcp2_crypto client-session helper installs the QUIC TLS
  // callbacks whose conn_ref must resolve to the live ngtcp2_conn.
  SSL_set_app_data(ssl_, conn_ref);
  SSL_set_connect_state(ssl_);
  SSL_set_alpn_protos(ssl_, H3_ALPN, sizeof(H3_ALPN));

  if (!server_name.empty()) {
    SSL_set_tlsext_host_name(ssl_, server_name.c_str());
    if (SSL_set1_host(ssl_, server_name.c_str()) != 1) {
      KATHTPP_LOG_ERR("SSL_set1_host failed\n");
      return false;
    }
  }

  if (enable_early_data) {
#ifdef KATHTPP_USE_BORINGSSL
    SSL_set_early_data_enabled(ssl_, 1);
#endif
  }

#ifdef KATHTPP_USE_BORINGSSL
  // BoringSSL's QUIC method is installed on SSL_CTX above.
#else
  if (ngtcp2_crypto_ossl_configure_client_session(ssl_) != 0) {
    KATHTPP_LOG_ERR("ngtcp2_crypto_ossl_configure_client_session failed\n");
    return false;
  }
#endif

  return true;
}

}  /* namespace kathttp */
