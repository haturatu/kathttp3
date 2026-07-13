#include "cert_verifier.h"

#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <memory>

#include "ca_bundle.h"
#include "kathttp3.h"

namespace kathttp3 {

namespace {

X509* der_to_x509(const DerCertificate& d) {
    if (d.data.empty()) return nullptr;
    const uint8_t* p = d.data.data();
    int n = static_cast<int>(d.data.size());
    return d2i_X509(nullptr, &p, n);
}

/* Builds an X509_STORE from a PEM buffer (one or more CERTIFICATE
 * blocks). Returns nullptr on failure. */
X509_STORE* store_from_pem(const char* pem, size_t len) {
    BIO* bio = BIO_new_mem_buf(pem, static_cast<int>(len));
    if (!bio) return nullptr;
    X509_STORE* store = X509_STORE_new();
    if (!store) {
        BIO_free(bio);
        return nullptr;
    }
    X509* x;
    while ((x = PEM_read_bio_X509_AUX(bio, nullptr, nullptr, nullptr)) != nullptr) {
        if (X509_STORE_add_cert(store, x) != 1) {
            X509_free(x);
            break;
        }
        X509_free(x);
    }
    BIO_free(bio);
    return store;
}

X509_STORE* store_from_file(const char* path) {
    BIO* bio = BIO_new_file(path, "rb");
    if (!bio) return nullptr;
    X509_STORE* store = X509_STORE_new();
    if (!store) {
        BIO_free(bio);
        return nullptr;
    }
    X509* x;
    while ((x = PEM_read_bio_X509_AUX(bio, nullptr, nullptr, nullptr)) != nullptr) {
        if (X509_STORE_add_cert(store, x) != 1) {
            X509_free(x);
            break;
        }
        X509_free(x);
    }
    BIO_free(bio);
    return store;
}

/* Verifies `chain` (leaf first) against `store` and checks the
 * hostname. Returns a detailed result. */
VerifyResult verify_with_store(const std::vector<DerCertificate>& chain, X509_STORE* store,
                               std::string_view hostname) {
    if (!store) {
        return {false, KATHTTP3_ERR_NO_TRUST_PROVIDER, "no trust store available"};
    }
    if (chain.empty()) {
        return {false, KATHTTP3_ERR_CERTIFICATE_VERIFY, "empty peer certificate chain"};
    }

    std::vector<X509*> certs;
    certs.reserve(chain.size());
    for (const auto& d : chain) {
        X509* x = der_to_x509(d);
        if (x) certs.push_back(x);
    }
    if (certs.empty()) {
        return {false, KATHTTP3_ERR_CERTIFICATE_VERIFY, "failed to parse peer certificate chain"};
    }

    STACK_OF(X509)* untrusted = sk_X509_new_null();
    for (X509* x : certs) sk_X509_push(untrusted, x);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    VerifyResult result{false, KATHTTP3_ERR_CERTIFICATE_VERIFY, "certificate verification failed"};
    if (ctx && X509_STORE_CTX_init(ctx, store, certs[0], untrusted) == 1) {
        X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);
        if (!hostname.empty()) {
            X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            X509_VERIFY_PARAM_set1_host(param, hostname.data(),
                                        static_cast<size_t>(hostname.size()));
        }
        if (X509_verify_cert(ctx) == 1) {
            result = {true, 0, ""};
        } else {
            int e = X509_STORE_CTX_get_error(ctx);
            if (e == X509_V_ERR_HOSTNAME_MISMATCH) {
                result = {false, KATHTTP3_ERR_HOSTNAME_MISMATCH, "certificate hostname mismatch"};
            } else {
                const char* reason = X509_verify_cert_error_string(static_cast<long>(e));
                result = {false, KATHTTP3_ERR_CERTIFICATE_VERIFY,
                          std::string("certificate verification failed: ") +
                              (reason ? reason : "unknown reason")};
            }
        }
    }
    if (ctx) X509_STORE_CTX_free(ctx);
    if (untrusted) sk_X509_free(untrusted);
    for (X509* x : certs) X509_free(x);
    return result;
}

/* Shared base: verification against a preloaded X509_STORE. */
class StoreCertificateVerifier : public CertificateVerifier {
   public:
    explicit StoreCertificateVerifier(X509_STORE* store) : store_(store) {}
    ~StoreCertificateVerifier() override {
        if (store_) X509_STORE_free(store_);
    }
    VerifyResult verify(std::string_view hostname, const std::vector<DerCertificate>& chain,
                        std::string_view) override {
        (void)hostname;
        return verify_with_store(chain, store_, hostname);
    }

   private:
    X509_STORE* store_;
};

}  // namespace

std::string auth_type_from_der(const std::vector<uint8_t>& der) {
    if (der.empty()) return "UNKNOWN";
    const uint8_t* p = der.data();
    int n = static_cast<int>(der.size());
    X509* leaf = d2i_X509(nullptr, &p, n);
    if (!leaf) return "UNKNOWN";
    std::string result = "UNKNOWN";
    EVP_PKEY* pkey = X509_get0_pubkey(leaf);
    if (pkey) {
        switch (EVP_PKEY_id(pkey)) {
            case EVP_PKEY_RSA:
                result = "RSA";
                break;
            case EVP_PKEY_EC:
                result = "EC";
                break;
            default:
                break;
        }
    }
    X509_free(leaf);
    return result;
}

/* ----------------------------------------------------------------- *
 * Public implementations
 * ----------------------------------------------------------------- */

class OpenSslCertificateVerifier : public StoreCertificateVerifier {
   public:
    explicit OpenSslCertificateVerifier(const std::string& ca_file)
        : StoreCertificateVerifier(store_from_file(ca_file.c_str())) {}
};

class EmbeddedBundleCertificateVerifier : public StoreCertificateVerifier {
   public:
    EmbeddedBundleCertificateVerifier()
        : StoreCertificateVerifier(store_from_pem(kCaBundlePem, sizeof(kCaBundlePem) - 1)) {}
};

class InsecureCertificateVerifier : public CertificateVerifier {
   public:
    VerifyResult verify(std::string_view, const std::vector<DerCertificate>&,
                        std::string_view) override {
        return {true, 0, ""};
    }
};

namespace {
CertificateVerifier* g_platform_verifier = nullptr;
}  // namespace

void set_platform_cert_verifier(CertificateVerifier* verifier) {
    g_platform_verifier = verifier;
}

CertificateVerifier* platform_cert_verifier() {
    return g_platform_verifier;
}

/* Factory used by the TLS layer once the trust policy is known. */
std::unique_ptr<CertificateVerifier> make_verifier(kathttp3_trust_mode mode, bool insecure,
                                                   const std::string& ca_file) {
    if (insecure) return std::make_unique<InsecureCertificateVerifier>();
    switch (mode) {
        case KATHTTP3_TRUST_EMBEDDED_MOZILLA:
            return std::make_unique<EmbeddedBundleCertificateVerifier>();
        case KATHTTP3_TRUST_CUSTOM_CA:
            if (ca_file.empty()) return nullptr;
            return std::make_unique<OpenSslCertificateVerifier>(ca_file);
        case KATHTTP3_TRUST_PLATFORM:
        default:
            return nullptr; /* resolved by the caller (platform-specific) */
    }
}

}  // namespace kathttp3
