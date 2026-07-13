#ifndef KATHTTP3_CERT_VERIFIER_H
#define KATHTTP3_CERT_VERIFIER_H

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "kathttp3.h"

namespace kathttp3 {

/* A single DER-encoded X.509 certificate. */
struct DerCertificate {
    std::vector<uint8_t> data;
};

/* Outcome of a verification attempt. `code` carries the kathttp3_error
 * to surface on failure so callers can distinguish cert failures from
 * generic TLS / transport errors. */
struct VerifyResult {
    bool ok = false;
    int code = 0;        /* KATHTTP3_ERR_* to surface on failure */
    std::string message; /* human-readable reason on failure */
};

/* Abstract certificate verifier. Platform-specific implementations
 * (Android JNI, OpenSSL store, embedded bundle, insecure) live
 * outside the core so the C++ core stays backend-agnostic. */
class CertificateVerifier {
   public:
    virtual ~CertificateVerifier() = default;

    /* Verify `chain` (leaf certificate first) for `hostname`, using
     * `auth_type` (e.g. "RSA", "EC", "EC_EC", "EC_RSA",
     * "RSASSA-PSS"). Return ok=true on success. */
    virtual VerifyResult verify(std::string_view hostname, const std::vector<DerCertificate>& chain,
                                std::string_view auth_type) = 0;
};

/* Derive the authType string ("RSA"/"EC"/...) from a DER cert. */
std::string auth_type_from_der(const std::vector<uint8_t>& der);

/* Builds a verifier for a resolved trust policy. Returns nullptr for
 * TRUST_PLATFORM (resolved platform-specifically by the caller). */
std::unique_ptr<CertificateVerifier> make_verifier(kathttp3_trust_mode mode, bool insecure,
                                                   const std::string& ca_file);

/* Platform verifier registration. The host (e.g. the Android JNI
 * layer) injects its platform verifier here; the core uses it for
 * TRUST_PLATFORM on Android. May be null (then the embedded bundle
 * is used as a fallback). */
void set_platform_cert_verifier(CertificateVerifier* verifier);
CertificateVerifier* platform_cert_verifier();

}  // namespace kathttp3

#endif /* KATHTTP3_CERT_VERIFIER_H */
