#ifndef KATHTTP3_ANDROID_CERT_VERIFIER_H
#define KATHTTP3_ANDROID_CERT_VERIFIER_H

#include <jni.h>

#include "cert_verifier.h"

namespace kathttp3 {

/* Android verifier: delegates to the platform X509TrustManager via JNI.
 * `ext` must be a global JNI reference to an
 * android.net.ssl.X509TrustManagerExtensions instance. */
class AndroidCertificateVerifier : public CertificateVerifier {
   public:
    AndroidCertificateVerifier(JavaVM* vm, jobject ext);
    ~AndroidCertificateVerifier() override;

    AndroidCertificateVerifier(const AndroidCertificateVerifier&) = delete;
    AndroidCertificateVerifier& operator=(const AndroidCertificateVerifier&) = delete;

    VerifyResult verify(std::string_view hostname, const std::vector<DerCertificate>& chain,
                        std::string_view auth_type) override;

   private:
    JavaVM* vm_ = nullptr;
    jobject ext_ = nullptr; /* global ref */
};

/* Builds the default-platform AndroidCertificateVerifier, or nullptr on
 * failure. The returned object is owned by the caller and must outlive
 * the engine (typically process-lifetime). */
CertificateVerifier* create_android_platform_verifier(JavaVM* vm);

}  // namespace kathttp3

#endif /* KATHTTP3_ANDROID_CERT_VERIFIER_H */
