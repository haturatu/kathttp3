#include "android_cert_verifier.h"

#include <string>

#include "log.h"

namespace kathttp3 {

AndroidCertificateVerifier::AndroidCertificateVerifier(JavaVM* vm, jobject ext)
    : vm_(vm), ext_(ext) {}

AndroidCertificateVerifier::~AndroidCertificateVerifier() {
    if (ext_) {
        JNIEnv* env = nullptr;
        if (vm_->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
            env->DeleteGlobalRef(ext_);
        }
        ext_ = nullptr;
    }
}

VerifyResult AndroidCertificateVerifier::verify(std::string_view hostname,
                                                const std::vector<DerCertificate>& chain,
                                                std::string_view auth_type) {
    if (!ext_) {
        return {false, KATHTTP3_ERR_NO_TRUST_PROVIDER, "no Android trust manager available"};
    }
    JNIEnv* env = nullptr;
    bool attached = false;
    if (vm_->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
#if defined(__ANDROID__)
        const jint attach_result = vm_->AttachCurrentThread(&env, nullptr);
#else
        const jint attach_result =
            vm_->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr);
#endif
        if (attach_result != JNI_OK) {
            return {false, KATHTTP3_ERR_NO_TRUST_PROVIDER, "JNI attach failed"};
        }
        attached = true;
    }

    VerifyResult result{false, KATHTTP3_ERR_CERTIFICATE_VERIFY, "certificate verification failed"};

    jclass x509_cls = env->FindClass("java/security/cert/X509Certificate");
    jclass cf_cls = env->FindClass("java/security/cert/CertificateFactory");
    jclass bais_cls = env->FindClass("java/io/ByteArrayInputStream");
    jmethodID cf_get = cf_cls ? env->GetStaticMethodID(
                                    cf_cls, "getInstance",
                                    "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;")
                              : nullptr;
    jmethodID bais_ctor = bais_cls ? env->GetMethodID(bais_cls, "<init>", "([B)V") : nullptr;
    jmethodID gen_cert =
        cf_cls ? env->GetMethodID(cf_cls, "generateCertificate",
                                  "(Ljava/io/InputStream;)Ljava/security/cert/Certificate;")
               : nullptr;
    if (x509_cls && cf_get && bais_ctor && gen_cert) {
        jstring x509_type = env->NewStringUTF("X.509");
        jobject cf = env->CallStaticObjectMethod(cf_cls, cf_get, x509_type);
        env->DeleteLocalRef(x509_type);
        if (cf) {
            jobjectArray arr =
                env->NewObjectArray(static_cast<jsize>(chain.size()), x509_cls, nullptr);
            if (arr) {
                for (size_t i = 0; i < chain.size(); ++i) {
                    const auto& d = chain[i].data;
                    jbyteArray ba = env->NewByteArray(static_cast<jsize>(d.size()));
                    if (ba) {
                        env->SetByteArrayRegion(ba, 0, static_cast<jsize>(d.size()),
                                                reinterpret_cast<const jbyte*>(d.data()));
                        jobject bais = env->NewObject(bais_cls, bais_ctor, ba);
                        jobject cert = bais ? env->CallObjectMethod(cf, gen_cert, bais) : nullptr;
                        if (cert && !env->ExceptionCheck()) {
                            env->SetObjectArrayElement(arr, static_cast<jsize>(i), cert);
                        }
                        if (cert) env->DeleteLocalRef(cert);
                        if (bais) env->DeleteLocalRef(bais);
                        env->DeleteLocalRef(ba);
                    }
                }

                jclass ext_cls = env->FindClass("android/net/http/X509TrustManagerExtensions");
                if (ext_cls) {
                    jmethodID check =
                        env->GetMethodID(ext_cls, "checkServerTrusted",
                                         "([Ljava/security/cert/X509Certificate;Ljava/lang/"
                                         "String;Ljava/lang/String;)Ljava/util/List;");
                    if (check) {
                        jstring auth_str = env->NewStringUTF(auth_type.data());
                        jstring host_str = env->NewStringUTF(hostname.data());
                        jobject verified =
                            env->CallObjectMethod(ext_, check, arr, auth_str, host_str);
                        if (env->ExceptionCheck()) {
                            jthrowable ex = env->ExceptionOccurred();
                            env->ExceptionClear();
                            if (ex) {
                                jclass ex_cls = env->GetObjectClass(ex);
                                jmethodID to_string =
                                    env->GetMethodID(ex_cls, "toString", "()Ljava/lang/String;");
                                jstring msg =
                                    to_string
                                        ? static_cast<jstring>(env->CallObjectMethod(ex, to_string))
                                        : nullptr;
                                if (msg) {
                                    const char* c = env->GetStringUTFChars(msg, nullptr);
                                    result.message =
                                        std::string("certificate verification failed: ") +
                                        (c ? c : "unknown reason");
                                    if (c) env->ReleaseStringUTFChars(msg, c);
                                    env->DeleteLocalRef(msg);
                                }
                                env->DeleteLocalRef(ex);
                            }
                            result.code = KATHTTP3_ERR_CERTIFICATE_VERIFY;
                        } else {
                            if (verified) env->DeleteLocalRef(verified);
                            result = {true, 0, ""};
                        }
                        if (auth_str) env->DeleteLocalRef(auth_str);
                        if (host_str) env->DeleteLocalRef(host_str);
                    }
                    env->DeleteLocalRef(ext_cls);
                }
                env->DeleteLocalRef(arr);
            }
        }
        env->DeleteLocalRef(x509_cls);
    }

    if (attached) vm_->DetachCurrentThread();
    return result;
}

CertificateVerifier* create_android_platform_verifier(JavaVM* vm) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        KATHTTP3_LOG_ERR("create_android_platform_verifier: no JNI env\n");
        return nullptr;
    }

    jclass tmf_cls = env->FindClass("javax/net/ssl/TrustManagerFactory");
    if (!tmf_cls) return nullptr;
    jmethodID get_def =
        env->GetStaticMethodID(tmf_cls, "getDefaultAlgorithm", "()Ljava/lang/String;");
    jmethodID get_inst = env->GetStaticMethodID(
        tmf_cls, "getInstance", "(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;");
    if (!get_def || !get_inst) return nullptr;
    jstring algo = static_cast<jstring>(env->CallStaticObjectMethod(tmf_cls, get_def));
    jobject tmf = env->CallStaticObjectMethod(tmf_cls, get_inst, algo);
    if (!tmf) return nullptr;
    jmethodID init = env->GetMethodID(tmf_cls, "init", "(Ljava/security/KeyStore;)V");
    jmethodID get_tms =
        env->GetMethodID(tmf_cls, "getTrustManagers", "()[Ljavax/net/ssl/TrustManager;");
    if (!init || !get_tms) return nullptr;
    env->CallVoidMethod(tmf, init, nullptr);
    jobjectArray tms = static_cast<jobjectArray>(env->CallObjectMethod(tmf, get_tms));
    if (!tms) return nullptr;

    jclass x509_tm_cls = env->FindClass("javax/net/ssl/X509TrustManager");
    jobject tm = nullptr;
    jsize n = env->GetArrayLength(tms);
    for (jsize i = 0; i < n; ++i) {
        jobject t = env->GetObjectArrayElement(tms, i);
        if (env->IsInstanceOf(t, x509_tm_cls)) {
            tm = t;
            break;
        }
        env->DeleteLocalRef(t);
    }
    if (!tm) return nullptr;

    jclass ext_cls = env->FindClass("android/net/http/X509TrustManagerExtensions");
    jmethodID ext_ctor = env->GetMethodID(ext_cls, "<init>", "(Ljavax/net/ssl/X509TrustManager;)V");
    if (!ext_cls || !ext_ctor) return nullptr;
    jobject ext = env->NewObject(ext_cls, ext_ctor, tm);
    if (!ext) return nullptr;
    jobject global_ext = env->NewGlobalRef(ext);

    return new AndroidCertificateVerifier(vm, global_ext);
}

}  // namespace kathttp3
