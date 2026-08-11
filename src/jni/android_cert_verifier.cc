#include "android_cert_verifier.h"

#include <limits>
#include <new>
#include <string>

#include "log.h"

namespace kathttp3 {

namespace {

template <typename T>
class LocalRef {
   public:
    LocalRef(JNIEnv* env, T value) : env_(env), value_(value) {}
    ~LocalRef() {
        if (value_) env_->DeleteLocalRef(value_);
    }
    LocalRef(const LocalRef&) = delete;
    LocalRef& operator=(const LocalRef&) = delete;
    LocalRef(LocalRef&& other) noexcept : env_(other.env_), value_(other.value_) {
        other.value_ = nullptr;
    }
    LocalRef& operator=(LocalRef&& other) noexcept {
        if (this != &other) {
            if (value_) env_->DeleteLocalRef(value_);
            env_ = other.env_;
            value_ = other.value_;
            other.value_ = nullptr;
        }
        return *this;
    }
    explicit operator bool() const {
        return value_ != nullptr;
    }
    T get() const {
        return value_;
    }

   private:
    JNIEnv* env_;
    T value_;
};

class ScopedThreadAttachment {
   public:
    ScopedThreadAttachment(JavaVM* vm, bool attached) : vm_(vm), attached_(attached) {}
    ~ScopedThreadAttachment() {
        if (attached_) vm_->DetachCurrentThread();
    }
    ScopedThreadAttachment(const ScopedThreadAttachment&) = delete;
    ScopedThreadAttachment& operator=(const ScopedThreadAttachment&) = delete;

   private:
    JavaVM* vm_;
    bool attached_;
};

bool clear_jni_failure(JNIEnv* env) {
    if (!env->ExceptionCheck()) return false;
    env->ExceptionClear();
    return true;
}

}  // namespace

AndroidCertificateVerifier::AndroidCertificateVerifier(JavaVM* vm, jobject ext)
    : vm_(vm), ext_(ext) {}

AndroidCertificateVerifier::~AndroidCertificateVerifier() {
    if (ext_) {
        JNIEnv* env = nullptr;
        bool attached = false;
        if (vm_->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
#if defined(__ANDROID__)
            attached = vm_->AttachCurrentThread(&env, nullptr) == JNI_OK;
#else
            attached = vm_->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) == JNI_OK;
#endif
            if (!attached) env = nullptr;
        }
        if (env) {
            env->DeleteGlobalRef(ext_);
        }
        if (attached) vm_->DetachCurrentThread();
        ext_ = nullptr;
    }
}

VerifyResult AndroidCertificateVerifier::verify(std::string_view hostname,
                                                const std::vector<DerCertificate>& chain,
                                                std::string_view auth_type) {
    if (!ext_) {
        return {false, KATHTTP3_ERR_NO_TRUST_PROVIDER, "no Android trust manager available"};
    }
    VerifyResult result{false, KATHTTP3_ERR_CERTIFICATE_VERIFY, "certificate verification failed"};
    if (chain.empty() || chain.size() > static_cast<size_t>(std::numeric_limits<jsize>::max())) {
        return result;
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
    ScopedThreadAttachment attachment(vm_, attached);

    LocalRef<jclass> x509_class(env, env->FindClass("java/security/cert/X509Certificate"));
    LocalRef<jclass> factory_class(env, env->FindClass("java/security/cert/CertificateFactory"));
    LocalRef<jclass> stream_class(env, env->FindClass("java/io/ByteArrayInputStream"));
    if (clear_jni_failure(env) || !x509_class || !factory_class || !stream_class) return result;

    const jmethodID get_factory =
        env->GetStaticMethodID(factory_class.get(), "getInstance",
                               "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;");
    const jmethodID stream_constructor = env->GetMethodID(stream_class.get(), "<init>", "([B)V");
    const jmethodID generate_certificate =
        env->GetMethodID(factory_class.get(), "generateCertificate",
                         "(Ljava/io/InputStream;)Ljava/security/cert/Certificate;");
    if (clear_jni_failure(env) || !get_factory || !stream_constructor || !generate_certificate) {
        return result;
    }

    LocalRef<jstring> x509_type(env, env->NewStringUTF("X.509"));
    if (clear_jni_failure(env) || !x509_type) return result;
    LocalRef<jobject> factory(
        env, env->CallStaticObjectMethod(factory_class.get(), get_factory, x509_type.get()));
    if (clear_jni_failure(env) || !factory) return result;

    LocalRef<jobjectArray> certificates(
        env, env->NewObjectArray(static_cast<jsize>(chain.size()), x509_class.get(), nullptr));
    if (clear_jni_failure(env) || !certificates) return result;
    for (size_t i = 0; i < chain.size(); ++i) {
        const auto& der = chain[i].data;
        if (der.empty() || der.size() > static_cast<size_t>(std::numeric_limits<jsize>::max())) {
            return result;
        }
        const auto der_size = static_cast<jsize>(der.size());
        LocalRef<jbyteArray> bytes(env, env->NewByteArray(der_size));
        if (clear_jni_failure(env) || !bytes) return result;
        env->SetByteArrayRegion(bytes.get(), 0, der_size,
                                reinterpret_cast<const jbyte*>(der.data()));
        if (clear_jni_failure(env)) return result;
        LocalRef<jobject> stream(
            env, env->NewObject(stream_class.get(), stream_constructor, bytes.get()));
        if (clear_jni_failure(env) || !stream) return result;
        LocalRef<jobject> certificate(
            env, env->CallObjectMethod(factory.get(), generate_certificate, stream.get()));
        if (clear_jni_failure(env) || !certificate) return result;
        env->SetObjectArrayElement(certificates.get(), static_cast<jsize>(i), certificate.get());
        if (clear_jni_failure(env)) return result;
    }

    LocalRef<jclass> extensions_class(
        env, env->FindClass("android/net/http/X509TrustManagerExtensions"));
    if (clear_jni_failure(env) || !extensions_class) return result;
    const jmethodID check_server_trusted =
        env->GetMethodID(extensions_class.get(), "checkServerTrusted",
                         "([Ljava/security/cert/X509Certificate;Ljava/lang/String;Ljava/lang/"
                         "String;)Ljava/util/List;");
    if (clear_jni_failure(env) || !check_server_trusted) return result;

    const std::string auth_string(auth_type);
    const std::string host_string(hostname);
    LocalRef<jstring> auth(env, env->NewStringUTF(auth_string.c_str()));
    LocalRef<jstring> host(env, env->NewStringUTF(host_string.c_str()));
    if (clear_jni_failure(env) || !auth || !host) return result;
    LocalRef<jobject> verified(
        env, env->CallObjectMethod(ext_, check_server_trusted, certificates.get(), auth.get(),
                                   host.get()));
    if (clear_jni_failure(env) || !verified) return result;
    return {true, 0, ""};
}

CertificateVerifier* create_android_platform_verifier(JavaVM* vm) {
    if (!vm) return nullptr;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        KATHTTP3_LOG_ERR("create_android_platform_verifier: no JNI env\n");
        return nullptr;
    }

    LocalRef<jclass> factory_class(env, env->FindClass("javax/net/ssl/TrustManagerFactory"));
    if (clear_jni_failure(env) || !factory_class) return nullptr;
    const jmethodID get_default_algorithm =
        env->GetStaticMethodID(factory_class.get(), "getDefaultAlgorithm", "()Ljava/lang/String;");
    const jmethodID get_instance =
        env->GetStaticMethodID(factory_class.get(), "getInstance",
                               "(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;");
    const jmethodID initialize =
        env->GetMethodID(factory_class.get(), "init", "(Ljava/security/KeyStore;)V");
    const jmethodID get_trust_managers = env->GetMethodID(factory_class.get(), "getTrustManagers",
                                                          "()[Ljavax/net/ssl/TrustManager;");
    if (clear_jni_failure(env) || !get_default_algorithm || !get_instance || !initialize ||
        !get_trust_managers) {
        return nullptr;
    }

    LocalRef<jstring> algorithm(env, static_cast<jstring>(env->CallStaticObjectMethod(
                                         factory_class.get(), get_default_algorithm)));
    if (clear_jni_failure(env) || !algorithm) return nullptr;
    LocalRef<jobject> factory(
        env, env->CallStaticObjectMethod(factory_class.get(), get_instance, algorithm.get()));
    if (clear_jni_failure(env) || !factory) return nullptr;
    env->CallVoidMethod(factory.get(), initialize, nullptr);
    if (clear_jni_failure(env)) return nullptr;
    LocalRef<jobjectArray> managers(
        env, static_cast<jobjectArray>(env->CallObjectMethod(factory.get(), get_trust_managers)));
    if (clear_jni_failure(env) || !managers) return nullptr;

    LocalRef<jclass> x509_manager_class(env, env->FindClass("javax/net/ssl/X509TrustManager"));
    if (clear_jni_failure(env) || !x509_manager_class) return nullptr;
    LocalRef<jobject> trust_manager(env, nullptr);
    const jsize count = env->GetArrayLength(managers.get());
    if (clear_jni_failure(env)) return nullptr;
    for (jsize i = 0; i < count; ++i) {
        LocalRef<jobject> candidate(env, env->GetObjectArrayElement(managers.get(), i));
        if (clear_jni_failure(env)) return nullptr;
        if (!candidate) continue;
        const bool is_x509 =
            env->IsInstanceOf(candidate.get(), x509_manager_class.get()) == JNI_TRUE;
        if (clear_jni_failure(env)) return nullptr;
        if (is_x509) {
            trust_manager = std::move(candidate);
            break;
        }
    }
    if (!trust_manager) return nullptr;

    LocalRef<jclass> extensions_class(
        env, env->FindClass("android/net/http/X509TrustManagerExtensions"));
    if (clear_jni_failure(env) || !extensions_class) return nullptr;
    const jmethodID extensions_constructor =
        env->GetMethodID(extensions_class.get(), "<init>", "(Ljavax/net/ssl/X509TrustManager;)V");
    if (clear_jni_failure(env) || !extensions_constructor) return nullptr;
    LocalRef<jobject> extensions(
        env, env->NewObject(extensions_class.get(), extensions_constructor, trust_manager.get()));
    if (clear_jni_failure(env) || !extensions) return nullptr;
    jobject global_extensions = env->NewGlobalRef(extensions.get());
    if (clear_jni_failure(env) || !global_extensions) {
        if (global_extensions) env->DeleteGlobalRef(global_extensions);
        return nullptr;
    }

    auto* verifier = new (std::nothrow) AndroidCertificateVerifier(vm, global_extensions);
    if (!verifier) env->DeleteGlobalRef(global_extensions);
    return verifier;
}

}  // namespace kathttp3
