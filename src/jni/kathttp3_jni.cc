#include <jni.h>
#include <sys/socket.h>

#include <atomic>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "android_cert_verifier.h"
#ifdef __ANDROID__
#include "android_qlog_sink.h"
#endif
#include "cert_verifier.h"
#include "kathttp3.h"
#include "log.h"

namespace {
JavaVM* g_vm = nullptr;
std::mutex g_handles_mutex;
std::unordered_set<kathttp3_client*> g_handles;
std::unordered_map<kathttp3_client*, void*> g_resolvers;
#ifdef __ANDROID__
std::unordered_map<kathttp3_client*, std::unique_ptr<kathttp3::AndroidQlogLogcatSink>>
    g_qlog_logcat_sinks;
#endif

struct JniCache {
    jclass string_class = nullptr;
    jclass list_class = nullptr;
    jclass address_class = nullptr;
    jclass resolver_class = nullptr;
    jclass callback_class = nullptr;
    jmethodID list_size = nullptr;
    jmethodID list_get = nullptr;
    jmethodID address_ip = nullptr;
    jmethodID address_port = nullptr;
    jmethodID resolver_resolve = nullptr;
    jmethodID callback_headers = nullptr;
    jmethodID callback_body = nullptr;
    jmethodID callback_complete = nullptr;
    jmethodID callback_error = nullptr;
};
JniCache g_jni;

void release_jni_cache(JNIEnv* env);

bool cache_class(JNIEnv* env, const char* name, jclass* destination) {
    jclass local = env->FindClass(name);
    if (!local) return false;
    *destination = reinterpret_cast<jclass>(env->NewGlobalRef(local));
    env->DeleteLocalRef(local);
    return *destination != nullptr;
}

bool initialize_jni_cache(JNIEnv* env) {
    if (!cache_class(env, "java/lang/String", &g_jni.string_class) ||
        !cache_class(env, "java/util/List", &g_jni.list_class) ||
        !cache_class(env, "dev/kathttp3/ResolvedAddress", &g_jni.address_class) ||
        !cache_class(env, "dev/kathttp3/DnsResolver", &g_jni.resolver_class) ||
        !cache_class(env, "dev/kathttp3/internal/NativeCallback", &g_jni.callback_class)) {
        release_jni_cache(env);
        return false;
    }
    g_jni.list_size = env->GetMethodID(g_jni.list_class, "size", "()I");
    g_jni.list_get = env->GetMethodID(g_jni.list_class, "get", "(I)Ljava/lang/Object;");
    g_jni.address_ip = env->GetMethodID(g_jni.address_class, "getIp", "()Ljava/lang/String;");
    g_jni.address_port = env->GetMethodID(g_jni.address_class, "getPort", "()I");
    g_jni.resolver_resolve =
        env->GetMethodID(g_jni.resolver_class, "resolve", "(Ljava/lang/String;I)Ljava/util/List;");
    g_jni.callback_headers = env->GetMethodID(g_jni.callback_class, "onHeaders",
                                              "(I[Ljava/lang/String;[Ljava/lang/String;)V");
    g_jni.callback_body = env->GetMethodID(g_jni.callback_class, "onBody", "([B)V");
    g_jni.callback_complete = env->GetMethodID(g_jni.callback_class, "onComplete", "()V");
    g_jni.callback_error = env->GetMethodID(g_jni.callback_class, "onError", "(I)V");
    const bool ready = !env->ExceptionCheck() && g_jni.list_size && g_jni.list_get &&
                       g_jni.address_ip && g_jni.address_port && g_jni.resolver_resolve &&
                       g_jni.callback_headers && g_jni.callback_body && g_jni.callback_complete &&
                       g_jni.callback_error;
    if (!ready) release_jni_cache(env);
    return ready;
}

void release_jni_cache(JNIEnv* env) {
    jclass* classes[] = {&g_jni.string_class, &g_jni.list_class, &g_jni.address_class,
                         &g_jni.resolver_class, &g_jni.callback_class};
    for (jclass* cls : classes) {
        if (*cls) env->DeleteGlobalRef(*cls);
        *cls = nullptr;
    }
    g_jni = JniCache{};
}

/* Per-client state for a Kotlin DnsResolver injected through the options. */
struct ResolverCtx {
    jobject resolver = nullptr; /* global ref */
};

class ThreadEnv {
   public:
    JNIEnv* get() {
        if (env_) return env_;
        if (!g_vm) return nullptr;
        if (g_vm->GetEnv(reinterpret_cast<void**>(&env_), JNI_VERSION_1_6) != JNI_OK) {
#ifdef __ANDROID__
            if (g_vm->AttachCurrentThreadAsDaemon(&env_, nullptr) == JNI_OK)
                attached_ = true;
            else
                env_ = nullptr;
#else
            if (g_vm->AttachCurrentThreadAsDaemon(reinterpret_cast<void**>(&env_), nullptr) ==
                JNI_OK)
                attached_ = true;
            else
                env_ = nullptr;
#endif
        }
        return env_;
    }
    ~ThreadEnv() {
        if (attached_ && g_vm) g_vm->DetachCurrentThread();
    }

   private:
    JNIEnv* env_ = nullptr;
    bool attached_ = false;
};
thread_local ThreadEnv g_thread_env;

struct CallbackState {
    jobject callback = nullptr;
    std::atomic<bool> terminal{false};
};

kathttp3_client* checked(jlong value) {
    auto* p = reinterpret_cast<kathttp3_client*>(static_cast<uintptr_t>(value));
    std::lock_guard<std::mutex> lock(g_handles_mutex);
    return g_handles.count(p) ? p : nullptr;
}

void release_state(JNIEnv* env, CallbackState* state) {
    if (!state) return;
    if (state->callback) env->DeleteGlobalRef(state->callback);
    delete state;
}

/* C-ABI callback handed to kathttp3; adapts the Kotlin DnsResolver into the
 * native Resolver interface. Family is derived from the IP string. */
int jni_resolve_cb(const char* host, uint16_t port, void* userdata, kathttp3_resolved_address* out,
                   size_t* out_count) {
    auto* ctx = static_cast<ResolverCtx*>(userdata);
    if (!ctx || !ctx->resolver || !out || !out_count) return -1;
    JNIEnv* env = g_thread_env.get();
    if (!env) return -1;

    jstring jhost = env->NewStringUTF(host);
    jobject list = env->CallObjectMethod(ctx->resolver, g_jni.resolver_resolve, jhost,
                                         static_cast<jint>(port));
    env->DeleteLocalRef(jhost);
    if (!list || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return -1;
    }

    jint count = env->CallIntMethod(list, g_jni.list_size);
    size_t cap = *out_count;
    size_t written = 0;
    for (jint i = 0; i < count && written < cap; ++i) {
        jobject elem = env->CallObjectMethod(list, g_jni.list_get, i);
        if (!elem) continue;
        jstring jip = reinterpret_cast<jstring>(env->CallObjectMethod(elem, g_jni.address_ip));
        jint aport = env->CallIntMethod(elem, g_jni.address_port);
        const char* ip = jip ? env->GetStringUTFChars(jip, nullptr) : nullptr;
        if (ip && *ip) {
            int family = (std::strchr(ip, ':') != nullptr) ? AF_INET6 : AF_INET;
            std::strncpy(out[written].ip, ip, sizeof(out[written].ip) - 1);
            out[written].ip[sizeof(out[written].ip) - 1] = '\0';
            out[written].port = static_cast<uint16_t>(aport);
            out[written].family = family;
            ++written;
            env->ReleaseStringUTFChars(jip, ip);
        }
        if (jip) env->DeleteLocalRef(jip);
        env->DeleteLocalRef(elem);
    }
    *out_count = written;
    env->DeleteLocalRef(list);
    return 0;
}

void free_resolver_ctx(JNIEnv* env, ResolverCtx* ctx) {
    if (!ctx) return;
    if (ctx->resolver) env->DeleteGlobalRef(ctx->resolver);
    delete ctx;
}

void event_cb(void* opaque, const kathttp3_event* event) noexcept {
    auto* state = static_cast<CallbackState*>(opaque);
    if (!state || !event || state->terminal.load(std::memory_order_acquire)) return;
    JNIEnv* env = g_thread_env.get();
    if (!env) return;
    if (event->type == KATHTTP3_EVENT_HEADERS) {
        if (event->header_count > static_cast<size_t>(std::numeric_limits<jsize>::max())) {
            KATHTTP3_LOG_ERR("JNI header count exceeds jsize\n");
            return;
        }
        const auto header_count = static_cast<jsize>(event->header_count);
        jobjectArray names = env->NewObjectArray(header_count, g_jni.string_class, nullptr);
        jobjectArray values = env->NewObjectArray(header_count, g_jni.string_class, nullptr);
        for (jsize i = 0; i < header_count && !env->ExceptionCheck(); ++i) {
            jstring n = env->NewStringUTF(event->names[i]);
            jstring v = env->NewStringUTF(event->values[i]);
            env->SetObjectArrayElement(names, i, n);
            env->SetObjectArrayElement(values, i, v);
            env->DeleteLocalRef(n);
            env->DeleteLocalRef(v);
        }
        if (names && values)
            env->CallVoidMethod(state->callback, g_jni.callback_headers, event->status_code, names,
                                values);
        env->DeleteLocalRef(names);
        env->DeleteLocalRef(values);
    } else if (event->type == KATHTTP3_EVENT_BODY) {
        if (event->data_len > static_cast<size_t>(std::numeric_limits<jsize>::max())) {
            KATHTTP3_LOG_ERR("JNI body chunk exceeds jsize\n");
            return;
        }
        const auto data_len = static_cast<jsize>(event->data_len);
        jbyteArray data = env->NewByteArray(data_len);
        if (data)
            env->SetByteArrayRegion(data, 0, data_len, reinterpret_cast<const jbyte*>(event->data));
        if (data) env->CallVoidMethod(state->callback, g_jni.callback_body, data);
        if (data) env->DeleteLocalRef(data);
    } else {
        if (!state->terminal.exchange(true, std::memory_order_acq_rel)) {
            if (event->type == KATHTTP3_EVENT_COMPLETE)
                env->CallVoidMethod(state->callback, g_jni.callback_complete);
            else
                env->CallVoidMethod(state->callback, g_jni.callback_error, event->error_code);
            if (env->ExceptionCheck()) env->ExceptionClear();
            release_state(env, state);
            return;
        }
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
}
}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK ||
        !initialize_jni_cache(env)) {
        if (env && env->ExceptionCheck()) env->ExceptionClear();
        return JNI_ERR;
    }
    // Build the platform (Android) certificate verifier and register it so
    // the core uses X509TrustManager for TRUST_PLATFORM.
    if (auto* v = kathttp3::create_android_platform_verifier(vm)) {
        kathttp3::set_platform_cert_verifier(v);
    }
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK)
        release_jni_cache(env);
    g_vm = nullptr;
}

extern "C" JNIEXPORT jlong JNICALL Java_dev_kathttp3_internal_NativeBridge_createClient(
    JNIEnv* env, jobject, jlong connect, jlong request, jlong idle, jlong dns, jlong handshake,
    jlong response_headers, jlong read, jlong write, jlong call, jlong consumer_stall,
    jint redirects, jint trustMode, jboolean insecure, jboolean enable_cookies,
    jboolean enable_0rtt, jboolean enable_qlog, jboolean enable_qlog_logcat, jstring caFile,
    jstring qlogPath, jint max_connection_workers, jint network_change_policy, jobject resolver) {
    kathttp3_client_options o;
    kathttp3_client_options_init(&o);
    o.connect_timeout_ms = static_cast<uint64_t>(connect);
    o.request_timeout_ms = static_cast<uint64_t>(request);
    o.idle_timeout_ms = static_cast<uint64_t>(idle);
    o.dns_timeout_ms = static_cast<uint64_t>(dns);
    o.handshake_timeout_ms = static_cast<uint64_t>(handshake);
    o.response_headers_timeout_ms = static_cast<uint64_t>(response_headers);
    o.read_timeout_ms = static_cast<uint64_t>(read);
    o.write_timeout_ms = static_cast<uint64_t>(write);
    o.call_timeout_ms = static_cast<uint64_t>(call);
    o.consumer_stall_timeout_ms = static_cast<uint64_t>(consumer_stall);
    o.max_redirects = static_cast<uint32_t>(redirects);
    o.trust_mode = static_cast<uint32_t>(trustMode);
    o.insecure_cert = insecure ? 1 : 0;
    o.enable_cookies = enable_cookies ? 1 : 0;
    o.enable_0rtt = enable_0rtt ? 1 : 0;
    o.enable_qlog = enable_qlog ? 1 : 0;
    o.max_connection_workers =
        max_connection_workers > 0 ? static_cast<uint32_t>(max_connection_workers) : 0;
    o.network_change_policy = network_change_policy == KATHTTP3_NETWORK_CHANGE_CLOSE_AND_RECONNECT
                                  ? KATHTTP3_NETWORK_CHANGE_CLOSE_AND_RECONNECT
                                  : KATHTTP3_NETWORK_CHANGE_ATTEMPT_MIGRATION;
#ifdef __ANDROID__
    std::unique_ptr<kathttp3::AndroidQlogLogcatSink> qlog_logcat_sink;
    if (enable_qlog && enable_qlog_logcat) {
        try {
            qlog_logcat_sink = std::make_unique<kathttp3::AndroidQlogLogcatSink>();
        } catch (...) {
            KATHTTP3_LOG_ERR("NativeBridge.createClient could not allocate qlog Logcat sink\n");
            return 0;
        }
        o.qlog_sink_cb = kathttp3::AndroidQlogLogcatSink::callback;
        o.qlog_sink_userdata = qlog_logcat_sink.get();
    }
#else
    (void)enable_qlog_logcat;
#endif
    const char* ca = caFile ? env->GetStringUTFChars(caFile, nullptr) : nullptr;
    if (caFile && !ca) return 0;
    o.ca_cert_file = ca;
    const char* qlog = qlogPath ? env->GetStringUTFChars(qlogPath, nullptr) : nullptr;
    if (qlogPath && !qlog) {
        if (ca) env->ReleaseStringUTFChars(caFile, ca);
        return 0;
    }
    o.qlog_path_prefix = qlog;
    ResolverCtx* rctx = nullptr;
    if (resolver) {
        rctx = new (std::nothrow) ResolverCtx;
        if (rctx) {
            rctx->resolver = env->NewGlobalRef(resolver);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (rctx->resolver) {
                o.resolve_cb = jni_resolve_cb;
                o.resolve_cb_userdata = rctx;
            } else {
                free_resolver_ctx(env, rctx);
                rctx = nullptr;
            }
        }
    }
    auto* p = kathttp3_client_create(&o);
    if (ca) env->ReleaseStringUTFChars(caFile, ca);
    if (qlog) env->ReleaseStringUTFChars(qlogPath, qlog);
    if (p) {
        try {
            std::lock_guard<std::mutex> lock(g_handles_mutex);
            g_handles.insert(p);
            if (rctx) g_resolvers[p] = rctx;
#ifdef __ANDROID__
            if (qlog_logcat_sink) g_qlog_logcat_sinks.emplace(p, std::move(qlog_logcat_sink));
#endif
        } catch (...) {
            KATHTTP3_LOG_ERR("NativeBridge.createClient failed while registering native handle\n");
            ResolverCtx* registered_resolver = nullptr;
#ifdef __ANDROID__
            std::unique_ptr<kathttp3::AndroidQlogLogcatSink> registered_qlog_sink;
#endif
            {
                std::lock_guard<std::mutex> lock(g_handles_mutex);
                g_handles.erase(p);
                auto resolver_it = g_resolvers.find(p);
                if (resolver_it != g_resolvers.end()) {
                    registered_resolver = static_cast<ResolverCtx*>(resolver_it->second);
                    g_resolvers.erase(resolver_it);
                }
#ifdef __ANDROID__
                auto qlog_it = g_qlog_logcat_sinks.find(p);
                if (qlog_it != g_qlog_logcat_sinks.end()) {
                    registered_qlog_sink = std::move(qlog_it->second);
                    g_qlog_logcat_sinks.erase(qlog_it);
                }
#endif
            }
            kathttp3_client_destroy(p);
            if (registered_resolver)
                free_resolver_ctx(env, registered_resolver);
            else if (rctx)
                free_resolver_ctx(env, rctx);
            return 0;
        }
    } else if (rctx) {
        free_resolver_ctx(env, rctx);
    }
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(p));
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp3_internal_NativeBridge_closeClient(JNIEnv*,
                                                                                      jobject,
                                                                                      jlong h) {
    if (auto* p = checked(h)) kathttp3_client_close(p);
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp3_internal_NativeBridge_destroyClient(JNIEnv* env,
                                                                                        jobject,
                                                                                        jlong h) {
    auto* p = reinterpret_cast<kathttp3_client*>(static_cast<uintptr_t>(h));
    ResolverCtx* rctx = nullptr;
#ifdef __ANDROID__
    std::unique_ptr<kathttp3::AndroidQlogLogcatSink> qlog_logcat_sink;
#endif
    {
        std::lock_guard<std::mutex> lock(g_handles_mutex);
        if (!g_handles.erase(p)) return;
        auto it = g_resolvers.find(p);
        if (it != g_resolvers.end()) {
            rctx = reinterpret_cast<ResolverCtx*>(it->second);
            g_resolvers.erase(it);
        }
#ifdef __ANDROID__
        auto qlog_it = g_qlog_logcat_sinks.find(p);
        if (qlog_it != g_qlog_logcat_sinks.end()) {
            qlog_logcat_sink = std::move(qlog_it->second);
            g_qlog_logcat_sinks.erase(qlog_it);
        }
#endif
    }
    kathttp3_client_destroy(p);
    // destroy joins all native workers before releasing resolver global refs;
    // a resolver callback can otherwise observe freed JNI state.
    if (rctx) free_resolver_ctx(env, rctx);
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp3_internal_NativeBridge_cancel(JNIEnv*, jobject,
                                                                                 jlong h,
                                                                                 jlong id) {
    if (auto* p = checked(h)) kathttp3_client_cancel(p, id);
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp3_internal_NativeBridge_networkChanged(
    JNIEnv*, jobject, jlong h, jlong generation, jlong network_handle) {
    if (auto* p = checked(h); p && generation > 0)
        kathttp3_client_network_changed2(p, static_cast<uint64_t>(generation),
                                         static_cast<uint64_t>(network_handle));
}

extern "C" JNIEXPORT jboolean JNICALL Java_dev_kathttp3_internal_NativeBridge_execute(
    JNIEnv* env, jobject, jlong h, jlong id, jstring method, jstring url, jobjectArray names,
    jobjectArray values, jbyteArray body, jboolean redirects, jboolean streaming,
    jboolean streaming_request_body, jlong streaming_content_length, jobject callback) {
    auto* client = checked(h);
    if (!client || !method || !url || !callback) return JNI_FALSE;
    const char* m = env->GetStringUTFChars(method, nullptr);
    const char* u = env->GetStringUTFChars(url, nullptr);
    kathttp3_request* req = kathttp3_request_create(m, u);
    env->ReleaseStringUTFChars(method, m);
    env->ReleaseStringUTFChars(url, u);
    if (!req) return JNI_FALSE;
    jsize count = names ? env->GetArrayLength(names) : 0;
    if (!values || env->GetArrayLength(values) != count) {
        kathttp3_request_destroy(req);
        return JNI_FALSE;
    }
    for (jsize i = 0; i < count; i++) {
        auto n = (jstring)env->GetObjectArrayElement(names, i);
        auto v = (jstring)env->GetObjectArrayElement(values, i);
        const char* cn = env->GetStringUTFChars(n, nullptr);
        const char* cv = env->GetStringUTFChars(v, nullptr);
        int rc = kathttp3_request_add_header(req, cn, cv);
        env->ReleaseStringUTFChars(n, cn);
        env->ReleaseStringUTFChars(v, cv);
        env->DeleteLocalRef(n);
        env->DeleteLocalRef(v);
        if (rc != 0) {
            kathttp3_request_destroy(req);
            return JNI_FALSE;
        }
    }
    if (body) {
        jsize len = env->GetArrayLength(body);
        jbyte* data = env->GetByteArrayElements(body, nullptr);
        int rc = kathttp3_request_set_body(req, reinterpret_cast<uint8_t*>(data),
                                           static_cast<size_t>(len));
        env->ReleaseByteArrayElements(body, data, JNI_ABORT);
        if (rc != 0) {
            kathttp3_request_destroy(req);
            return JNI_FALSE;
        }
    }
    kathttp3_request_set_follow_redirects(req, redirects);
    kathttp3_request_set_streaming(req, streaming);
    if (streaming_request_body &&
        kathttp3_request_set_streaming_body(req, static_cast<int64_t>(streaming_content_length)) !=
            KATHTTP3_OK) {
        kathttp3_request_destroy(req);
        return JNI_FALSE;
    }
    auto* state = new (std::nothrow) CallbackState;
    if (!state) {
        kathttp3_request_destroy(req);
        return JNI_FALSE;
    }
    state->callback = env->NewGlobalRef(callback);
    if (!state->callback) {
        delete state;
        kathttp3_request_destroy(req);
        return JNI_FALSE;
    }
    kathttp3_client_execute(client, req, id, event_cb, state);
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_dev_kathttp3_internal_NativeBridge_consume(JNIEnv*, jobject, jlong h, jlong id, jlong bytes) {
    auto* client = checked(h);
    if (!client || bytes < 0) return JNI_FALSE;
    return kathttp3_client_consume_body(client, id, static_cast<size_t>(bytes)) == KATHTTP3_OK
               ? JNI_TRUE
               : JNI_FALSE;
}

extern "C" JNIEXPORT jint JNICALL Java_dev_kathttp3_internal_NativeBridge_appendRequestBody(
    JNIEnv* env, jobject, jlong h, jlong id, jbyteArray data, jboolean finished) {
    auto* client = checked(h);
    if (!client) return KATHTTP3_ERR_CLOSED;
    const jsize len = data ? env->GetArrayLength(data) : 0;
    jbyte* bytes = data && len ? env->GetByteArrayElements(data, nullptr) : nullptr;
    const auto result = kathttp3_client_request_body_append(
        client, id, reinterpret_cast<const uint8_t*>(bytes), static_cast<size_t>(len), finished);
    if (bytes) env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    return result;
}
