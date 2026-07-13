#include <jni.h>
#include <sys/socket.h>

#include <atomic>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "android_cert_verifier.h"
#include "cert_verifier.h"
#include "kathttp.h"

namespace {
JavaVM* g_vm = nullptr;
std::mutex g_handles_mutex;
std::unordered_set<kathttp_client*> g_handles;
std::unordered_map<kathttp_client*, void*> g_resolvers;

/* Per-client state for a Kotlin DnsResolver injected through the options.
 * Class/method IDs are resolved on the calling (Java) thread at create time,
 * where the app class loader is available, then used from the native worker
 * thread (which would fail FindClass otherwise). */
struct ResolverCtx {
    jobject resolver = nullptr;      /* global ref */
    jmethodID resolve_mid = nullptr; /* DnsResolver.resolve */
    jclass list_class = nullptr;     /* global ref to java/util/List */
    jmethodID list_size_mid = nullptr;
    jmethodID list_get_mid = nullptr;
    jclass addr_class = nullptr;  /* global ref to dev/kathttp/ResolvedAddress */
    jmethodID ip_mid = nullptr;   /* ResolvedAddress.getIp */
    jmethodID port_mid = nullptr; /* ResolvedAddress.getPort */
};

class EnvScope {
   public:
    EnvScope() {
        if (g_vm->GetEnv(reinterpret_cast<void**>(&env_), JNI_VERSION_1_6) != JNI_OK) {
#ifdef __ANDROID__
            if (g_vm->AttachCurrentThread(&env_, nullptr) == JNI_OK)
                attached_ = true;
            else
                env_ = nullptr;
#else
            if (g_vm->AttachCurrentThread(reinterpret_cast<void**>(&env_), nullptr) == JNI_OK)
                attached_ = true;
            else
                env_ = nullptr;
#endif
        }
    }
    ~EnvScope() {
        if (attached_) g_vm->DetachCurrentThread();
    }
    JNIEnv* get() const {
        return env_;
    }

   private:
    JNIEnv* env_ = nullptr;
    bool attached_ = false;
};

struct CallbackState {
    jobject callback = nullptr;
    std::atomic<bool> terminal{false};
};

kathttp_client* checked(jlong value) {
    auto* p = reinterpret_cast<kathttp_client*>(static_cast<uintptr_t>(value));
    std::lock_guard<std::mutex> lock(g_handles_mutex);
    return g_handles.count(p) ? p : nullptr;
}

void release_state(JNIEnv* env, CallbackState* state) {
    if (!state) return;
    if (state->callback) env->DeleteGlobalRef(state->callback);
    delete state;
}

/* C-ABI callback handed to kathttp; adapts the Kotlin DnsResolver into the
 * native Resolver interface. Family is derived from the IP string. */
int jni_resolve_cb(const char* host, uint16_t port, void* userdata, kathttp_resolved_address* out,
                   size_t* out_count) {
    auto* ctx = static_cast<ResolverCtx*>(userdata);
    if (!ctx || !ctx->resolver || !out || !out_count) return -1;
    EnvScope scope;
    JNIEnv* env = scope.get();
    if (!env) return -1;

    jstring jhost = env->NewStringUTF(host);
    jobject list =
        env->CallObjectMethod(ctx->resolver, ctx->resolve_mid, jhost, static_cast<jint>(port));
    env->DeleteLocalRef(jhost);
    if (!list || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return -1;
    }

    jint count = env->CallIntMethod(list, ctx->list_size_mid);
    size_t cap = *out_count;
    size_t written = 0;
    for (jint i = 0; i < count && written < cap; ++i) {
        jobject elem = env->CallObjectMethod(list, ctx->list_get_mid, i);
        if (!elem) continue;
        jstring jip = reinterpret_cast<jstring>(env->CallObjectMethod(elem, ctx->ip_mid));
        jint aport = env->CallIntMethod(elem, ctx->port_mid);
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
    if (ctx->list_class) env->DeleteGlobalRef(ctx->list_class);
    if (ctx->addr_class) env->DeleteGlobalRef(ctx->addr_class);
    delete ctx;
}

void event_cb(void* opaque, const kathttp_event* event) noexcept {
    auto* state = static_cast<CallbackState*>(opaque);
    if (!state || !event || state->terminal.load(std::memory_order_acquire)) return;
    EnvScope scope;
    JNIEnv* env = scope.get();
    if (!env) return;
    jclass cls = env->GetObjectClass(state->callback);
    if (!cls) {
        env->ExceptionClear();
        return;
    }
    if (event->type == KATHTTP_EVENT_HEADERS) {
        jclass str = env->FindClass("java/lang/String");
        jobjectArray names = env->NewObjectArray(event->header_count, str, nullptr);
        jobjectArray values = env->NewObjectArray(event->header_count, str, nullptr);
        for (size_t i = 0; i < event->header_count && !env->ExceptionCheck(); ++i) {
            jstring n = env->NewStringUTF(event->names[i]);
            jstring v = env->NewStringUTF(event->values[i]);
            env->SetObjectArrayElement(names, i, n);
            env->SetObjectArrayElement(values, i, v);
            env->DeleteLocalRef(n);
            env->DeleteLocalRef(v);
        }
        jmethodID mid =
            env->GetMethodID(cls, "onHeaders", "(I[Ljava/lang/String;[Ljava/lang/String;)V");
        if (mid) env->CallVoidMethod(state->callback, mid, event->status_code, names, values);
        env->DeleteLocalRef(names);
        env->DeleteLocalRef(values);
    } else if (event->type == KATHTTP_EVENT_BODY) {
        jbyteArray data = env->NewByteArray(event->data_len);
        if (data)
            env->SetByteArrayRegion(data, 0, event->data_len,
                                    reinterpret_cast<const jbyte*>(event->data));
        jmethodID mid = env->GetMethodID(cls, "onBody", "([B)V");
        if (mid && data) env->CallVoidMethod(state->callback, mid, data);
        if (data) env->DeleteLocalRef(data);
    } else {
        if (!state->terminal.exchange(true, std::memory_order_acq_rel)) {
            const char* name = event->type == KATHTTP_EVENT_COMPLETE ? "onComplete" : "onError";
            const char* sig = event->type == KATHTTP_EVENT_COMPLETE ? "()V" : "(I)V";
            jmethodID mid = env->GetMethodID(cls, name, sig);
            if (mid) {
                if (event->type == KATHTTP_EVENT_COMPLETE)
                    env->CallVoidMethod(state->callback, mid);
                else
                    env->CallVoidMethod(state->callback, mid, event->error_code);
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(cls);
            release_state(env, state);
            return;
        }
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(cls);
}
}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_vm = vm;
    // Build the platform (Android) certificate verifier and register it so
    // the core uses X509TrustManager for TRUST_PLATFORM.
    if (auto* v = kathttp::create_android_platform_verifier(vm)) {
        kathttp::set_platform_cert_verifier(v);
    }
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jlong JNICALL Java_dev_kathttp_internal_NativeBridge_createClient(
    JNIEnv* env, jobject, jlong connect, jlong request, jlong idle, jlong dns, jlong handshake,
    jlong response_headers, jlong read, jlong write, jlong call, jint redirects, jint trustMode,
    jboolean insecure, jstring caFile, jobject resolver) {
    kathttp_client_options o;
    kathttp_client_options_init(&o);
    o.connect_timeout_ms = connect;
    o.request_timeout_ms = request;
    o.idle_timeout_ms = idle;
    o.dns_timeout_ms = dns;
    o.handshake_timeout_ms = handshake;
    o.response_headers_timeout_ms = response_headers;
    o.read_timeout_ms = read;
    o.write_timeout_ms = write;
    o.call_timeout_ms = call;
    o.max_redirects = redirects;
    o.trust_mode = static_cast<uint32_t>(trustMode);
    o.insecure_cert = insecure ? 1 : 0;
    const char* ca = caFile ? env->GetStringUTFChars(caFile, nullptr) : nullptr;
    if (caFile && !ca) return 0;
    o.ca_cert_file = ca;
    ResolverCtx* rctx = nullptr;
    if (resolver) {
        rctx = new (std::nothrow) ResolverCtx;
        if (rctx) {
            jclass rc = env->GetObjectClass(resolver);
            jclass lc = env->FindClass("java/util/List");
            jclass ac = env->FindClass("dev/kathttp/ResolvedAddress");
            rctx->resolver = env->NewGlobalRef(resolver);
            rctx->resolve_mid =
                rc ? env->GetMethodID(rc, "resolve", "(Ljava/lang/String;I)Ljava/util/List;")
                   : nullptr;
            rctx->list_class = lc ? reinterpret_cast<jclass>(env->NewGlobalRef(lc)) : nullptr;
            rctx->list_size_mid = (rctx->list_class && !env->ExceptionCheck())
                                      ? env->GetMethodID(rctx->list_class, "size", "()I")
                                      : nullptr;
            rctx->list_get_mid =
                (rctx->list_class && !env->ExceptionCheck())
                    ? env->GetMethodID(rctx->list_class, "get", "(I)Ljava/lang/Object;")
                    : nullptr;
            rctx->addr_class = ac ? reinterpret_cast<jclass>(env->NewGlobalRef(ac)) : nullptr;
            rctx->ip_mid = (rctx->addr_class && !env->ExceptionCheck())
                               ? env->GetMethodID(rctx->addr_class, "getIp", "()Ljava/lang/String;")
                               : nullptr;
            rctx->port_mid = (rctx->addr_class && !env->ExceptionCheck())
                                 ? env->GetMethodID(rctx->addr_class, "getPort", "()I")
                                 : nullptr;
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (rc) env->DeleteLocalRef(rc);
            if (lc) env->DeleteLocalRef(lc);
            if (ac) env->DeleteLocalRef(ac);
            if (rctx->resolve_mid && rctx->list_class && rctx->list_size_mid &&
                rctx->list_get_mid && rctx->addr_class && rctx->ip_mid && rctx->port_mid) {
                o.resolve_cb = jni_resolve_cb;
                o.resolve_cb_userdata = rctx;
            } else {
                free_resolver_ctx(env, rctx);
                rctx = nullptr;
            }
        }
    }
    auto* p = kathttp_client_create(&o);
    if (ca) env->ReleaseStringUTFChars(caFile, ca);
    if (p) {
        try {
            std::lock_guard<std::mutex> lock(g_handles_mutex);
            g_handles.insert(p);
            if (rctx) g_resolvers[p] = rctx;
        } catch (...) {
            if (rctx) {
                free_resolver_ctx(env, rctx);
                g_resolvers.erase(p);
            }
            kathttp_client_destroy(p);
            return 0;
        }
    } else if (rctx) {
        free_resolver_ctx(env, rctx);
    }
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(p));
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp_internal_NativeBridge_closeClient(JNIEnv*,
                                                                                     jobject,
                                                                                     jlong h) {
    std::lock_guard<std::mutex> lock(g_handles_mutex);
    auto* p = reinterpret_cast<kathttp_client*>(static_cast<uintptr_t>(h));
    if (g_handles.count(p)) kathttp_client_close(p);
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp_internal_NativeBridge_destroyClient(JNIEnv* env,
                                                                                       jobject,
                                                                                       jlong h) {
    auto* p = reinterpret_cast<kathttp_client*>(static_cast<uintptr_t>(h));
    ResolverCtx* rctx = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_handles_mutex);
        if (!g_handles.erase(p)) return;
        auto it = g_resolvers.find(p);
        if (it != g_resolvers.end()) {
            rctx = reinterpret_cast<ResolverCtx*>(it->second);
            g_resolvers.erase(it);
        }
    }
    if (rctx) free_resolver_ctx(env, rctx);
    kathttp_client_destroy(p);
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp_internal_NativeBridge_cancel(JNIEnv*, jobject,
                                                                                jlong h, jlong id) {
    std::lock_guard<std::mutex> lock(g_handles_mutex);
    auto* p = reinterpret_cast<kathttp_client*>(static_cast<uintptr_t>(h));
    if (g_handles.count(p)) kathttp_client_cancel(p, id);
}

extern "C" JNIEXPORT jboolean JNICALL Java_dev_kathttp_internal_NativeBridge_execute(
    JNIEnv* env, jobject, jlong h, jlong id, jstring method, jstring url, jobjectArray names,
    jobjectArray values, jbyteArray body, jboolean redirects, jboolean streaming,
    jobject callback) {
    std::lock_guard<std::mutex> handle_lock(g_handles_mutex);
    auto* client = reinterpret_cast<kathttp_client*>(static_cast<uintptr_t>(h));
    if (!g_handles.count(client) || !method || !url || !callback) return JNI_FALSE;
    const char* m = env->GetStringUTFChars(method, nullptr);
    const char* u = env->GetStringUTFChars(url, nullptr);
    kathttp_request* req = kathttp_request_create(m, u);
    env->ReleaseStringUTFChars(method, m);
    env->ReleaseStringUTFChars(url, u);
    if (!req) return JNI_FALSE;
    jsize count = names ? env->GetArrayLength(names) : 0;
    if (!values || env->GetArrayLength(values) != count) {
        kathttp_request_destroy(req);
        return JNI_FALSE;
    }
    for (jsize i = 0; i < count; i++) {
        auto n = (jstring)env->GetObjectArrayElement(names, i);
        auto v = (jstring)env->GetObjectArrayElement(values, i);
        const char* cn = env->GetStringUTFChars(n, nullptr);
        const char* cv = env->GetStringUTFChars(v, nullptr);
        int rc = kathttp_request_add_header(req, cn, cv);
        env->ReleaseStringUTFChars(n, cn);
        env->ReleaseStringUTFChars(v, cv);
        env->DeleteLocalRef(n);
        env->DeleteLocalRef(v);
        if (rc != 0) {
            kathttp_request_destroy(req);
            return JNI_FALSE;
        }
    }
    if (body) {
        jsize len = env->GetArrayLength(body);
        jbyte* data = env->GetByteArrayElements(body, nullptr);
        int rc = kathttp_request_set_body(req, reinterpret_cast<uint8_t*>(data), len);
        env->ReleaseByteArrayElements(body, data, JNI_ABORT);
        if (rc != 0) {
            kathttp_request_destroy(req);
            return JNI_FALSE;
        }
    }
    kathttp_request_set_follow_redirects(req, redirects);
    kathttp_request_set_streaming(req, streaming);
    auto* state = new (std::nothrow) CallbackState;
    if (!state) {
        kathttp_request_destroy(req);
        return JNI_FALSE;
    }
    state->callback = env->NewGlobalRef(callback);
    if (!state->callback) {
        delete state;
        kathttp_request_destroy(req);
        return JNI_FALSE;
    }
    kathttp_client_execute(client, req, id, event_cb, state);
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL Java_dev_kathttp_internal_NativeBridge_consume(
    JNIEnv*, jobject, jlong h, jlong id, jlong bytes) {
    std::lock_guard<std::mutex> handle_lock(g_handles_mutex);
    auto* client = reinterpret_cast<kathttp_client*>(static_cast<uintptr_t>(h));
    if (!g_handles.count(client) || bytes < 0) return JNI_FALSE;
    return kathttp_client_consume_body(client, id, static_cast<size_t>(bytes)) == KATHTTP_OK
               ? JNI_TRUE
               : JNI_FALSE;
}
