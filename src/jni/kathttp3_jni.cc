#include <arpa/inet.h>
#include <jni.h>
#include <sys/socket.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "android_cert_verifier.h"
#ifdef __ANDROID__
#include "android_qlog_sink.h"
#endif
#include "cert_verifier.h"
#include "jni_body_batch.h"
#include "kathttp3.h"
#include "log.h"

namespace {
JavaVM* g_vm = nullptr;
std::mutex g_handles_mutex;
std::atomic<uint64_t> g_next_handle{1};

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

struct HandleEntry {
    kathttp3_client* client = nullptr;
    ResolverCtx* resolver = nullptr;
    size_t active_calls = 0;
    bool destroy_requested = false;
    bool destroy_started = false;
#ifdef __ANDROID__
    std::unique_ptr<kathttp3::AndroidQlogLogcatSink> qlog_logcat_sink;
#endif
};

std::unordered_map<jlong, std::shared_ptr<HandleEntry>> g_handles;

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

class UtfChars {
   public:
    UtfChars(JNIEnv* env, jstring string)
        : env_(env),
          string_(string),
          chars_(string ? env->GetStringUTFChars(string, nullptr) : nullptr) {}
    ~UtfChars() {
        if (chars_) env_->ReleaseStringUTFChars(string_, chars_);
    }

    UtfChars(const UtfChars&) = delete;
    UtfChars& operator=(const UtfChars&) = delete;

    explicit operator bool() const {
        return chars_ != nullptr;
    }
    const char* get() const {
        return chars_;
    }

   private:
    JNIEnv* env_;
    jstring string_;
    const char* chars_;
};

struct CallbackState {
    jobject callback = nullptr;
    std::atomic<bool> terminal{false};
    std::atomic<bool> failure_reported{false};
    kathttp3::JniBodyBatch body_batch;
};

void finalize_handle(std::shared_ptr<HandleEntry> entry) noexcept;

class ClientLease {
   public:
    ClientLease() = default;
    explicit ClientLease(std::shared_ptr<HandleEntry> entry) : entry_(std::move(entry)) {}
    ~ClientLease() {
        release();
    }

    ClientLease(const ClientLease&) = delete;
    ClientLease& operator=(const ClientLease&) = delete;
    ClientLease(ClientLease&& other) noexcept : entry_(std::move(other.entry_)) {}
    ClientLease& operator=(ClientLease&& other) noexcept {
        if (this != &other) {
            release();
            entry_ = std::move(other.entry_);
        }
        return *this;
    }

    explicit operator bool() const {
        return entry_ != nullptr;
    }
    kathttp3_client* get() const {
        return entry_ ? entry_->client : nullptr;
    }

   private:
    void release() noexcept {
        if (!entry_) return;
        std::shared_ptr<HandleEntry> finalize;
        {
            std::lock_guard<std::mutex> lock(g_handles_mutex);
            if (entry_->active_calls > 0) --entry_->active_calls;
            if (entry_->active_calls == 0 && entry_->destroy_requested &&
                !entry_->destroy_started) {
                entry_->destroy_started = true;
                finalize = entry_;
            }
        }
        entry_.reset();
        if (finalize) finalize_handle(std::move(finalize));
    }

    std::shared_ptr<HandleEntry> entry_;
};

ClientLease acquire_client(jlong value) {
    if (value == 0) return {};
    std::lock_guard<std::mutex> lock(g_handles_mutex);
    const auto it = g_handles.find(value);
    if (it == g_handles.end() || it->second->destroy_requested) return {};
    ++it->second->active_calls;
    return ClientLease(it->second);
}

void release_state(JNIEnv* env, CallbackState* state) {
    if (!state) return;
    if (state->callback) env->DeleteGlobalRef(state->callback);
    delete state;
}

uint64_t monotonic_now_ns() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count());
}

bool flush_body_batch(JNIEnv* env, CallbackState* state) {
    if (state->body_batch.empty()) return true;
    const auto data_len = static_cast<jsize>(state->body_batch.size());
    jbyteArray data = env->NewByteArray(data_len);
    if (!data || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (data) env->DeleteLocalRef(data);
        return false;
    }
    env->SetByteArrayRegion(data, 0, data_len,
                            reinterpret_cast<const jbyte*>(state->body_batch.data()));
    if (!env->ExceptionCheck()) env->CallVoidMethod(state->callback, g_jni.callback_body, data);
    env->DeleteLocalRef(data);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    state->body_batch.clear();
    return true;
}

void report_jni_body_failure(JNIEnv* env, CallbackState* state) {
    if (state->failure_reported.exchange(true, std::memory_order_acq_rel)) return;
    env->CallVoidMethod(state->callback, g_jni.callback_error, KATHTTP3_ERR_NOMEM);
    if (env->ExceptionCheck()) env->ExceptionClear();
}

/* C-ABI callback handed to kathttp3; adapts the Kotlin DnsResolver into the
 * native Resolver interface. Family is derived from the IP string. */
int jni_resolve_cb(const char* host, uint16_t port, void* userdata, kathttp3_resolved_address* out,
                   size_t* out_count) {
    auto* ctx = static_cast<ResolverCtx*>(userdata);
    if (!host || !ctx || !ctx->resolver || !out || !out_count) return -1;
    JNIEnv* env = g_thread_env.get();
    if (!env) return -1;

    jstring jhost = env->NewStringUTF(host);
    if (!jhost || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (jhost) env->DeleteLocalRef(jhost);
        return -1;
    }
    jobject list = env->CallObjectMethod(ctx->resolver, g_jni.resolver_resolve, jhost,
                                         static_cast<jint>(port));
    env->DeleteLocalRef(jhost);
    if (!list || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return -1;
    }

    jint count = env->CallIntMethod(list, g_jni.list_size);
    if (count < 0 || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(list);
        return -1;
    }
    size_t cap = *out_count;
    size_t written = 0;
    bool failed = false;
    for (jint i = 0; i < count && written < cap; ++i) {
        jobject elem = env->CallObjectMethod(list, g_jni.list_get, i);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            failed = true;
            break;
        }
        if (!elem) continue;
        jstring jip = reinterpret_cast<jstring>(env->CallObjectMethod(elem, g_jni.address_ip));
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            env->DeleteLocalRef(elem);
            failed = true;
            break;
        }
        jint aport = env->CallIntMethod(elem, g_jni.address_port);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            if (jip) env->DeleteLocalRef(jip);
            env->DeleteLocalRef(elem);
            failed = true;
            break;
        }
        const char* ip = jip ? env->GetStringUTFChars(jip, nullptr) : nullptr;
        if (jip && !ip) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(jip);
            env->DeleteLocalRef(elem);
            failed = true;
            break;
        }
        in_addr ipv4{};
        in6_addr ipv6{};
        const int family = ip && inet_pton(AF_INET, ip, &ipv4) == 1    ? AF_INET
                           : ip && inet_pton(AF_INET6, ip, &ipv6) == 1 ? AF_INET6
                                                                       : 0;
        if (family != 0 && aport > 0 && aport <= UINT16_MAX) {
            std::strncpy(out[written].ip, ip, sizeof(out[written].ip) - 1);
            out[written].ip[sizeof(out[written].ip) - 1] = '\0';
            out[written].port = static_cast<uint16_t>(aport);
            out[written].family = family;
            ++written;
        }
        if (ip) env->ReleaseStringUTFChars(jip, ip);
        if (jip) env->DeleteLocalRef(jip);
        env->DeleteLocalRef(elem);
    }
    *out_count = failed ? 0 : written;
    env->DeleteLocalRef(list);
    return failed ? -1 : 0;
}

void free_resolver_ctx(JNIEnv* env, ResolverCtx* ctx) {
    if (!ctx) return;
    if (ctx->resolver) env->DeleteGlobalRef(ctx->resolver);
    delete ctx;
}

void finalize_handle(std::shared_ptr<HandleEntry> entry) noexcept {
    if (!entry) return;
    kathttp3_client_destroy(entry->client);
    // Native destruction joins resolver workers before their global reference
    // is released. A lease is always finalized on a JVM-attached JNI caller.
    if (entry->resolver) {
        if (JNIEnv* env = g_thread_env.get()) {
            free_resolver_ctx(env, entry->resolver);
        } else {
            KATHTTP3_LOG_ERR("could not release JNI resolver for destroyed client\n");
            delete entry->resolver;
        }
        entry->resolver = nullptr;
    }
#ifdef __ANDROID__
    entry->qlog_logcat_sink.reset();
#endif
}

void event_cb(void* opaque, const kathttp3_event* event) noexcept {
    auto* state = static_cast<CallbackState*>(opaque);
    if (!state || !event || state->terminal.load(std::memory_order_acquire)) return;
    JNIEnv* env = g_thread_env.get();
    if (!env) return;
    if (event->type == KATHTTP3_EVENT_HEADERS) {
        if (event->header_count > static_cast<size_t>(std::numeric_limits<jsize>::max()) ||
            (event->header_count != 0 && (!event->names || !event->values))) {
            KATHTTP3_LOG_ERR("JNI received an invalid header array\n");
            report_jni_body_failure(env, state);
            return;
        }
        const auto header_count = static_cast<jsize>(event->header_count);
        jobjectArray names = env->NewObjectArray(header_count, g_jni.string_class, nullptr);
        jobjectArray values = env->NewObjectArray(header_count, g_jni.string_class, nullptr);
        if (!names || !values || env->ExceptionCheck()) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (names) env->DeleteLocalRef(names);
            if (values) env->DeleteLocalRef(values);
            report_jni_body_failure(env, state);
            return;
        }
        bool failed = false;
        for (jsize i = 0; i < header_count && !env->ExceptionCheck(); ++i) {
            if (!event->names[i] || !event->values[i]) {
                failed = true;
                break;
            }
            jstring n = env->NewStringUTF(event->names[i]);
            if (!n || env->ExceptionCheck()) {
                if (n) env->DeleteLocalRef(n);
                failed = true;
                break;
            }
            jstring v = env->NewStringUTF(event->values[i]);
            if (!v || env->ExceptionCheck()) {
                env->DeleteLocalRef(n);
                if (v) env->DeleteLocalRef(v);
                failed = true;
                break;
            }
            env->SetObjectArrayElement(names, i, n);
            if (!env->ExceptionCheck()) env->SetObjectArrayElement(values, i, v);
            env->DeleteLocalRef(n);
            env->DeleteLocalRef(v);
        }
        if (failed || env->ExceptionCheck()) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(names);
            env->DeleteLocalRef(values);
            report_jni_body_failure(env, state);
            return;
        }
        env->CallVoidMethod(state->callback, g_jni.callback_headers, event->status_code, names,
                            values);
        env->DeleteLocalRef(names);
        env->DeleteLocalRef(values);
    } else if (event->type == KATHTTP3_EVENT_BODY) {
        if (state->failure_reported.load(std::memory_order_acquire)) return;
        if (event->data_len != 0 && !event->data) {
            report_jni_body_failure(env, state);
            return;
        }
        size_t offset = 0;
        const uint64_t now = monotonic_now_ns();
        while (offset < event->data_len) {
            const size_t copied =
                state->body_batch.append(event->data + offset, event->data_len - offset, now);
            if (copied == 0) {
                if (!flush_body_batch(env, state)) {
                    report_jni_body_failure(env, state);
                    break;
                }
                continue;
            }
            offset += copied;
            if (state->body_batch.should_flush(now) && !flush_body_batch(env, state)) {
                report_jni_body_failure(env, state);
                break;
            }
        }
    } else {
        if (!state->terminal.exchange(true, std::memory_order_acq_rel)) {
            if (!state->failure_reported.load(std::memory_order_acquire)) {
                if (!flush_body_batch(env, state)) {
                    report_jni_body_failure(env, state);
                } else if (event->type == KATHTTP3_EVENT_COMPLETE) {
                    env->CallVoidMethod(state->callback, g_jni.callback_complete);
                } else {
                    env->CallVoidMethod(state->callback, g_jni.callback_error, event->error_code);
                }
            }
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
        const uint64_t next_handle = g_next_handle.fetch_add(1, std::memory_order_relaxed);
        if (next_handle == 0 ||
            next_handle > static_cast<uint64_t>(std::numeric_limits<jlong>::max())) {
            kathttp3_client_destroy(p);
            if (rctx) free_resolver_ctx(env, rctx);
            return 0;
        }
        const auto handle = static_cast<jlong>(next_handle);
        std::shared_ptr<HandleEntry> entry;
        try {
            entry = std::make_shared<HandleEntry>();
            entry->client = p;
            entry->resolver = rctx;
#ifdef __ANDROID__
            entry->qlog_logcat_sink = std::move(qlog_logcat_sink);
#endif
            std::lock_guard<std::mutex> lock(g_handles_mutex);
            g_handles.emplace(handle, entry);
        } catch (...) {
            KATHTTP3_LOG_ERR("NativeBridge.createClient failed while registering native handle\n");
            kathttp3_client_destroy(p);
            ResolverCtx* owned_resolver = entry ? entry->resolver : rctx;
            if (owned_resolver) free_resolver_ctx(env, owned_resolver);
            if (entry) entry->resolver = nullptr;
            return 0;
        }
        return handle;
    } else if (rctx) {
        free_resolver_ctx(env, rctx);
    }
    return 0;
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp3_internal_NativeBridge_closeClient(JNIEnv*,
                                                                                      jobject,
                                                                                      jlong h) {
    auto client = acquire_client(h);
    if (client) kathttp3_client_close(client.get());
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp3_internal_NativeBridge_destroyClient(JNIEnv* env,
                                                                                        jobject,
                                                                                        jlong h) {
    std::shared_ptr<HandleEntry> finalize;
    {
        std::lock_guard<std::mutex> lock(g_handles_mutex);
        const auto it = g_handles.find(h);
        if (it == g_handles.end()) return;
        auto entry = it->second;
        g_handles.erase(it);
        entry->destroy_requested = true;
        if (entry->active_calls == 0 && !entry->destroy_started) {
            entry->destroy_started = true;
            finalize = std::move(entry);
        }
    }
    (void)env;
    if (finalize) finalize_handle(std::move(finalize));
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp3_internal_NativeBridge_cancel(JNIEnv*, jobject,
                                                                                 jlong h,
                                                                                 jlong id) {
    auto client = acquire_client(h);
    if (client) kathttp3_client_cancel(client.get(), id);
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp3_internal_NativeBridge_networkChanged(
    JNIEnv*, jobject, jlong h, jlong generation, jlong network_handle) {
    auto client = acquire_client(h);
    if (client && generation > 0)
        kathttp3_client_network_changed2(client.get(), static_cast<uint64_t>(generation),
                                         static_cast<uint64_t>(network_handle));
}

extern "C" JNIEXPORT jboolean JNICALL Java_dev_kathttp3_internal_NativeBridge_execute(
    JNIEnv* env, jobject, jlong h, jlong id, jstring method, jstring url, jobjectArray names,
    jobjectArray values, jbyteArray body, jboolean redirects, jboolean streaming,
    jboolean streaming_request_body, jlong streaming_content_length, jobject callback) {
    auto client = acquire_client(h);
    if (!client || !method || !url || !callback) return JNI_FALSE;
    UtfChars m(env, method);
    if (!m) return JNI_FALSE;
    UtfChars u(env, url);
    if (!u) return JNI_FALSE;
    kathttp3_request* req = kathttp3_request_create(m.get(), u.get());
    if (!req) return JNI_FALSE;
    jsize count = names ? env->GetArrayLength(names) : 0;
    if (!values || env->GetArrayLength(values) != count) {
        kathttp3_request_destroy(req);
        return JNI_FALSE;
    }
    for (jsize i = 0; i < count; i++) {
        auto n = reinterpret_cast<jstring>(env->GetObjectArrayElement(names, i));
        auto v = reinterpret_cast<jstring>(env->GetObjectArrayElement(values, i));
        if (env->ExceptionCheck() || !n || !v) {
            if (n) env->DeleteLocalRef(n);
            if (v) env->DeleteLocalRef(v);
            kathttp3_request_destroy(req);
            return JNI_FALSE;
        }
        int rc = KATHTTP3_ERR_NOMEM;
        {
            UtfChars cn(env, n);
            if (cn) {
                UtfChars cv(env, v);
                if (cv) rc = kathttp3_request_add_header(req, cn.get(), cv.get());
            }
        }
        env->DeleteLocalRef(n);
        env->DeleteLocalRef(v);
        if (rc != 0) {
            kathttp3_request_destroy(req);
            return JNI_FALSE;
        }
    }
    if (body) {
        const jsize len = env->GetArrayLength(body);
        jbyte* data = len == 0 ? nullptr : env->GetByteArrayElements(body, nullptr);
        if (len != 0 && !data) {
            kathttp3_request_destroy(req);
            return JNI_FALSE;
        }
        const int rc = kathttp3_request_set_body(req, reinterpret_cast<uint8_t*>(data),
                                                 static_cast<size_t>(len));
        if (data) env->ReleaseByteArrayElements(body, data, JNI_ABORT);
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
    kathttp3_client_execute(client.get(), req, id, event_cb, state);
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_dev_kathttp3_internal_NativeBridge_consume(JNIEnv*, jobject, jlong h, jlong id, jlong bytes) {
    auto client = acquire_client(h);
    if (!client || bytes < 0) return JNI_FALSE;
    return kathttp3_client_consume_body(client.get(), id, static_cast<size_t>(bytes)) == KATHTTP3_OK
               ? JNI_TRUE
               : JNI_FALSE;
}

extern "C" JNIEXPORT jint JNICALL Java_dev_kathttp3_internal_NativeBridge_appendRequestBody(
    JNIEnv* env, jobject, jlong h, jlong id, jbyteArray data, jboolean finished) {
    auto client = acquire_client(h);
    if (!client) return KATHTTP3_ERR_CLOSED;
    const jsize len = data ? env->GetArrayLength(data) : 0;
    jbyte* bytes = data && len ? env->GetByteArrayElements(data, nullptr) : nullptr;
    if (data && len && !bytes) return KATHTTP3_ERR_NOMEM;
    const auto result = kathttp3_client_request_body_append(client.get(), id,
                                                            reinterpret_cast<const uint8_t*>(bytes),
                                                            static_cast<size_t>(len), finished);
    if (bytes) env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    return result;
}
