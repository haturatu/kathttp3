#include <jni.h>
#include <atomic>
#include <mutex>
#include <unordered_set>
#include <vector>
#include "android_cert_verifier.h"
#include "cert_verifier.h"
#include "kathttp.h"

namespace {
JavaVM *g_vm = nullptr;
std::mutex g_handles_mutex;
std::unordered_set<kathttp_client *> g_handles;

class EnvScope {
 public:
  EnvScope() { if (g_vm->GetEnv(reinterpret_cast<void **>(&env_), JNI_VERSION_1_6) != JNI_OK) {
#ifdef __ANDROID__
    if (g_vm->AttachCurrentThread(&env_, nullptr) == JNI_OK) attached_ = true; else env_ = nullptr;
#else
    if (g_vm->AttachCurrentThread(reinterpret_cast<void **>(&env_), nullptr) == JNI_OK) attached_ = true; else env_ = nullptr;
#endif
  } }
  ~EnvScope() { if (attached_) g_vm->DetachCurrentThread(); }
  JNIEnv *get() const { return env_; }
 private: JNIEnv *env_ = nullptr; bool attached_ = false;
};

struct CallbackState {
  jobject callback = nullptr;
  std::atomic<bool> terminal{false};
};

kathttp_client *checked(jlong value) {
  auto *p = reinterpret_cast<kathttp_client *>(static_cast<uintptr_t>(value));
  std::lock_guard<std::mutex> lock(g_handles_mutex);
  return g_handles.count(p) ? p : nullptr;
}

void release_state(JNIEnv *env, CallbackState *state) {
  if (!state) return;
  if (state->callback) env->DeleteGlobalRef(state->callback);
  delete state;
}

void event_cb(void *opaque, const kathttp_event *event) noexcept {
  auto *state = static_cast<CallbackState *>(opaque);
  if (!state || !event || state->terminal.load(std::memory_order_acquire)) return;
  EnvScope scope; JNIEnv *env = scope.get(); if (!env) return;
  jclass cls = env->GetObjectClass(state->callback);
  if (!cls) { env->ExceptionClear(); return; }
  if (event->type == KATHTTP_EVENT_HEADERS) {
    jclass str = env->FindClass("java/lang/String");
    jobjectArray names = env->NewObjectArray(event->header_count, str, nullptr);
    jobjectArray values = env->NewObjectArray(event->header_count, str, nullptr);
    for (size_t i = 0; i < event->header_count && !env->ExceptionCheck(); ++i) {
      jstring n = env->NewStringUTF(event->names[i]); jstring v = env->NewStringUTF(event->values[i]);
      env->SetObjectArrayElement(names, i, n); env->SetObjectArrayElement(values, i, v); env->DeleteLocalRef(n); env->DeleteLocalRef(v);
    }
    jmethodID mid = env->GetMethodID(cls, "onHeaders", "(I[Ljava/lang/String;[Ljava/lang/String;)V");
    if (mid) env->CallVoidMethod(state->callback, mid, event->status_code, names, values);
    env->DeleteLocalRef(names); env->DeleteLocalRef(values);
  } else if (event->type == KATHTTP_EVENT_BODY) {
    jbyteArray data = env->NewByteArray(event->data_len);
    if (data) env->SetByteArrayRegion(data, 0, event->data_len, reinterpret_cast<const jbyte *>(event->data));
    jmethodID mid = env->GetMethodID(cls, "onBody", "([B)V"); if (mid && data) env->CallVoidMethod(state->callback, mid, data);
    if (data) env->DeleteLocalRef(data);
  } else {
    if (!state->terminal.exchange(true, std::memory_order_acq_rel)) {
      const char *name = event->type == KATHTTP_EVENT_COMPLETE ? "onComplete" : "onError";
      const char *sig = event->type == KATHTTP_EVENT_COMPLETE ? "()V" : "(I)V";
      jmethodID mid = env->GetMethodID(cls, name, sig);
      if (mid) { if (event->type == KATHTTP_EVENT_COMPLETE) env->CallVoidMethod(state->callback, mid); else env->CallVoidMethod(state->callback, mid, event->error_code); }
      if (env->ExceptionCheck()) env->ExceptionClear();
      env->DeleteLocalRef(cls); release_state(env, state); return;
    }
  }
  if (env->ExceptionCheck()) env->ExceptionClear();
  env->DeleteLocalRef(cls);
}
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
  g_vm = vm;
  // Build the platform (Android) certificate verifier and register it so
  // the core uses X509TrustManager for TRUST_PLATFORM.
  if (auto *v = kathttp::create_android_platform_verifier(vm)) {
    kathttp::set_platform_cert_verifier(v);
  }
  return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jlong JNICALL Java_dev_kathttp_internal_NativeBridge_createClient(JNIEnv *env, jobject, jlong connect, jlong request, jlong idle, jint redirects, jint trustMode, jboolean insecure, jstring caFile) {
  kathttp_client_options o; kathttp_client_options_init(&o); o.connect_timeout_ms=connect; o.request_timeout_ms=request; o.idle_timeout_ms=idle; o.max_redirects=redirects;
  o.trust_mode = static_cast<uint32_t>(trustMode); o.insecure_cert = insecure ? 1 : 0;
  const char *ca = caFile ? env->GetStringUTFChars(caFile, nullptr) : nullptr; if (caFile && !ca) return 0; o.ca_cert_file = ca;
  auto *p=kathttp_client_create(&o); if (ca) env->ReleaseStringUTFChars(caFile, ca); if (p) { try { std::lock_guard<std::mutex> lock(g_handles_mutex); g_handles.insert(p); } catch (...) { kathttp_client_destroy(p); return 0; } } return static_cast<jlong>(reinterpret_cast<uintptr_t>(p));
}
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp_internal_NativeBridge_closeClient(JNIEnv *, jobject, jlong h) { std::lock_guard<std::mutex> lock(g_handles_mutex); auto *p=reinterpret_cast<kathttp_client *>(static_cast<uintptr_t>(h)); if (g_handles.count(p)) kathttp_client_close(p); }
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp_internal_NativeBridge_destroyClient(JNIEnv *, jobject, jlong h) { auto *p=reinterpret_cast<kathttp_client *>(static_cast<uintptr_t>(h)); { std::lock_guard<std::mutex> lock(g_handles_mutex); if (!g_handles.erase(p)) return; } kathttp_client_destroy(p); }
extern "C" JNIEXPORT void JNICALL Java_dev_kathttp_internal_NativeBridge_cancel(JNIEnv *, jobject, jlong h, jlong id) { std::lock_guard<std::mutex> lock(g_handles_mutex); auto *p=reinterpret_cast<kathttp_client *>(static_cast<uintptr_t>(h)); if (g_handles.count(p)) kathttp_client_cancel(p,id); }

extern "C" JNIEXPORT jboolean JNICALL Java_dev_kathttp_internal_NativeBridge_execute(JNIEnv *env, jobject, jlong h, jlong id, jstring method, jstring url, jobjectArray names, jobjectArray values, jbyteArray body, jboolean redirects, jobject callback) {
  std::lock_guard<std::mutex> handle_lock(g_handles_mutex);
  auto *client=reinterpret_cast<kathttp_client *>(static_cast<uintptr_t>(h)); if (!g_handles.count(client) || !method || !url || !callback) return JNI_FALSE;
  const char *m=env->GetStringUTFChars(method,nullptr); const char *u=env->GetStringUTFChars(url,nullptr);
  kathttp_request *req=kathttp_request_create(m,u); env->ReleaseStringUTFChars(method,m); env->ReleaseStringUTFChars(url,u); if (!req) return JNI_FALSE;
  jsize count=names?env->GetArrayLength(names):0; if (!values || env->GetArrayLength(values)!=count) { kathttp_request_destroy(req); return JNI_FALSE; }
  for (jsize i=0;i<count;i++) { auto n=(jstring)env->GetObjectArrayElement(names,i); auto v=(jstring)env->GetObjectArrayElement(values,i); const char *cn=env->GetStringUTFChars(n,nullptr); const char *cv=env->GetStringUTFChars(v,nullptr); int rc=kathttp_request_add_header(req,cn,cv); env->ReleaseStringUTFChars(n,cn); env->ReleaseStringUTFChars(v,cv); env->DeleteLocalRef(n); env->DeleteLocalRef(v); if(rc!=0){kathttp_request_destroy(req);return JNI_FALSE;} }
  if(body){ jsize len=env->GetArrayLength(body); jbyte *data=env->GetByteArrayElements(body,nullptr); int rc=kathttp_request_set_body(req,reinterpret_cast<uint8_t*>(data),len); env->ReleaseByteArrayElements(body,data,JNI_ABORT); if(rc!=0){kathttp_request_destroy(req);return JNI_FALSE;} }
  kathttp_request_set_follow_redirects(req, redirects);
  auto *state=new(std::nothrow) CallbackState; if(!state){kathttp_request_destroy(req);return JNI_FALSE;} state->callback=env->NewGlobalRef(callback); if(!state->callback){delete state;kathttp_request_destroy(req);return JNI_FALSE;}
  kathttp_client_execute(client,req,id,event_cb,state); return JNI_TRUE;
}
