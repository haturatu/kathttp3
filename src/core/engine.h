#ifndef KATHTTP3_ENGINE_H
#define KATHTTP3_ENGINE_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "cookie_jar.h"
#include "dns.h"
#include "kathttp3.h"
#include "quic_client.h"
#include "response_cache.h"
#include "tls.h"

struct kathttp3_request;

namespace kathttp3 {

class QuicClient;
class EngineTestAccess;

/* Owns the connection pool, the per-request registry, the TLS context
 * and the cookie jar. Implements the kathttp3_client C ABI surface. */
class Engine {
   public:
    explicit Engine(const kathttp3_client_options& opt);
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    void set_origin_policy(const std::string& tag);

    void execute(kathttp3_request* req, int64_t request_id, kathttp3_event_callback cb,
                 void* user_data);
    void cancel(int64_t request_id);
    int consume(int64_t request_id, size_t bytes);
    int append_request_body(int64_t request_id, const uint8_t* data, size_t len, bool finished);
    void destroy();
    void network_changed(uint64_t generation, uint64_t network_handle);

    /* Called from QuicClient worker threads. */
    void on_job_headers(Job* job, int status, const HeaderList& headers);
    void on_job_body(Job* job, const uint8_t* data, size_t len);
    void on_job_complete(Job* job);
    void on_job_error(Job* job, int err, const char* msg);
    /* Called from the Engine-owned callback dispatcher. */
    void on_job_cached(Job* job);

   private:
    friend class EngineTestAccess;

    std::mutex lifecycle_mutex_;
    std::recursive_mutex callback_mutex_;
    struct ReqEntry {
        kathttp3_event_callback cb = nullptr;
        void* user_data = nullptr;
        QuicClient* client = nullptr;
        bool cancelled = false;
        bool terminal = false;
        int redirect_count = 0;
    };

    QuicClient* get_or_create_client(const Url& origin);
    void dispatch_headers(Job* job, int status, const HeaderList& headers);
    void dispatch_body(Job* job, const uint8_t* data, size_t len);
    void dispatch_complete(Job* job);
    void dispatch_error(Job* job, int err, const char* msg);
    void add_cookie_header(kathttp3_request* req, const Url& url);
    void store_cookies(const Url& url, const HeaderList& headers);
    void prepare_cache(Job* job);
    void add_cache_validator(Job* job, const CachedResponse& response);
    void deliver_cached(Job* job, const CachedResponse& response);
    bool queue_cached_job(std::unique_ptr<Job>& job);
    void remove_queued_cached_job(int64_t request_id);
    void run_cached_dispatcher();
    void stop_cached_dispatcher();
    void store_job_response(Job* job);
    void invalidate_cache_validation(Job* job);
    void invalidate_after_unsafe_request(Job* job, const HeaderList& headers);
    void deliver(const kathttp3_event& ev);

    std::mutex mtx_; /* serializes registry access and event delivery */
    std::unordered_map<int64_t, ReqEntry> registry_;

    std::mutex pool_mutex_;
    std::unordered_map<std::string, std::unique_ptr<QuicClient>> pool_;
    uint32_t max_connection_workers_ = 32;

    std::string policy_tag_;
    uint64_t network_generation_ = 0;
    std::shared_ptr<std::atomic<uint64_t>> resolver_network_generation_ =
        std::make_shared<std::atomic<uint64_t>>(0);
    std::shared_ptr<std::atomic<uint64_t>> android_network_handle_ =
        std::make_shared<std::atomic<uint64_t>>(0);
    kathttp3_client_options opt_{};
    std::string qlog_path_prefix_;
    kathttp3_qlog_sink_cb qlog_sink_cb_ = nullptr;
    void* qlog_sink_userdata_ = nullptr;
    std::shared_ptr<Resolver> resolver_;
    std::shared_ptr<DnsCache> dns_cache_;
    std::shared_ptr<ResponseCache> http_cache_;
    size_t cache_max_entry_bytes_ = 4 * 1024 * 1024;
    std::mutex cache_dispatch_mutex_;
    std::condition_variable cache_dispatch_cv_;
    std::deque<std::unique_ptr<Job>> cache_dispatch_jobs_;
    static constexpr size_t kMaxQueuedCachedJobs = 128;
    size_t cache_dispatch_max_bytes_ = 32 * 1024 * 1024;
    size_t cache_dispatch_queued_bytes_ = 0;
    std::thread cache_dispatch_thread_;
    bool cache_dispatch_stop_ = false;
    TlsClientContext tls_ctx_;
    CookieJar cookie_jar_;
    int wakeup_fd_ = -1;
    std::atomic<bool> destroyed_{false};
};

} /* namespace kathttp3 */

#endif /* KATHTTP3_ENGINE_H */
