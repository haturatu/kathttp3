#ifndef KATHTTP_ENGINE_H
#define KATHTTP_ENGINE_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "cookie_jar.h"
#include "dns.h"
#include "kathttp.h"
#include "quic_client.h"
#include "tls.h"

struct kathttp_request;

namespace kathttp {

class QuicClient;

/* Owns the connection pool, the per-request registry, the TLS context
 * and the cookie jar. Implements the kathttp_client C ABI surface. */
class Engine {
   public:
    explicit Engine(const kathttp_client_options& opt);
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    void set_origin_policy(const std::string& tag);

    void execute(kathttp_request* req, int64_t request_id, kathttp_event_callback cb,
                 void* user_data);
    void cancel(int64_t request_id);
    int consume(int64_t request_id, size_t bytes);
    void destroy();

    /* Called from QuicClient worker threads. */
    void on_job_headers(Job* job, int status, const HeaderList& headers);
    void on_job_body(Job* job, const uint8_t* data, size_t len);
    void on_job_complete(Job* job);
    void on_job_error(Job* job, int err, const char* msg);

   private:
    std::mutex lifecycle_mutex_;
    std::recursive_mutex callback_mutex_;
    struct ReqEntry {
        kathttp_event_callback cb = nullptr;
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
    void add_cookie_header(kathttp_request* req, const Url& url);
    void store_cookies(const Url& url, const HeaderList& headers);
    void deliver(const kathttp_event& ev);

    std::mutex mtx_; /* serializes registry access and event delivery */
    std::unordered_map<int64_t, ReqEntry> registry_;

    std::mutex pool_mutex_;
    std::unordered_map<std::string, std::unique_ptr<QuicClient>> pool_;

    std::string policy_tag_;
    kathttp_client_options opt_{};
    std::shared_ptr<Resolver> resolver_;
    TlsClientContext tls_ctx_;
    CookieJar cookie_jar_;
    int wakeup_fd_ = -1;
    std::atomic<bool> destroyed_{false};
};

} /* namespace kathttp */

#endif /* KATHTTP_ENGINE_H */
