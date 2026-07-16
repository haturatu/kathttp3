#include "engine.h"

#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include "cert_verifier.h"
#include "cookie_jar.h"
#include "header_list.h"
#include "log.h"
#include "redirect.h"
#include "request.h"
#include "response.h"
#include "url.h"

namespace kathttp3 {

namespace {
constexpr int kDefaultMaxRedirects = 10;
constexpr uint32_t kDefaultMaxConnectionWorkers = 32;

int case_eq(const std::string& a, const char* b) {
    return strcasecmp(a.c_str(), b) == 0;
}

bool parse_content_length(std::string_view s, uint64_t& out) {
    if (s.empty()) return false;
    const char* begin = s.data();
    const char* end = begin + s.size();
    auto [parsed, error] = std::from_chars(begin, end, out);
    return error == std::errc{} && parsed == end;
}

void invoke_callback(kathttp3_event_callback callback, void* user_data, const kathttp3_event& event,
                     const char* context) noexcept {
    if (!callback) return;
    try {
        callback(user_data, &event);
    } catch (const std::exception& error) {
        KATHTTP3_LOG_WARN("request callback threw during %s: %s\n", context, error.what());
    } catch (...) {
        KATHTTP3_LOG_WARN("request callback threw during %s\n", context);
    }
}
}  // namespace

Engine::Engine(const kathttp3_client_options& opt)
    : opt_(opt),
      qlog_path_prefix_(opt.enable_qlog && opt.qlog_path_prefix ? opt.qlog_path_prefix : ""),
      qlog_sink_cb_(opt.enable_qlog ? opt.qlog_sink_cb : nullptr),
      qlog_sink_userdata_(opt.enable_qlog ? opt.qlog_sink_userdata : nullptr) {
    max_connection_workers_ =
        opt_.max_connection_workers ? opt_.max_connection_workers : kDefaultMaxConnectionWorkers;
    if (opt_.enable_qlog != 0 && qlog_path_prefix_.empty() && qlog_sink_cb_ == nullptr) {
        throw std::invalid_argument("qlog enabled without a destination");
    }
    if (opt.resolve_cb) {
        kathttp3_resolve_cb cb = opt.resolve_cb;
        void* ud = opt.resolve_cb_userdata;
        resolver_ = std::make_shared<CallbackResolver>(
            [cb, ud](const std::string& host, uint16_t port, const std::atomic<bool>*) {
                std::vector<ResolvedEndpoint> out;
                std::vector<kathttp3_resolved_address> buf(64);
                size_t n = buf.size();
                int rc = cb(host.c_str(), port, ud, buf.data(), &n);
                if (rc != 0) return out;
                out.reserve(n);
                for (size_t i = 0; i < n; ++i)
                    out.push_back({std::string(buf[i].ip), buf[i].port, buf[i].family});
                return out;
            });
    } else {
        resolver_ = std::make_shared<GetAddrInfoResolver>(android_network_handle_);
    }
    dns_cache_ = std::make_shared<DnsCache>();
    resolver_ =
        std::make_shared<CachedResolver>(resolver_, dns_cache_, resolver_network_generation_);
    if (!tls_ctx_.init(static_cast<kathttp3_trust_mode>(opt_.trust_mode), opt_.insecure_cert != 0,
                       opt_.ca_cert_file ? opt_.ca_cert_file : std::string(),
                       opt_.keylog_file ? opt_.keylog_file : std::string(),
                       platform_cert_verifier())) {
        throw std::runtime_error("TLS context initialization failed");
    }
    wakeup_fd_ = eventfd(0, EFD_NONBLOCK);
}

Engine::~Engine() {
    if (wakeup_fd_ != -1) close(wakeup_fd_);
}

void Engine::set_origin_policy(const std::string& tag) {
    std::lock_guard<std::mutex> lk(mtx_);
    policy_tag_ = tag;
}

void Engine::network_changed(uint64_t generation, uint64_t network_handle) {
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    if (destroyed_.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(pool_mutex_);
    if (generation <= network_generation_) return;
    network_generation_ = generation;
    android_network_handle_->store(network_handle, std::memory_order_release);
    resolver_network_generation_->store(generation, std::memory_order_release);
    dns_cache_->invalidate_network(generation);
    // Never destroy a worker from the Android callback thread. Each client
    // serializes migration or failure on its own QUIC event loop, preventing
    // consume/cancel callbacks from racing a freed raw registry pointer.
    for (auto& entry : pool_)
        entry.second->request_network_change({generation, NetworkHandle{network_handle}});
}

QuicClient* Engine::get_or_create_client(const Url& origin) {
    std::string key =
        policy_tag_ + "|" + origin.scheme + "://" + origin.host + ":" + std::to_string(origin.port);
    std::lock_guard<std::mutex> lk(pool_mutex_);
    auto it = pool_.find(key);
    if (it != pool_.end()) {
        // Reuse both Active and Connecting clients before any new client can
        // enqueue DNS. Requests arriving during a handshake stay on that
        // client's pending queue rather than starting duplicate resolution.
        if (!it->second->accepts_new_jobs()) {
            // erase the entry itself. Keeping an empty entry makes the
            // emplace below fail for this key, leaving us with a dangling
            // pointer to the just-destroyed replacement client.
            pool_.erase(it);
        } else {
            return it->second.get();
        }
    }
    // Each pooled origin owns a worker and a UDP socket. Reap closed entries
    // before enforcing a process-wide bound; never grow one worker per origin
    // without limit.
    for (auto candidate = pool_.begin(); candidate != pool_.end();) {
        if (candidate->second->is_closed())
            candidate = pool_.erase(candidate);
        else
            ++candidate;
    }
    if (pool_.size() >= max_connection_workers_) return nullptr;
    const QuicTimeouts timeouts{opt_.connect_timeout_ms,   opt_.request_timeout_ms,
                                opt_.idle_timeout_ms,      opt_.dns_timeout_ms,
                                opt_.handshake_timeout_ms, opt_.response_headers_timeout_ms,
                                opt_.read_timeout_ms,      opt_.write_timeout_ms,
                                opt_.call_timeout_ms,      opt_.consumer_stall_timeout_ms};
    auto qc = std::make_unique<QuicClient>(
        this, tls_ctx_, origin, resolver_, opt_.enable_0rtt != 0, timeouts, opt_.quic_version,
        qlog_path_prefix_, qlog_sink_cb_, qlog_sink_userdata_,
        android_network_handle_->load(std::memory_order_acquire),
        opt_.network_change_policy != KATHTTP3_NETWORK_CHANGE_CLOSE_AND_RECONNECT);
    QuicClient* p = qc.get();
    pool_.emplace(key, std::move(qc));
    return p;
}

void Engine::execute(kathttp3_request* req, int64_t request_id, kathttp3_event_callback cb,
                     void* user_data) {
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    if (destroyed_.load()) {
        kathttp3_event ev{};
        ev.type = KATHTTP3_EVENT_ERROR;
        ev.request_id = request_id;
        ev.error_code = KATHTTP3_ERR_CLOSED;
        invoke_callback(cb, user_data, ev, "closed client");
        delete req;
        return;
    }
    Url url;
    if (!parse_url(req->url, url)) {
        kathttp3_event ev{};
        ev.type = KATHTTP3_EVENT_ERROR;
        ev.request_id = request_id;
        ev.error_code = KATHTTP3_ERR_INVALID_ARG;
        invoke_callback(cb, user_data, ev, "invalid request");
        delete req;
        return;
    }
    if (opt_.enable_cookies) add_cookie_header(req, url);

    auto job = std::make_unique<Job>();
    job->id = request_id;
    job->request = req;
    job->url = url;
    job->streaming = req->streaming != 0;

    QuicClient* c = get_or_create_client(url);
    if (!c) {
        kathttp3_event ev{};
        ev.type = KATHTTP3_EVENT_ERROR;
        ev.request_id = request_id;
        ev.error_code = KATHTTP3_ERR_CONNECTION_LIMIT;
        invoke_callback(cb, user_data, ev, "connection-worker admission");
        delete req;
        return;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        registry_[request_id] = ReqEntry{cb, user_data, c, false, false, 0};
    }
    c->submit_job(std::move(job));
}

int Engine::consume(int64_t request_id, size_t bytes) {
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    QuicClient* c = nullptr;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = registry_.find(request_id);
        if (it == registry_.end() || it->second.terminal) return KATHTTP3_ERR_CLOSED;
        c = it->second.client;
    }
    return c ? c->consume(request_id, bytes) : KATHTTP3_ERR_CLOSED;
}

int Engine::append_request_body(int64_t request_id, const uint8_t* data, size_t len,
                                bool finished) {
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    QuicClient* c = nullptr;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const auto it = registry_.find(request_id);
        if (it == registry_.end() || it->second.terminal) return KATHTTP3_ERR_CLOSED;
        c = it->second.client;
    }
    return c ? c->append_request_body(request_id, data, len, finished) : KATHTTP3_ERR_CLOSED;
}

void Engine::cancel(int64_t request_id) {
    std::lock_guard<std::recursive_mutex> callback_lock(callback_mutex_);
    QuicClient* c = nullptr;
    kathttp3_event_callback cb = nullptr;
    void* ud = nullptr;
    {
        std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = registry_.find(request_id);
        if (it == registry_.end()) return;
        if (it->second.terminal) return;
        it->second.cancelled = true;
        it->second.terminal = true;
        c = it->second.client;
        cb = it->second.cb;
        ud = it->second.user_data;
        registry_.erase(it);
        if (c) c->cancel_job(request_id);
    }
    kathttp3_event ev{};
    ev.type = KATHTTP3_EVENT_ERROR;
    ev.request_id = request_id;
    ev.error_code = KATHTTP3_ERR_CANCELLED;
    /* This ends caller ownership immediately; the worker subsequently owns
     * the asynchronous RESET_STREAM/STOP_SENDING cleanup. */
    invoke_callback(cb, ud, ev, "cancellation");
}

void Engine::destroy() {
    std::unique_lock<std::mutex> lifecycle(lifecycle_mutex_);
    if (destroyed_.exchange(true)) return;
    std::vector<std::unique_ptr<QuicClient>> clients;
    {
        std::lock_guard<std::mutex> lk(pool_mutex_);
        for (auto& kv : pool_) clients.push_back(std::move(kv.second));
        pool_.clear();
    }
    // Keep lifecycle exclusion while workers are joined. consume(), request
    // body append and cancel otherwise could fetch a registry raw pointer and
    // call it while this vector destroys the owning QuicClient.
    clients.clear();

    std::vector<std::pair<int64_t, kathttp3_event_callback>> pending;
    std::vector<void*> pending_ud;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto& kv : registry_) {
            if (kv.second.terminal || kv.second.cancelled) continue;
            kv.second.terminal = true;
            pending.push_back({kv.first, kv.second.cb});
            pending_ud.push_back(kv.second.user_data);
        }
        registry_.clear();
    }
    lifecycle.unlock();
    for (size_t i = 0; i < pending.size(); ++i) {
        if (!pending[i].second) continue;
        std::lock_guard<std::recursive_mutex> callback_lock(callback_mutex_);
        kathttp3_event ev{};
        ev.type = KATHTTP3_EVENT_ERROR;
        ev.request_id = pending[i].first;
        ev.error_code = KATHTTP3_ERR_CLOSED;
        invoke_callback(pending[i].second, pending_ud[i], ev, "client close");
    }
}

void Engine::on_job_headers(Job* job, int status, const HeaderList& headers) {
    // Redirect handling (RFC 9114 allows 3xx to be followed).
    if (status / 100 == 3 && status != 304 && job->request->follow_redirects) {
        Response tmp;
        tmp.status_code = status;
        tmp.headers = headers;
        RedirectPolicy policy;
        RedirectDecision dec = policy.evaluate(job->request->method, job->url, tmp, true,
                                               kDefaultMaxRedirects - job->redirect_count);
        if (dec.follow && !dec.new_url.empty()) {
            Url new_url;
            if (parse_url(dec.new_url, new_url) && new_url.valid()) {
                if (opt_.enable_cookies) store_cookies(job->url, headers);
                // Mark the current hop so its own completion is ignored.
                job->redirected = true;

                auto* nr = new kathttp3_request;
                nr->method = dec.new_method;
                nr->url = new_url.to_string();
                for (const auto& header : job->request->headers.all()) {
                    const bool sensitive = case_eq(header.name, "authorization") ||
                                           case_eq(header.name, "proxy-authorization") ||
                                           case_eq(header.name, "cookie") ||
                                           case_eq(header.name, "host");
                    const bool body_header = case_eq(header.name, "content-length") ||
                                             case_eq(header.name, "content-type") ||
                                             case_eq(header.name, "content-encoding");
                    if ((dec.cross_origin && sensitive) ||
                        ((nr->method == "GET" || nr->method == "HEAD") && body_header))
                        continue;
                    nr->headers.add(header.name, header.value);
                }
                if (nr->method == "GET" || nr->method == "HEAD") {
                    nr->body.clear();
                } else {
                    nr->body = job->request->body;
                }
                nr->follow_redirects = 1;

                if (opt_.enable_cookies) add_cookie_header(nr, new_url);

                auto njob = std::make_unique<Job>();
                njob->id = job->id;
                njob->request = nr;
                njob->url = new_url;
                njob->redirect_count = job->redirect_count + 1;

                QuicClient* nc = get_or_create_client(new_url);
                if (!nc) {
                    on_job_error(job, KATHTTP3_ERR_CONNECTION_LIMIT,
                                 "connection-worker admission limit");
                    return;
                }
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    auto it = registry_.find(job->id);
                    if (it != registry_.end()) {
                        it->second.client = nc;
                        it->second.redirect_count = njob->redirect_count;
                    }
                }
                nc->submit_job(std::move(njob));
                return;
            }
        }
    }

    if (opt_.enable_cookies) store_cookies(job->url, headers);
    // RFC 9110: repeated Content-Length is legal only if every field-value is
    // exactly the same valid decimal value.  Do this before exposing headers.
    bool saw_content_length = false;
    uint64_t content_length = 0;
    for (const auto& header : headers.list()) {
        if (!case_eq(header.name, "content-length")) continue;
        uint64_t value = 0;
        if (!parse_content_length(header.value, value) ||
            (saw_content_length && value != content_length) ||
            value > static_cast<uint64_t>(INT64_MAX)) {
            on_job_error(job, KATHTTP3_ERR_BODY, "invalid Content-Length");
            return;
        }
        saw_content_length = true;
        content_length = value;
    }
    if (saw_content_length) job->declared_content_length = static_cast<int64_t>(content_length);
    dispatch_headers(job, status, headers);
}

void Engine::on_job_body(Job* job, const uint8_t* data, size_t len) {
    job->received_body_bytes += len;
    dispatch_body(job, data, len);
}

void Engine::on_job_complete(Job* job) {
    if (job->redirected) return;  // intermediate redirect hop
    if (job->declared_content_length >= 0) {
        int st = job->response.status_code;
        bool exempt = (job->request->method == "HEAD") || st == 204 || st == 304 || (st / 100 == 1);
        if (!exempt &&
            job->received_body_bytes != static_cast<uint64_t>(job->declared_content_length)) {
            kathttp3_event ev{};
            ev.type = KATHTTP3_EVENT_ERROR;
            ev.request_id = job->id;
            ev.error_code = KATHTTP3_ERR_BODY;
            deliver(ev);
            return;
        }
    }
    dispatch_complete(job);
}

void Engine::on_job_error(Job* job, int err, const char* msg) {
    (void)msg;
    if (job->redirected) return;
    dispatch_error(job, err, msg ? msg : "request failed");
}

void Engine::dispatch_headers(Job* job, int status, const HeaderList& headers) {
    std::vector<const char*> names, values;
    for (const auto& h : headers.list()) {
        names.push_back(h.name.c_str());
        values.push_back(h.value.c_str());
    }
    kathttp3_event ev{};
    ev.type = KATHTTP3_EVENT_HEADERS;
    ev.request_id = job->id;
    ev.status_code = status;
    ev.names = names.data();
    ev.values = values.data();
    ev.header_count = names.size();
    deliver(ev);
}

void Engine::dispatch_body(Job* job, const uint8_t* data, size_t len) {
    kathttp3_event ev{};
    ev.type = KATHTTP3_EVENT_BODY;
    ev.request_id = job->id;
    ev.data = data;
    ev.data_len = len;
    deliver(ev);
}

void Engine::dispatch_complete(Job* job) {
    kathttp3_event ev{};
    ev.type = KATHTTP3_EVENT_COMPLETE;
    ev.request_id = job->id;
    ev.error_code = 0;
    deliver(ev);
}

void Engine::dispatch_error(Job* job, int err, const char* msg) {
    kathttp3_event ev{};
    ev.type = KATHTTP3_EVENT_ERROR;
    ev.request_id = job->id;
    ev.error_code = err;
    (void)msg;
    deliver(ev);
}

void Engine::deliver(const kathttp3_event& ev) {
    std::lock_guard<std::recursive_mutex> callback_lock(callback_mutex_);
    ReqEntry e;
    kathttp3_event_callback cb = nullptr;
    void* ud = nullptr;
    bool terminal = (ev.type == KATHTTP3_EVENT_COMPLETE || ev.type == KATHTTP3_EVENT_ERROR);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = registry_.find(ev.request_id);
        if (it == registry_.end()) return;
        e = it->second;
        if (e.terminal) return;
        if (e.cancelled) {
            registry_.erase(it);
            return;
        }
        if (terminal) it->second.terminal = true;
        cb = e.cb;
        ud = e.user_data;
    }
    invoke_callback(cb, ud, ev, terminal ? "terminal delivery" : "event delivery");
    if (terminal) {
        std::lock_guard<std::mutex> lk(mtx_);
        registry_.erase(ev.request_id);
    }
}

void Engine::add_cookie_header(kathttp3_request* req, const Url& url) {
    std::string cookie = cookie_jar_.cookie_header(url);
    if (cookie.empty()) return;
    bool has = false;
    for (const auto& h : req->headers.list()) {
        if (case_eq(h.name, "cookie")) {
            has = true;
            break;
        }
    }
    if (!has) req->headers.add("cookie", cookie);
}

void Engine::store_cookies(const Url& url, const HeaderList& headers) {
    cookie_jar_.store(url, headers);
}

} /* namespace kathttp3 */

/* ------------------------------------------------------------------ *
 * C ABI
 * ------------------------------------------------------------------ */
extern "C" {

void kathttp3_client_options_init(kathttp3_client_options* opt) {
    if (!opt) return;
    std::memset(opt, 0, sizeof(*opt));
    opt->struct_size = sizeof(kathttp3_client_options);
    opt->abi_version = KATHTTP3_ABI_VERSION;
    opt->connect_timeout_ms = 10000;
    opt->request_timeout_ms = 30000;
    opt->idle_timeout_ms = 30000;
    opt->max_redirects = 10;
    opt->max_connections_per_origin = 1;
    opt->enable_0rtt = 1;
    opt->verify_cert = 1;
    opt->insecure_cert = 0;
    opt->trust_mode = KATHTTP3_TRUST_PLATFORM;
    opt->dns_timeout_ms = opt->connect_timeout_ms;
    opt->handshake_timeout_ms = opt->connect_timeout_ms;
    opt->response_headers_timeout_ms = opt->request_timeout_ms;
    opt->read_timeout_ms = opt->idle_timeout_ms;
    opt->write_timeout_ms = opt->idle_timeout_ms;
    opt->call_timeout_ms = opt->request_timeout_ms;
    opt->consumer_stall_timeout_ms = opt->read_timeout_ms;
    opt->enable_qlog = 0;
    opt->max_connection_workers = 32;
    opt->network_change_policy = KATHTTP3_NETWORK_CHANGE_ATTEMPT_MIGRATION;
}

void kathttp3_client_config_init(kathttp3_client_config* config) {
    kathttp3_client_options_init(config);
}

uint32_t kathttp3_api_version(void) {
    return KATHTTP3_ABI_VERSION;
}

kathttp3_client* kathttp3_client_create(const kathttp3_client_options* options) {
    if (!options) return nullptr;
    constexpr size_t kRequiredOptionsSize =
        offsetof(kathttp3_client_options, resolve_cb_userdata) + sizeof(void*);
    if (options->struct_size < kRequiredOptionsSize) return nullptr;
    if (options->abi_version != KATHTTP3_ABI_VERSION_CURRENT) return nullptr;
    try {
        kathttp3_client_options normalized;
        kathttp3_client_options_init(&normalized);
        std::memcpy(&normalized, options,
                    std::min<size_t>(options->struct_size, sizeof(normalized)));
        auto* e = new kathttp3::Engine(normalized);
        return reinterpret_cast<kathttp3_client*>(e);
    } catch (...) {
        KATHTTP3_LOG_ERR("kathttp3_client_create caught a native exception\n");
        return nullptr;
    }
}

void kathttp3_client_destroy(kathttp3_client* client) {
    if (!client) return;
    try {
        auto* e = reinterpret_cast<kathttp3::Engine*>(client);
        e->destroy();
        delete e;
    } catch (...) {
        KATHTTP3_LOG_WARN("kathttp3_client_destroy caught a native exception\n");
    }
}

void kathttp3_client_close(kathttp3_client* client) {
    if (!client) return;
    try {
        reinterpret_cast<kathttp3::Engine*>(client)->destroy();
    } catch (...) {
        KATHTTP3_LOG_WARN("kathttp3_client_close caught a native exception\n");
    }
}

void kathttp3_client_set_origin_policy(kathttp3_client* client, const char* policy_tag) {
    if (!client) return;
    try {
        reinterpret_cast<kathttp3::Engine*>(client)->set_origin_policy(policy_tag ? policy_tag
                                                                                  : "");
    } catch (...) {
        KATHTTP3_LOG_WARN("kathttp3_client_set_origin_policy caught a native exception\n");
    }
}

void kathttp3_client_network_changed(kathttp3_client* client, uint64_t generation) {
    kathttp3_client_network_changed2(client, generation, 0);
}

void kathttp3_client_network_changed2(kathttp3_client* client, uint64_t generation,
                                      uint64_t network_handle) {
    if (!client) return;
    try {
        reinterpret_cast<kathttp3::Engine*>(client)->network_changed(generation, network_handle);
    } catch (...) {
        KATHTTP3_LOG_WARN("kathttp3_client_network_changed2 caught a native exception\n");
    }
}

void kathttp3_client_execute(kathttp3_client* client, kathttp3_request* request, int64_t request_id,
                             kathttp3_event_callback cb, void* user_data) {
    if (!client || !request) {
        delete request;
        return;
    }
    try {
        reinterpret_cast<kathttp3::Engine*>(client)->execute(request, request_id, cb, user_data);
    } catch (...) {
        KATHTTP3_LOG_ERR("kathttp3_client_execute caught a native exception; reporting OOM\n");
        kathttp3_event ev{};
        ev.type = KATHTTP3_EVENT_ERROR;
        ev.request_id = request_id;
        ev.error_code = KATHTTP3_ERR_NOMEM;
        if (cb) cb(user_data, &ev);
        delete request;
    }
}

void kathttp3_client_cancel(kathttp3_client* client, int64_t request_id) {
    if (!client) return;
    try {
        reinterpret_cast<kathttp3::Engine*>(client)->cancel(request_id);
    } catch (...) {
        KATHTTP3_LOG_WARN("kathttp3_client_cancel caught a native exception\n");
    }
}

void kathttp3_client_consume(kathttp3_client* client, int64_t request_id, size_t bytes) {
    if (!client) return;
    try {
        (void)reinterpret_cast<kathttp3::Engine*>(client)->consume(request_id, bytes);
    } catch (...) {
        KATHTTP3_LOG_WARN("kathttp3_client_consume caught a native exception\n");
    }
}

kathttp3_error kathttp3_client_consume_body(kathttp3_client* client, int64_t request_id,
                                            size_t bytes) {
    if (!client) return KATHTTP3_ERR_INVALID_ARG;
    try {
        return static_cast<kathttp3_error>(
            reinterpret_cast<kathttp3::Engine*>(client)->consume(request_id, bytes));
    } catch (...) {
        KATHTTP3_LOG_WARN(
            "kathttp3_client_consume_body caught a native exception; reporting closed\n");
        return KATHTTP3_ERR_CLOSED;
    }
}

kathttp3_error kathttp3_client_request_body_append(kathttp3_client* client, int64_t request_id,
                                                   const uint8_t* data, size_t len, int finished) {
    if (!client || (!data && len)) return KATHTTP3_ERR_INVALID_ARG;
    try {
        return static_cast<kathttp3_error>(
            reinterpret_cast<kathttp3::Engine*>(client)->append_request_body(request_id, data, len,
                                                                             finished != 0));
    } catch (...) {
        KATHTTP3_LOG_WARN(
            "kathttp3_client_request_body_append caught a native exception; reporting OOM\n");
        return KATHTTP3_ERR_NOMEM;
    }
}

} /* extern "C" */
