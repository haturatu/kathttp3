#include "engine.h"

#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
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

namespace kathttp {

namespace {
constexpr int kDefaultMaxRedirects = 10;

int case_eq(const std::string& a, const char* b) {
    return strcasecmp(a.c_str(), b) == 0;
}

/* Parse the first non-negative integer found in a header value (e.g. the
 * leading number of a "Content-Length: 1234" field, ignoring junk/weight). */
bool parse_leading_uint(std::string_view s, uint64_t& out) {
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    if (i >= s.size() || s[i] < '0' || s[i] > '9') return false;
    uint64_t v = 0;
    for (; i < s.size() && s[i] >= '0' && s[i] <= '9'; ++i) {
        v = v * 10 + static_cast<uint64_t>(s[i] - '0');
    }
    out = v;
    return true;
}
}  // namespace

Engine::Engine(const kathttp_client_options& opt) : opt_(opt) {
    if (opt.resolve_cb) {
        kathttp_resolve_cb cb = opt.resolve_cb;
        void* ud = opt.resolve_cb_userdata;
        resolver_ = std::make_shared<CallbackResolver>(
            [cb, ud](const std::string& host, uint16_t port, const std::atomic<bool>*) {
                std::vector<ResolvedEndpoint> out;
                std::vector<kathttp_resolved_address> buf(64);
                size_t n = buf.size();
                int rc = cb(host.c_str(), port, ud, buf.data(), &n);
                if (rc != 0) return out;
                out.reserve(n);
                for (size_t i = 0; i < n; ++i)
                    out.push_back({std::string(buf[i].ip), buf[i].port, buf[i].family});
                return out;
            });
    } else {
        resolver_ = std::make_shared<GetAddrInfoResolver>();
    }
    if (!tls_ctx_.init(static_cast<kathttp_trust_mode>(opt_.trust_mode), opt_.insecure_cert != 0,
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

QuicClient* Engine::get_or_create_client(const Url& origin) {
    std::string key =
        policy_tag_ + "|" + origin.scheme + "://" + origin.host + ":" + std::to_string(origin.port);
    std::lock_guard<std::mutex> lk(pool_mutex_);
    auto it = pool_.find(key);
    if (it != pool_.end()) {
        if (it->second->is_closed()) {
            it->second.reset();
        } else {
            return it->second.get();
        }
    }
    auto qc = std::make_unique<QuicClient>(this, tls_ctx_, origin, resolver_, opt_.enable_0rtt != 0,
                                           opt_.connect_timeout_ms, opt_.request_timeout_ms,
                                           opt_.idle_timeout_ms, opt_.dns_timeout_ms,
                                           opt_.handshake_timeout_ms,
                                           opt_.response_headers_timeout_ms, opt_.read_timeout_ms,
                                           opt_.write_timeout_ms, opt_.call_timeout_ms,
                                           opt_.quic_version);
    QuicClient* p = qc.get();
    pool_.emplace(key, std::move(qc));
    return p;
}

void Engine::execute(kathttp_request* req, int64_t request_id, kathttp_event_callback cb,
                     void* user_data) {
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    if (destroyed_.load()) {
        kathttp_event ev{};
        ev.type = KATHTTP_EVENT_ERROR;
        ev.request_id = request_id;
        ev.error_code = KATHTTP_ERR_CLOSED;
        if (cb) {
            try {
                cb(user_data, &ev);
            } catch (...) {
            }
        }
        delete req;
        return;
    }
    Url url;
    if (!parse_url(req->url, url)) {
        kathttp_event ev{};
        ev.type = KATHTTP_EVENT_ERROR;
        ev.request_id = request_id;
        ev.error_code = KATHTTP_ERR_INVALID_ARG;
        if (cb) cb(user_data, &ev);
        delete req;
        return;
    }
    add_cookie_header(req, url);

    auto job = std::make_unique<Job>();
    job->id = request_id;
    job->request = req;
    job->url = url;
    job->streaming = req->streaming != 0;

    QuicClient* c = get_or_create_client(url);
    {
        std::lock_guard<std::mutex> lk(mtx_);
        registry_[request_id] = ReqEntry{cb, user_data, c, false, false, 0};
    }
    c->submit_job(std::move(job));
}

void Engine::consume(int64_t request_id, size_t bytes) {
    QuicClient* c = nullptr;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = registry_.find(request_id);
        if (it == registry_.end()) return;
        c = it->second.client;
    }
    if (c) c->consume(request_id, bytes);
}

void Engine::cancel(int64_t request_id) {
    std::lock_guard<std::recursive_mutex> callback_lock(callback_mutex_);
    QuicClient* c = nullptr;
    kathttp_event_callback cb = nullptr;
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
    if (cb) {
        kathttp_event ev{};
        ev.type = KATHTTP_EVENT_ERROR;
        ev.request_id = request_id;
        ev.error_code = KATHTTP_ERR_CANCELLED;
        cb(ud, &ev);
    }
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
    lifecycle.unlock();
    // clients are destructed (threads joined) when `clients` leaves scope.
    clients.clear();

    std::vector<std::pair<int64_t, kathttp_event_callback>> pending;
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
    for (size_t i = 0; i < pending.size(); ++i) {
        if (!pending[i].second) continue;
        std::lock_guard<std::recursive_mutex> callback_lock(callback_mutex_);
        kathttp_event ev{};
        ev.type = KATHTTP_EVENT_ERROR;
        ev.request_id = pending[i].first;
        ev.error_code = KATHTTP_ERR_CLOSED;
        pending[i].second(pending_ud[i], &ev);
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
                store_cookies(job->url, headers);
                // Mark the current hop so its own completion is ignored.
                job->redirected = true;

                auto* nr = new kathttp_request;
                nr->method = dec.new_method;
                nr->url = new_url.to_string();
                if (nr->method == "GET" || nr->method == "HEAD") {
                    nr->body.clear();
                } else {
                    nr->body = job->request->body;
                }
                nr->follow_redirects = 1;

                add_cookie_header(nr, new_url);

                auto njob = std::make_unique<Job>();
                njob->id = job->id;
                njob->request = nr;
                njob->url = new_url;
                njob->redirect_count = job->redirect_count + 1;

                QuicClient* nc = get_or_create_client(new_url);
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

    store_cookies(job->url, headers);
    // Record declared Content-Length for later body-length validation.
    std::string_view cl = headers.get("content-length");
    if (!cl.empty()) {
        uint64_t v = 0;
        if (parse_leading_uint(cl, v)) job->declared_content_length = static_cast<int64_t>(v);
    }
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
            kathttp_event ev{};
            ev.type = KATHTTP_EVENT_ERROR;
            ev.request_id = job->id;
            ev.error_code = KATHTTP_ERR_BODY;
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
    kathttp_event ev{};
    ev.type = KATHTTP_EVENT_HEADERS;
    ev.request_id = job->id;
    ev.status_code = status;
    ev.names = names.data();
    ev.values = values.data();
    ev.header_count = names.size();
    deliver(ev);
}

void Engine::dispatch_body(Job* job, const uint8_t* data, size_t len) {
    kathttp_event ev{};
    ev.type = KATHTTP_EVENT_BODY;
    ev.request_id = job->id;
    ev.data = data;
    ev.data_len = len;
    deliver(ev);
}

void Engine::dispatch_complete(Job* job) {
    kathttp_event ev{};
    ev.type = KATHTTP_EVENT_COMPLETE;
    ev.request_id = job->id;
    ev.error_code = 0;
    deliver(ev);
}

void Engine::dispatch_error(Job* job, int err, const char* msg) {
    kathttp_event ev{};
    ev.type = KATHTTP_EVENT_ERROR;
    ev.request_id = job->id;
    ev.error_code = err;
    (void)msg;
    deliver(ev);
}

void Engine::deliver(const kathttp_event& ev) {
    std::lock_guard<std::recursive_mutex> callback_lock(callback_mutex_);
    ReqEntry e;
    kathttp_event_callback cb = nullptr;
    void* ud = nullptr;
    bool terminal = (ev.type == KATHTTP_EVENT_COMPLETE || ev.type == KATHTTP_EVENT_ERROR);
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
    if (cb) cb(ud, &ev);
    if (terminal) {
        std::lock_guard<std::mutex> lk(mtx_);
        registry_.erase(ev.request_id);
    }
}

void Engine::add_cookie_header(kathttp_request* req, const Url& url) {
    std::string cookie = cookie_jar_.cookie_header(url);
    if (cookie.empty()) return;
    bool has = false;
    for (const auto& h : req->headers.list()) {
        if (case_eq(h.name, "cookie")) {
            has = true;
            break;
        }
    }
    if (!has) req->headers.add("Cookie", cookie);
}

void Engine::store_cookies(const Url& url, const HeaderList& headers) {
    cookie_jar_.store(url, headers);
}

} /* namespace kathttp */

/* ------------------------------------------------------------------ *
 * C ABI
 * ------------------------------------------------------------------ */
extern "C" {

void kathttp_client_options_init(kathttp_client_options* opt) {
    if (!opt) return;
    std::memset(opt, 0, sizeof(*opt));
    opt->struct_size = sizeof(kathttp_client_options);
    opt->abi_version = KATHTTP_ABI_VERSION;
    opt->connect_timeout_ms = 10000;
    opt->request_timeout_ms = 30000;
    opt->idle_timeout_ms = 30000;
    opt->max_redirects = 10;
    opt->max_connections_per_origin = 1;
    opt->verify_cert = 1;
    opt->insecure_cert = 0;
    opt->trust_mode = KATHTTP_TRUST_PLATFORM;
    opt->dns_timeout_ms = opt->connect_timeout_ms;
    opt->handshake_timeout_ms = opt->connect_timeout_ms;
    opt->response_headers_timeout_ms = opt->request_timeout_ms;
    opt->read_timeout_ms = opt->idle_timeout_ms;
    opt->write_timeout_ms = opt->idle_timeout_ms;
    opt->call_timeout_ms = opt->request_timeout_ms;
}

uint32_t kathttp_api_version(void) {
    return KATHTTP_ABI_VERSION;
}

kathttp_client* kathttp_client_create(const kathttp_client_options* options) {
    if (!options) return nullptr;
    constexpr size_t kRequiredOptionsSize =
        offsetof(kathttp_client_options, resolve_cb_userdata) + sizeof(void*);
    if (options->struct_size < kRequiredOptionsSize) return nullptr;
    if (options->abi_version != KATHTTP_ABI_VERSION) return nullptr;
    try {
        kathttp_client_options normalized;
        kathttp_client_options_init(&normalized);
        std::memcpy(&normalized, options,
                    std::min<size_t>(options->struct_size, sizeof(normalized)));
        auto* e = new kathttp::Engine(normalized);
        return reinterpret_cast<kathttp_client*>(e);
    } catch (...) {
        return nullptr;
    }
}

void kathttp_client_destroy(kathttp_client* client) {
    if (!client) return;
    try {
        auto* e = reinterpret_cast<kathttp::Engine*>(client);
        e->destroy();
        delete e;
    } catch (...) {
    }
}

void kathttp_client_close(kathttp_client* client) {
    if (!client) return;
    try {
        reinterpret_cast<kathttp::Engine*>(client)->destroy();
    } catch (...) {
    }
}

void kathttp_client_set_origin_policy(kathttp_client* client, const char* policy_tag) {
    if (!client) return;
    try {
        reinterpret_cast<kathttp::Engine*>(client)->set_origin_policy(policy_tag ? policy_tag : "");
    } catch (...) {
    }
}

void kathttp_client_execute(kathttp_client* client, kathttp_request* request, int64_t request_id,
                            kathttp_event_callback cb, void* user_data) {
    if (!client || !request) {
        delete request;
        return;
    }
    try {
        reinterpret_cast<kathttp::Engine*>(client)->execute(request, request_id, cb, user_data);
    } catch (...) {
        kathttp_event ev{};
        ev.type = KATHTTP_EVENT_ERROR;
        ev.request_id = request_id;
        ev.error_code = KATHTTP_ERR_NOMEM;
        if (cb) cb(user_data, &ev);
        delete request;
    }
}

void kathttp_client_cancel(kathttp_client* client, int64_t request_id) {
    if (!client) return;
    try {
        reinterpret_cast<kathttp::Engine*>(client)->cancel(request_id);
    } catch (...) {
    }
}

void kathttp_client_consume(kathttp_client* client, int64_t request_id, size_t bytes) {
    if (!client) return;
    try {
        reinterpret_cast<kathttp::Engine*>(client)->consume(request_id, bytes);
    } catch (...) {
    }
}

} /* extern "C" */
