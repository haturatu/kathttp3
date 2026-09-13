#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>

#include "cache_control.h"
#include "connection_state.h"
#include "cookie_jar.h"
#include "dns.h"
#include "dns_wait.h"
#include "flow_control.h"
#include "handshake_race.h"
#include "handshake_stream_buffer.h"
#include "header_list.h"
#include "http_date.h"
#include "jni_body_batch.h"
#include "kathttp3.h"
#include "lazy_worker_start.h"
#include "network_change.h"
#include "precommit_failover.h"
#include "redirect.h"
#include "request.h"
#include "request_body_offset.h"
#include "response_cache.h"
#include "time_util.h"
#include "udp_error.h"
#include "udp_socket.h"
#include "url.h"
#include "wakeup_coalescer.h"

using namespace kathttp3;

namespace {

class FakeCacheClock final : public CacheClock {
   public:
    std::optional<uint64_t> wall_seconds() const override {
        return wall_available ? std::optional<uint64_t>(wall) : std::nullopt;
    }

    uint64_t monotonic_ns() const override {
        return monotonic;
    }

    bool wall_available = true;
    uint64_t wall = 1'000;
    uint64_t monotonic = 1'000'000'000ULL;
};

}  // namespace

int main() {
    // The QUIC worker is elected only after the first Job is visible. This
    // prevents an empty worker from exiting before the initial submission.
    LazyWorkerStart worker_start;
    assert(!worker_start.started());
    assert(worker_start.claim_after_enqueue());
    assert(worker_start.started());
    assert(!worker_start.claim_after_enqueue());

    Url u;
    assert(parse_url("https://example.com/a?q=1#ignored", u));
    assert(u.host == "example.com" && u.request_target() == "/a?q=1");
    assert(u.port == 0 && u.authority() == "example.com");
    assert(parse_url("https://example.com:8443/a", u));
    assert(u.authority() == "example.com:8443");
    assert(parse_url("https://example.com/a?", u));
    assert(u.request_target() == "/a?");
    assert(u.to_string() == "https://example.com/a?");
    assert(parse_url("https://example.com?", u));
    assert(u.request_target() == "/?");
    assert(u.to_string() == "https://example.com/?");
    assert(parse_url("HTTPS://example.com/a", u) && u.scheme == "https");
    assert(!parse_url(std::string("h\x80ttps://example.com/", 21), u));
    assert(!parse_url("http://example.com", u));
    assert(!parse_url("https://example.com:99999/", u));
    assert(parse_url("https://[::1]:443/", u));
    assert(u.authority() == "[::1]");
    assert(u.to_string() == "https://[::1]/");
    assert(parse_url("https://[2001:db8::1]:8443/a", u));
    assert(u.authority() == "[2001:db8::1]:8443");
    assert(u.to_string() == "https://[2001:db8::1]:8443/a");
    assert(!parse_url("https://::1/", u));
    assert(!parse_url("https://[::1]suffix/", u));
    assert(!parse_url("https://[not-ipv6]/", u));
    assert(parse_url("HTTPS://example.com/a%20b;v?q=x/y?z#fragment", u));
    assert(u.path == "/a%20b;v" && u.query == "q=x/y?z");
    assert(!parse_url("https://exa mple.com/", u));
    assert(!parse_url("https://example.com/a path", u));
    assert(!parse_url("https://example.com/a\\path", u));
    assert(!parse_url("https://example.com/%", u));
    assert(!parse_url("https://example.com/%GG", u));
    assert(!parse_url("https://example.com/path#bad%", u));
    assert(!parse_url("https://example.com/[raw-bracket]", u));
    HeaderList h;
    h.add("Content-Type", "text/plain");
    assert(h.get("content-type") == "text/plain");
    // Public request input accepts conventional mixed-case names but stores
    // the HTTP/3 wire form in lowercase.
    kathttp3_request* request = kathttp3_request_create("GET", "https://example.com/");
    assert(request != nullptr);
    assert(kathttp3_request_add_header(request, "TE", " Trailers\t") == KATHTTP3_OK);
    assert(kathttp3_request_add_header(request, "Connection", "close") == KATHTTP3_ERR_INVALID_ARG);
    assert(kathttp3_request_add_header(request, "Keep-Alive", "timeout=5") ==
           KATHTTP3_ERR_INVALID_ARG);
    assert(kathttp3_request_add_header(request, "TE", "gzip") == KATHTTP3_ERR_INVALID_ARG);
    assert(kathttp3_request_add_header(request, "bad(name", "value") == KATHTTP3_ERR_INVALID_ARG);
    assert(kathttp3_request_add_header(request, "x-control", "bad\x01value") ==
           KATHTTP3_ERR_INVALID_ARG);
    const std::array<uint8_t, 3> initial_request_body{{1, 2, 3}};
    assert(kathttp3_request_set_body(request, initial_request_body.data(),
                                     initial_request_body.size()) == KATHTTP3_OK);
    assert(request->body_present);
    assert(kathttp3_request_set_body(request, nullptr, 1) == KATHTTP3_ERR_INVALID_ARG);
    assert(request->body ==
           std::vector<uint8_t>(initial_request_body.begin(), initial_request_body.end()));
    assert(kathttp3_request_set_body(request, nullptr, 0) == KATHTTP3_OK);
    assert(request->body.empty() && request->body_present);
    kathttp3_request_destroy(request);
    assert(kathttp3_request_create("", "https://example.com/") == nullptr);
    assert(kathttp3_request_create("BAD METHOD", "https://example.com/") == nullptr);
    request = kathttp3_request_create("POST", "https://example.com/");
    const std::array<uint8_t, 3> request_body{'a', 'b', 'c'};
    assert(kathttp3_request_set_body(request, request_body.data(), request_body.size()) ==
           KATHTTP3_OK);
    assert(kathttp3_request_add_header(request, "Content-Length", "3") == KATHTTP3_OK);
    assert(kathttp3_request_add_header(request, "Content-Length", "3") == KATHTTP3_OK);
    assert(validate_request_body_framing(*request));
    kathttp3_request_destroy(request);
    request = kathttp3_request_create("POST", "https://example.com/");
    assert(kathttp3_request_set_body(request, request_body.data(), request_body.size()) ==
           KATHTTP3_OK);
    assert(kathttp3_request_add_header(request, "Content-Length", "2") == KATHTTP3_OK);
    assert(!validate_request_body_framing(*request));
    kathttp3_request_destroy(request);
    request = kathttp3_request_create("POST", "https://example.com/");
    assert(kathttp3_request_add_header(request, "Content-Length", "invalid") == KATHTTP3_OK);
    assert(!validate_request_body_framing(*request));
    kathttp3_request_destroy(request);
    request = kathttp3_request_create("POST", "https://example.com/");
    assert(kathttp3_request_set_streaming_body(request, -1) == KATHTTP3_OK);
    assert(kathttp3_request_add_header(request, "Content-Length", "7") == KATHTTP3_OK);
    assert(validate_request_body_framing(*request));
    assert(request->streaming_body_length == 7);
    assert(kathttp3_request_set_body(request, request_body.data(), request_body.size()) ==
           KATHTTP3_OK);
    assert(!request->streaming_body && request->streaming_body_length == -1);
    assert(!validate_request_body_framing(*request));
    kathttp3_request_destroy(request);
    Response response;
    response.status_code = 303;
    response.headers.add("location", "/next");
    Url from;
    assert(parse_url("https://example.com/a/b", from));
    RedirectPolicy redirects;
    auto d = redirects.evaluate("POST", from, response, true, 3);
    assert(d.follow && d.drop_body && d.new_method == "GET" &&
           d.new_url == "https://example.com/next");
    d = redirects.evaluate("PUT", from, response, true, 3);
    assert(d.follow && d.drop_body && d.new_method == "GET");
    d = redirects.evaluate("HEAD", from, response, true, 3);
    assert(d.follow && d.drop_body && d.new_method == "HEAD");
    response.status_code = 301;
    d = redirects.evaluate("POST", from, response, true, 3);
    assert(d.follow && d.drop_body && d.new_method == "GET");
    d = redirects.evaluate("PUT", from, response, true, 3);
    assert(d.follow && !d.drop_body && d.new_method == "PUT");
    response.status_code = 302;
    d = redirects.evaluate("POST", from, response, true, 3);
    assert(d.follow && d.drop_body && d.new_method == "GET");
    d = redirects.evaluate("PATCH", from, response, true, 3);
    assert(d.follow && !d.drop_body && d.new_method == "PATCH");
    response.status_code = 303;
    assert(parse_url("https://example.com/a/b/c?old=1", from));
    response.headers.clear();
    response.headers.add("location", "?new=2");
    d = redirects.evaluate("GET", from, response, true, 3);
    assert(d.follow && d.new_url == "https://example.com/a/b/c?new=2");
    response.headers.clear();
    response.headers.add("location", "../next");
    d = redirects.evaluate("GET", from, response, true, 3);
    assert(d.follow && d.new_url == "https://example.com/a/next");
    response.headers.clear();
    response.headers.add("location", "/a/./b/../c");
    d = redirects.evaluate("GET", from, response, true, 3);
    assert(d.follow && d.new_url == "https://example.com/a/c");
    response.headers.clear();
    response.headers.add("location", "#fragment");
    d = redirects.evaluate("GET", from, response, true, 3);
    assert(d.follow && d.new_url == "https://example.com/a/b/c?old=1");
    response.status_code = 307;
    response.headers.clear();
    response.headers.add("location", "//other.example/next");
    d = redirects.evaluate("POST", from, response, true, 3);
    assert(d.follow && d.cross_origin && !d.drop_body && d.new_method == "POST");
    d = redirects.evaluate("GET", from, response, true, 3);
    assert(d.follow && !d.drop_body && d.new_method == "GET");
    response.status_code = 302;
    response.headers.clear();
    response.headers.add("location", "http://example.com/plaintext");
    assert(!redirects.evaluate("GET", from, response, true, 3).follow);
    CookieJar jar;
    HeaderList set;
    set.add("set-cookie", "a=b; Secure; Path=/");
    jar.store(from, set);
    const auto cookie = jar.cookie_header(from);
    assert(cookie == "a=b");
    jar.store(from, "scoped=yes; Domain=example.com; Path=/a; Secure");
    const auto scoped_at_origin = jar.cookie_header(from);
    assert(scoped_at_origin.find("scoped=yes") != std::string::npos);
    Url other;
    assert(parse_url("https://evil.example/a", other));
    const auto scoped_at_other = jar.cookie_header(other);
    assert(scoped_at_other.find("scoped=yes") == std::string::npos);
    jar.store(from, "scoped=gone; Domain=example.com; Path=/a; Max-Age=0");
    const auto expired_cookie = jar.cookie_header(from);
    assert(expired_cookie.find("scoped=") == std::string::npos);
    jar.store(from, "dated=present; Path=/a; Secure");
    jar.store(from, "dated=gone; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/a; Secure");
    const auto dated_cookie = jar.cookie_header(from);
    assert(dated_cookie.find("dated=") == std::string::npos);
    jar.store(from, "future=present; Expires=Wed, 09 Jun 2038 10:18:14 GMT; Path=/a; Secure");
    const auto future_cookie = jar.cookie_header(from);
    assert(future_cookie.find("future=present") != std::string::npos);
    jar.store(from,
              "precedence=gone; Max-Age=0; Expires=Wed, 09 Jun 2038 10:18:14 GMT; Path=/a; "
              "Secure");
    const auto precedence_cookie = jar.cookie_header(from);
    assert(precedence_cookie.find("precedence=") == std::string::npos);
    CookieJar ordered_jar;
    ordered_jar.store(from, "id=root; Path=/; Secure");
    ordered_jar.store(from, "id=deep; Path=/a; Secure");
    Url nested;
    assert(parse_url("https://example.com/a/b?ignored=1", nested));
    const auto ordered_cookie = ordered_jar.cookie_header(nested);
    assert(ordered_cookie == "id=deep; id=root");
    ordered_jar.store(from, "query-path=bad; Path=/a/b?ignored=1; Secure");
    const auto query_path_cookie = ordered_jar.cookie_header(nested);
    assert(query_path_cookie.find("query-path=") == std::string::npos);

    // Resolver work is deliberately dispatched off the QUIC worker.  The
    // callback receives owned values, and cancellation suppresses delivery.
    auto cancelled = std::make_shared<std::atomic<bool>>(false);
    std::mutex dns_mutex;
    std::condition_variable dns_ready;
    bool dns_done = false;
    std::vector<ResolvedEndpoint> endpoints;
    auto resolver = std::make_shared<CallbackResolver>(
        [](const std::string&, uint16_t port, const std::atomic<bool>*) {
            return std::vector<ResolvedEndpoint>{{"2001:db8::1", port, AF_INET6},
                                                 {"192.0.2.1", port, AF_INET}};
        });
    const bool scheduled = resolve_async(resolver, "example.test", 443, cancelled,
                                         [&](std::vector<ResolvedEndpoint> result) {
                                             std::lock_guard<std::mutex> lock(dns_mutex);
                                             endpoints = std::move(result);
                                             dns_done = true;
                                             dns_ready.notify_one();
                                         });
    assert(scheduled);
    {
        std::unique_lock<std::mutex> lock(dns_mutex);
        assert(dns_ready.wait_for(lock, std::chrono::seconds(1), [&] { return dns_done; }));
    }
    assert(endpoints.size() == 2 && endpoints.front().family == AF_INET6);

    // The C resolver callback is untrusted across the ABI boundary: a count
    // larger than the supplied capacity must not index past the fixed buffer.
    auto oversized_c_resolver = [](const char*, uint16_t, void*, kathttp3_resolved_address*,
                                   size_t* count) {
        *count = 65;
        return 0;
    };
    assert(resolve_with_c_callback(oversized_c_resolver, nullptr, "example.test", 443).empty());

    auto unterminated_c_resolver = [](const char*, uint16_t, void*,
                                      kathttp3_resolved_address* output, size_t* count) {
        std::fill(std::begin(output[0].ip), std::end(output[0].ip), '1');
        output[0].port = 443;
        output[0].family = AF_INET;
        *count = 1;
        return 0;
    };
    assert(resolve_with_c_callback(unterminated_c_resolver, nullptr, "example.test", 443).empty());

    auto valid_c_resolver = [](const char*, uint16_t port, void*, kathttp3_resolved_address* output,
                               size_t* count) {
        std::strcpy(output[0].ip, "192.0.2.44");
        output[0].port = port;
        output[0].family = AF_INET;
        *count = 1;
        return 0;
    };
    const auto c_endpoints =
        resolve_with_c_callback(valid_c_resolver, nullptr, "example.test", 443);
    assert(c_endpoints.size() == 1 && c_endpoints[0].ip == "192.0.2.44" &&
           c_endpoints[0].port == 443 && c_endpoints[0].family == AF_INET);

    // Concurrent callers for one resolver/host/port share one upstream query.
    // Waiters remain asynchronous and receive independent owned result values.
    std::mutex flight_mutex;
    std::condition_variable flight_ready;
    std::condition_variable flight_release;
    std::condition_variable flight_completed;
    bool upstream_entered = false;
    bool release_upstream = false;
    size_t upstream_calls = 0;
    size_t completed_waiters = 0;
    auto single_flight_resolver = std::make_shared<CallbackResolver>(
        [&](const std::string&, uint16_t port, const std::atomic<bool>*) {
            std::unique_lock<std::mutex> lock(flight_mutex);
            ++upstream_calls;
            upstream_entered = true;
            flight_ready.notify_one();
            flight_release.wait(lock, [&] { return release_upstream; });
            return std::vector<ResolvedEndpoint>{{"192.0.2.10", port, AF_INET}};
        });
    std::vector<std::shared_ptr<std::atomic<bool>>> flight_cancellations;
    auto submit_waiter = [&] {
        auto waiter_cancelled = std::make_shared<std::atomic<bool>>(false);
        flight_cancellations.push_back(waiter_cancelled);
        return resolve_async(single_flight_resolver, "RR2.GoogleVideo.COM.", 443, waiter_cancelled,
                             [&](const std::vector<ResolvedEndpoint>& result) {
                                 std::lock_guard<std::mutex> lock(flight_mutex);
                                 if (result.size() == 1 && result.front().ip == "192.0.2.10") {
                                     ++completed_waiters;
                                 }
                                 flight_completed.notify_one();
                             });
    };
    const bool first_flight_scheduled = submit_waiter();
    assert(first_flight_scheduled);
    {
        std::unique_lock<std::mutex> lock(flight_mutex);
        const bool entered =
            flight_ready.wait_for(lock, std::chrono::seconds(1), [&] { return upstream_entered; });
        assert(entered);
    }
    constexpr size_t kSharedDnsWaiters = 50;
    for (size_t i = 1; i < kSharedDnsWaiters; ++i) {
        const bool waiter_scheduled = submit_waiter();
        assert(waiter_scheduled);
    }
    {
        std::lock_guard<std::mutex> lock(flight_mutex);
        release_upstream = true;
    }
    flight_release.notify_one();
    {
        std::unique_lock<std::mutex> lock(flight_mutex);
        const bool all_completed = flight_completed.wait_for(
            lock, std::chrono::seconds(1), [&] { return completed_waiters == kSharedDnsWaiters; });
        assert(all_completed);
        assert(upstream_calls == 1);
    }

    // Cancelling one waiter must not cancel the shared lookup for its peers.
    upstream_entered = false;
    release_upstream = false;
    completed_waiters = 0;
    auto cancelled_waiter = std::make_shared<std::atomic<bool>>(false);
    auto live_waiter = std::make_shared<std::atomic<bool>>(false);
    const bool cancelled_flight_scheduled =
        resolve_async(single_flight_resolver, "youtubei.googleapis.com", 443, cancelled_waiter,
                      [&](std::vector<ResolvedEndpoint>) {
                          std::lock_guard<std::mutex> lock(flight_mutex);
                          completed_waiters += 100;
                          flight_completed.notify_one();
                      });
    assert(cancelled_flight_scheduled);
    {
        std::unique_lock<std::mutex> lock(flight_mutex);
        const bool entered =
            flight_ready.wait_for(lock, std::chrono::seconds(1), [&] { return upstream_entered; });
        assert(entered);
    }
    const bool live_waiter_scheduled =
        resolve_async(single_flight_resolver, "YOUTUBEI.GOOGLEAPIS.COM.", 443, live_waiter,
                      [&](std::vector<ResolvedEndpoint>) {
                          std::lock_guard<std::mutex> lock(flight_mutex);
                          ++completed_waiters;
                          flight_completed.notify_one();
                      });
    assert(live_waiter_scheduled);
    cancel_resolve(cancelled_waiter);
    {
        std::lock_guard<std::mutex> lock(flight_mutex);
        release_upstream = true;
    }
    flight_release.notify_one();
    {
        std::unique_lock<std::mutex> lock(flight_mutex);
        const bool live_completed = flight_completed.wait_for(
            lock, std::chrono::seconds(1), [&] { return completed_waiters == 1; });
        assert(live_completed);
    }

    // More unique hosts than the worker queue can hold move into the bounded
    // host-pending queue instead of failing admission. Cancelling queued hosts
    // removes their waiters and prevents their resolver callbacks from running.
    std::mutex saturation_mutex;
    std::condition_variable saturation_entered;
    std::condition_variable saturation_release;
    std::condition_variable saturation_completed;
    bool release_saturated_workers = false;
    size_t saturated_upstream_calls = 0;
    size_t saturated_completions = 0;
    auto saturation_resolver = std::make_shared<CallbackResolver>(
        [&](const std::string&, uint16_t port, const std::atomic<bool>*) {
            std::unique_lock<std::mutex> lock(saturation_mutex);
            ++saturated_upstream_calls;
            saturation_entered.notify_all();
            saturation_release.wait(lock, [&] { return release_saturated_workers; });
            return std::vector<ResolvedEndpoint>{{"192.0.2.30", port, AF_INET}};
        });
    constexpr size_t kSaturatedHostCount = 40;
    std::vector<std::shared_ptr<std::atomic<bool>>> saturated_cancellations;
    saturated_cancellations.reserve(kSaturatedHostCount);
    for (size_t i = 0; i < kSaturatedHostCount; ++i) {
        auto token = std::make_shared<std::atomic<bool>>(false);
        saturated_cancellations.push_back(token);
        const bool accepted =
            resolve_async(saturation_resolver, "queue-" + std::to_string(i) + ".test", 443, token,
                          [&](std::vector<ResolvedEndpoint>) {
                              std::lock_guard<std::mutex> lock(saturation_mutex);
                              ++saturated_completions;
                              saturation_completed.notify_all();
                          });
        assert(accepted);
    }
    {
        std::unique_lock<std::mutex> lock(saturation_mutex);
        assert(saturation_entered.wait_for(lock, std::chrono::seconds(1),
                                           [&] { return saturated_upstream_calls == 2; }));
    }
    for (size_t i = 2; i < saturated_cancellations.size(); ++i)
        cancel_resolve(saturated_cancellations[i]);
    {
        std::lock_guard<std::mutex> lock(saturation_mutex);
        release_saturated_workers = true;
    }
    saturation_release.notify_all();
    {
        std::unique_lock<std::mutex> lock(saturation_mutex);
        assert(saturation_completed.wait_for(lock, std::chrono::seconds(1),
                                             [&] { return saturated_completions == 2; }));
        assert(saturated_upstream_calls == 2);
    }

    // A replacement Android Network gets a distinct flight even for the same
    // hostname, so it cannot inherit addresses from the previous generation.
    std::mutex generation_mutex;
    std::condition_variable generation_entered;
    std::condition_variable generation_release;
    std::condition_variable generation_completed;
    size_t generation_upstream_calls = 0;
    size_t generation_callbacks = 0;
    bool release_generations = false;
    auto generation_upstream = std::make_shared<CallbackResolver>(
        [&](const std::string&, uint16_t port, const std::atomic<bool>*) {
            std::unique_lock<std::mutex> lock(generation_mutex);
            ++generation_upstream_calls;
            generation_entered.notify_all();
            generation_release.wait(lock, [&] { return release_generations; });
            return std::vector<ResolvedEndpoint>{{"192.0.2.20", port, AF_INET}};
        });
    auto generation_cache = std::make_shared<DnsCache>();
    auto network_generation = std::make_shared<std::atomic<uint64_t>>(1);
    auto generation_resolver =
        std::make_shared<CachedResolver>(generation_upstream, generation_cache, network_generation);
    auto first_generation_cancelled = std::make_shared<std::atomic<bool>>(false);
    auto second_generation_cancelled = std::make_shared<std::atomic<bool>>(false);
    auto generation_callback = [&](std::vector<ResolvedEndpoint>) {
        std::lock_guard<std::mutex> lock(generation_mutex);
        ++generation_callbacks;
        generation_completed.notify_one();
    };
    const bool first_generation_scheduled =
        resolve_async(generation_resolver, "yt3.googleusercontent.com", 443,
                      first_generation_cancelled, generation_callback);
    assert(first_generation_scheduled);
    {
        std::unique_lock<std::mutex> lock(generation_mutex);
        const bool first_entered = generation_entered.wait_for(
            lock, std::chrono::seconds(1), [&] { return generation_upstream_calls == 1; });
        assert(first_entered);
    }
    network_generation->store(2, std::memory_order_release);
    const bool second_generation_scheduled =
        resolve_async(generation_resolver, "YT3.GOOGLEUSERCONTENT.COM.", 443,
                      second_generation_cancelled, generation_callback);
    assert(second_generation_scheduled);
    {
        std::unique_lock<std::mutex> lock(generation_mutex);
        const bool both_entered = generation_entered.wait_for(
            lock, std::chrono::seconds(1), [&] { return generation_upstream_calls == 2; });
        assert(both_entered);
        release_generations = true;
    }
    generation_release.notify_all();
    {
        std::unique_lock<std::mutex> lock(generation_mutex);
        const bool both_completed = generation_completed.wait_for(
            lock, std::chrono::seconds(1), [&] { return generation_callbacks == 2; });
        assert(both_completed);
    }
    const HappyEyeballsPlan v6_primary = make_happy_eyeballs_plan(endpoints);
    assert(v6_primary.enabled() && v6_primary.primary == 0 && v6_primary.fallback == 1);
    std::vector<ResolvedEndpoint> v4_primary{
        {"192.0.2.2", 443, AF_INET}, {"2001:db8::2", 443, AF_INET6}, {"192.0.2.3", 443, AF_INET}};
    const HappyEyeballsPlan v4_plan = make_happy_eyeballs_plan(v4_primary);
    assert(v4_plan.enabled() && v4_plan.primary == 0 && v4_plan.fallback == 1);
    assert(!make_happy_eyeballs_plan({v4_primary.front()}).enabled());
    assert(!make_happy_eyeballs_plan({{"invalid", 443, 0}, v4_primary.front()}).enabled());
    assert(connection_state_accepts_new_jobs(ConnectionState::Connecting, false));
    assert(connection_state_accepts_new_jobs(ConnectionState::Active, false));
    assert(!connection_state_accepts_new_jobs(ConnectionState::Draining, false));
    assert(!connection_state_accepts_new_jobs(ConnectionState::Closing, false));
    assert(!connection_state_accepts_new_jobs(ConnectionState::Active, true));
    assert(network_change_action({1, NetworkHandle{42}}, 1, true) == NetworkChangeAction::None);
    assert(network_change_action({2, NetworkHandle{0}}, 1, true) == NetworkChangeAction::Reconnect);
    assert(network_change_action({2, NetworkHandle{42}}, 1, false) ==
           NetworkChangeAction::Reconnect);
    assert(network_change_action({2, NetworkHandle{42}}, 1, true) == NetworkChangeAction::Migrate);
    assert(network_change_action({2, NetworkHandle{42}}, 1, true, false) ==
           NetworkChangeAction::Reconnect);
    assert(udp_error_is_temporary(EAGAIN));
    assert(udp_error_is_temporary(ENOBUFS));
    assert(udp_error_is_network_lost(ENETUNREACH));
    assert(udp_error_is_network_lost(EHOSTUNREACH));
    assert(udp_error_is_network_lost(ENETDOWN));
    assert(udp_error_is_network_lost(ECONNRESET));
    assert(!udp_error_is_network_lost(EINVAL));

    // Race selection is based on the recorded 1-RTT-ready transition, not
    // whichever candidate happens to be processed first by poll().
    assert(select_earliest_1rtt_candidate({300, 100}) == 1);
    assert(select_earliest_1rtt_candidate({100, 100}) == 0);
    assert(select_earliest_1rtt_candidate({0, 0}) == kNoHandshakeRaceWinner);

    // A fallback is permitted only before nghttp3 accepted request HEADERS;
    // cancellation and an already committed request must never be replayed.
    assert(can_fail_over_before_request_commit(true, false, false));
    assert(!can_fail_over_before_request_commit(false, false, false));
    assert(!can_fail_over_before_request_commit(true, true, false));
    assert(!can_fail_over_before_request_commit(true, false, true));
    assert(!can_fail_over_before_request_commit(true, false, false, false));

    assert(elapsed_ns(100, 90) == 10);
    assert(elapsed_ns(90, 100) == 0);
    assert(saturating_elapsed(90, 100) == 0);
    assert(deadline_elapsed_ns(200, 100, 100));
    assert(!deadline_elapsed_ns(99, 100, 1));
    assert(!deadline_elapsed_ns(200, 0, 100));
    assert(milliseconds_to_ns_saturated(0) == 0);
    assert(milliseconds_to_ns_saturated(std::numeric_limits<uint64_t>::max() / 1'000'000ULL) ==
           (std::numeric_limits<uint64_t>::max() / 1'000'000ULL) * 1'000'000ULL);
    assert(milliseconds_to_ns_saturated(std::numeric_limits<uint64_t>::max() / 1'000'000ULL + 1) ==
           std::numeric_limits<uint64_t>::max());
    const auto deadline_before = std::chrono::steady_clock::now();
    assert(steady_deadline_after_ms(1) >= deadline_before);
    assert(steady_deadline_after_ms(std::numeric_limits<uint64_t>::max()) ==
           std::chrono::steady_clock::time_point::max());

    // Cache-Control directives are parsed as fields and tokens, not as
    // substrings. Numeric overflow saturates while malformed numerals fail.
    HeaderList cache_control_headers;
    cache_control_headers.add("Cache-Control", "foo-max-age=60, MAX-AGE=\"60\", private");
    cache_control_headers.add("cache-control", "no-cache, must-revalidate");
    const CacheControl parsed_cache_control = parse_cache_control(cache_control_headers);
    assert(parsed_cache_control.max_age && *parsed_cache_control.max_age == 60);
    assert(parsed_cache_control.is_private && parsed_cache_control.no_cache &&
           parsed_cache_control.must_revalidate);
    HeaderList quoted_unknown;
    quoted_unknown.add("cache-control", "x=\"no-store\", max-age=60");
    assert(!parse_cache_control(quoted_unknown).no_store);
    assert(!parse_delta_seconds("-1"));
    assert(!parse_delta_seconds("123abc"));
    assert(!parse_delta_seconds(""));
    assert(parse_delta_seconds("184467440737095516160") == std::numeric_limits<uint64_t>::max());
    assert(!parse_delta_seconds("184467440737095516160garbage"));
    HeaderList conflicting_cache_control;
    conflicting_cache_control.add("cache-control", "max-age=60");
    conflicting_cache_control.add("cache-control", "Max-Age=120");
    const CacheControl conflict = parse_cache_control(conflicting_cache_control);
    assert(conflict.conflicting_max_age);
    HeaderList invalid_cache_control;
    invalid_cache_control.add("cache-control", "max-age=0x10");
    assert(parse_cache_control(invalid_cache_control).invalid);

    assert(parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT") == 784111777);
    assert(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT") == 784111777);
    assert(parse_http_date("Sun Nov  6 08:49:37 1994") == 784111777);
    assert(format_http_date(784111777) == "Sun, 06 Nov 1994 08:49:37 GMT");
    assert(format_http_date(1'000) == "Thu, 01 Jan 1970 00:16:40 GMT");
    assert(!parse_http_date("Sun, 06 Nov 1994 08:49:37 PST"));
    assert(!parse_http_date("Xun, 06 Nov 1994 08:49:37 GMT"));
    assert(!parse_http_date("Sund, 06-Nov-94 08:49:37 GMT"));

    auto cache_clock = std::make_shared<FakeCacheClock>();
    ResponseCache response_cache(
        ResponseCacheConfig{.max_entries = 4, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        cache_clock);
    HeaderList cache_request_headers;
    const CacheRequest cache_request{"GET", "https://cache.example/item", cache_request_headers,
                                     false};
    Response cache_response;
    cache_response.status_code = 200;
    cache_response.headers.add("Cache-Control", "max-age=60");
    cache_response.headers.add("ETag", "\"v1\"");
    cache_response.body = {1, 2, 3};
    assert(response_cache.should_capture(cache_request, 200, cache_response.headers));
    const bool stored_cache_response = response_cache.store(cache_request, cache_response);
    assert(stored_cache_response);
    CacheLookup cache_hit = response_cache.lookup(cache_request);
    assert(cache_hit.state == CacheState::Fresh && cache_hit.response);
    assert(cache_hit.response->body == cache_response.body);
    assert(cache_hit.response->headers.get("age") == "0");
    cache_clock->monotonic += 60'000'000'000ULL;
    cache_hit = response_cache.lookup(cache_request);
    assert(cache_hit.state == CacheState::NeedsValidation && cache_hit.response);
    assert(response_cache.can_serve_stale_if_error(*cache_hit.response) == false);
    HeaderList request_revalidate_headers;
    request_revalidate_headers.add("cache-control", "max-age=0");
    const CacheRequest request_revalidate{"GET", "https://cache.example/item",
                                          request_revalidate_headers, false};
    const CacheLookup request_revalidate_hit = response_cache.lookup(request_revalidate);
    assert(request_revalidate_hit.state == CacheState::NeedsValidation);

    Response zero_age_response;
    zero_age_response.status_code = 200;
    zero_age_response.headers.add("Cache-Control", "MAX-AGE=0");
    zero_age_response.body = {4};
    const CacheRequest zero_age_request{"GET", "https://cache.example/zero", cache_request_headers,
                                        false};
    const bool stored_zero_age_response = response_cache.store(zero_age_request, zero_age_response);
    assert(stored_zero_age_response);
    const CacheLookup zero_age_hit = response_cache.lookup(zero_age_request);
    assert(zero_age_hit.state == CacheState::NeedsValidation);

    Response date_age_response;
    date_age_response.status_code = 200;
    date_age_response.headers.add("cache-control", "max-age=60");
    date_age_response.headers.add("date", "Thu, 01 Jan 1970 00:16:30 GMT");
    date_age_response.headers.add("age", "5");
    date_age_response.body = {6};
    const CacheRequest date_age_request{"GET", "https://cache.example/date-age",
                                        cache_request_headers, false};
    const bool stored_date_age_response = response_cache.store(date_age_request, date_age_response);
    assert(stored_date_age_response);
    const auto date_age_hit = response_cache.lookup(date_age_request);
    assert(date_age_hit.state == CacheState::Fresh && date_age_hit.response);
    assert(date_age_hit.response->headers.get("age") == "10");

    Response expires_response;
    expires_response.status_code = 200;
    expires_response.headers.add("date", "Thu, 01 Jan 1970 00:16:40 GMT");
    expires_response.headers.add("expires", "Thu, 01 Jan 1970 00:17:40 GMT");
    expires_response.body = {10};
    const CacheRequest expires_request{"GET", "https://cache.example/expires",
                                       cache_request_headers, false};
    const bool stored_expires_response = response_cache.store(expires_request, expires_response);
    assert(stored_expires_response);
    const CacheLookup expires_hit = response_cache.lookup(expires_request);
    assert(expires_hit.state == CacheState::Fresh);

    HeaderList star_vary_headers;
    star_vary_headers.add("cache-control", "max-age=60");
    star_vary_headers.add("vary", "*");
    Response star_vary_response;
    star_vary_response.status_code = 200;
    star_vary_response.headers = star_vary_headers;
    star_vary_response.body = {5};
    const CacheRequest star_vary_request{"GET", "https://cache.example/star", cache_request_headers,
                                         false};
    const bool stored_star_vary_response =
        response_cache.store(star_vary_request, star_vary_response);
    assert(!stored_star_vary_response);
    Response invalid_vary_response = star_vary_response;
    invalid_vary_response.headers.clear();
    invalid_vary_response.headers.add("cache-control", "max-age=60");
    invalid_vary_response.headers.add("vary", "accept encoding");
    const CacheRequest invalid_vary_request{"GET", "https://cache.example/invalid-vary",
                                            cache_request_headers, false};
    const bool stored_invalid_vary_response =
        response_cache.store(invalid_vary_request, invalid_vary_response);
    assert(!stored_invalid_vary_response);

    HeaderList gzip_request_headers;
    gzip_request_headers.add("accept-encoding", "gzip");
    const CacheRequest gzip_request{"GET", "https://cache.example/vary", gzip_request_headers,
                                    false};
    Response vary_response;
    vary_response.status_code = 200;
    vary_response.headers.add("cache-control", "max-age=60");
    vary_response.headers.add("Vary", "Accept-Encoding");
    vary_response.body = {9};
    const bool stored_gzip_response = response_cache.store(gzip_request, vary_response);
    assert(stored_gzip_response);
    HeaderList br_request_headers;
    br_request_headers.add("accept-encoding", "br");
    const CacheRequest br_request{"GET", "https://cache.example/vary", br_request_headers, false};
    const CacheLookup gzip_hit = response_cache.lookup(gzip_request);
    assert(gzip_hit.state == CacheState::Fresh);
    const CacheLookup br_hit = response_cache.lookup(br_request);
    assert(br_hit.state == CacheState::Miss);

    HeaderList authorized_headers;
    authorized_headers.add("Authorization", "Bearer secret");
    const CacheRequest authorized_request{"GET", "https://cache.example/private",
                                          authorized_headers, false};
    const CacheLookup authorized_hit = response_cache.lookup(authorized_request);
    assert(authorized_hit.state == CacheState::Miss);
    const bool stored_authorized_response =
        response_cache.store(authorized_request, cache_response);
    assert(!stored_authorized_response);

    const CacheRequest lowercase_method_request{"get", "https://cache.example/item",
                                                cache_request_headers, false};
    const CacheLookup lowercase_method_hit = response_cache.lookup(lowercase_method_request);
    assert(lowercase_method_hit.state == CacheState::Miss);
    const bool stored_lowercase_method =
        response_cache.store(lowercase_method_request, cache_response);
    assert(!stored_lowercase_method);

    const CacheRequest get_with_body_request{"GET", "https://cache.example/item",
                                             cache_request_headers, false, true};
    const CacheLookup get_with_body_hit = response_cache.lookup(get_with_body_request);
    assert(get_with_body_hit.state == CacheState::Miss);
    const bool stored_get_with_body = response_cache.store(get_with_body_request, cache_response);
    assert(!stored_get_with_body);

    constexpr std::array<const char*, 5> kConditionalHeaders = {
        "if-none-match", "if-modified-since", "if-match", "if-unmodified-since", "if-range",
    };
    for (const char* name : kConditionalHeaders) {
        HeaderList conditional_headers;
        conditional_headers.add(name, "\"caller-validator\"");
        const CacheRequest conditional_request{"GET", "https://cache.example/item",
                                               conditional_headers, false};
        const CacheLookup conditional_hit = response_cache.lookup(conditional_request);
        assert(conditional_hit.state == CacheState::Miss);
        const bool stored_conditional = response_cache.store(conditional_request, cache_response);
        assert(!stored_conditional);
    }

    auto no_cache_clock = std::make_shared<FakeCacheClock>();
    ResponseCache no_cache_cache(
        ResponseCacheConfig{.max_entries = 4, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        no_cache_clock);
    Response no_cache_response;
    no_cache_response.status_code = 200;
    no_cache_response.headers.add("cache-control", "no-cache, max-age=60");
    no_cache_response.headers.add("etag", "\"no-cache-v1\"");
    no_cache_response.body = {11};
    const CacheRequest no_cache_request{"GET", "https://cache.example/no-cache",
                                        cache_request_headers, false};
    assert(no_cache_cache.should_capture(no_cache_request, 200, no_cache_response.headers));
    const bool stored_no_cache = no_cache_cache.store(no_cache_request, no_cache_response);
    assert(stored_no_cache);
    const CacheLookup no_cache_hit = no_cache_cache.lookup(no_cache_request);
    assert(no_cache_hit.state == CacheState::NeedsValidation && no_cache_hit.response &&
           no_cache_hit.response->requires_revalidation);

    Response no_cache_without_validator = no_cache_response;
    no_cache_without_validator.headers.clear();
    no_cache_without_validator.headers.add("cache-control", "no-cache, max-age=60");
    const CacheRequest no_cache_without_validator_request{
        "GET", "https://cache.example/no-cache-without-validator", cache_request_headers, false};
    assert(!no_cache_cache.should_capture(no_cache_without_validator_request, 200,
                                          no_cache_without_validator.headers));
    const bool stored_no_cache_without_validator =
        no_cache_cache.store(no_cache_without_validator_request, no_cache_without_validator);
    assert(!stored_no_cache_without_validator);

    HeaderList stale_error_headers;
    stale_error_headers.add("cache-control", "max-age=1, stale-if-error=5");
    Response stale_error_response;
    stale_error_response.status_code = 200;
    stale_error_response.headers = stale_error_headers;
    stale_error_response.body = {7};
    const CacheRequest stale_error_request{"GET", "https://cache.example/error",
                                           cache_request_headers, false};
    cache_clock->monotonic = 1'000'000'000ULL;
    const bool stored_stale_error_response =
        response_cache.store(stale_error_request, stale_error_response);
    assert(stored_stale_error_response);
    cache_clock->monotonic += 3'000'000'000ULL;
    const auto stale_lookup = response_cache.lookup(stale_error_request);
    assert(stale_lookup.response &&
           response_cache.can_serve_stale_if_error(*stale_lookup.response));
    response_cache.invalidate(stale_error_request.url);
    const CacheLookup stale_after_invalidation = response_cache.lookup(stale_error_request);
    assert(stale_after_invalidation.state == CacheState::Miss);

    auto revalidation_clock = std::make_shared<FakeCacheClock>();
    ResponseCache revalidation_cache(
        ResponseCacheConfig{.max_entries = 4, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        revalidation_clock);
    Response revalidation_response;
    revalidation_response.status_code = 200;
    revalidation_response.headers.add("cache-control", "max-age=0, stale-if-error=300");
    revalidation_response.headers.add("etag", "\"v1\"");
    revalidation_response.body = {8, 9};
    const CacheRequest revalidation_request{"GET", "https://cache.example/revalidate",
                                            cache_request_headers, false};
    const bool stored_revalidation_response =
        revalidation_cache.store(revalidation_request, revalidation_response);
    assert(stored_revalidation_response);
    const auto stale_for_validation = revalidation_cache.lookup(revalidation_request);
    assert(stale_for_validation.state == CacheState::NeedsValidation &&
           stale_for_validation.response && stale_for_validation.response->etag);
    assert(revalidation_cache.can_serve_stale_if_error(*stale_for_validation.response));
    HeaderList not_modified_headers;
    not_modified_headers.add("cache-control", "max-age=60");
    not_modified_headers.add("etag", "\"v2\"");
    const auto mismatched = revalidation_cache.merge_304(
        *stale_for_validation.response, revalidation_request, not_modified_headers);
    assert(!mismatched);
    const auto still_stale = revalidation_cache.lookup(revalidation_request);
    assert(still_stale.state == CacheState::NeedsValidation && still_stale.response &&
           still_stale.response->etag && *still_stale.response->etag == "\"v1\"");

    HeaderList matching_not_modified_headers;
    matching_not_modified_headers.add("cache-control", "max-age=60");
    matching_not_modified_headers.add("etag", "\"v1\"");
    const auto merged = revalidation_cache.merge_304(
        *stale_for_validation.response, revalidation_request, matching_not_modified_headers);
    assert(merged && merged->retention_candidate && merged->delivery.status_code == 200 &&
           merged->delivery.body == revalidation_response.body &&
           merged->delivery.headers.get("date") == "Thu, 01 Jan 1970 00:16:40 GMT");
    const auto refreshed = revalidation_cache.lookup(revalidation_request);
    assert(refreshed.state == CacheState::Fresh && refreshed.response);
    assert(refreshed.response->etag && *refreshed.response->etag == "\"v1\"");

    auto revalidation_age_clock = std::make_shared<FakeCacheClock>();
    ResponseCache revalidation_age_cache(
        ResponseCacheConfig{.max_entries = 4, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        revalidation_age_clock);
    Response revalidation_age_response;
    revalidation_age_response.status_code = 200;
    revalidation_age_response.headers.add("cache-control", "max-age=1");
    revalidation_age_response.headers.add("etag", "\"age-v1\"");
    revalidation_age_response.body = {11};
    const CacheRequest revalidation_age_request{"GET", "https://cache.example/revalidate-age",
                                                cache_request_headers, false};
    const bool stored_revalidation_age =
        revalidation_age_cache.store(revalidation_age_request, revalidation_age_response);
    assert(stored_revalidation_age);
    revalidation_age_clock->monotonic += 120'000'000'000ULL;
    revalidation_age_clock->wall += 120;
    const auto stale_age = revalidation_age_cache.lookup(revalidation_age_request);
    assert(stale_age.state == CacheState::NeedsValidation && stale_age.response &&
           stale_age.response->headers.get("age") == "120");
    HeaderList age_not_modified_headers;
    age_not_modified_headers.add("cache-control", "max-age=60");
    age_not_modified_headers.add("date", "Thu, 01 Jan 1970 00:18:40 GMT");
    age_not_modified_headers.add("etag", "\"age-v1\"");
    const auto age_merged = revalidation_age_cache.merge_304(
        *stale_age.response, revalidation_age_request, age_not_modified_headers);
    assert(age_merged && age_merged->retention_candidate &&
           age_merged->delivery.body == revalidation_age_response.body);
    const auto age_refreshed = revalidation_age_cache.lookup(revalidation_age_request);
    assert(age_refreshed.state == CacheState::Fresh && age_refreshed.response &&
           age_refreshed.response->headers.get("age") == "0");

    Response no_store_revalidation_response = revalidation_response;
    no_store_revalidation_response.headers.clear();
    no_store_revalidation_response.headers.add("cache-control", "max-age=0");
    no_store_revalidation_response.headers.add("etag", "\"no-store-v1\"");
    no_store_revalidation_response.body = {12, 13};
    const CacheRequest no_store_revalidation_request{
        "GET", "https://cache.example/revalidate-no-store", cache_request_headers, false};
    const bool stored_no_store_revalidation =
        revalidation_cache.store(no_store_revalidation_request, no_store_revalidation_response);
    assert(stored_no_store_revalidation);
    const auto no_store_stale = revalidation_cache.lookup(no_store_revalidation_request);
    assert(no_store_stale.state == CacheState::NeedsValidation && no_store_stale.response);
    HeaderList no_store_not_modified_headers;
    no_store_not_modified_headers.add("cache-control", "no-store");
    no_store_not_modified_headers.add("etag", "\"no-store-v1\"");
    const auto no_store_merged = revalidation_cache.merge_304(
        *no_store_stale.response, no_store_revalidation_request, no_store_not_modified_headers);
    assert(no_store_merged && !no_store_merged->retention_candidate &&
           no_store_merged->delivery.status_code == 200 &&
           no_store_merged->delivery.body == no_store_revalidation_response.body);
    const CacheLookup no_store_after_merge =
        revalidation_cache.lookup(no_store_revalidation_request);
    assert(no_store_after_merge.state == CacheState::Miss);

    Response star_vary_revalidation_response = revalidation_response;
    star_vary_revalidation_response.headers.clear();
    star_vary_revalidation_response.headers.add("cache-control", "max-age=0");
    star_vary_revalidation_response.headers.add("etag", "\"star-v1\"");
    star_vary_revalidation_response.body = {16};
    const CacheRequest star_vary_revalidation_request{
        "GET", "https://cache.example/revalidate-star", cache_request_headers, false};
    const bool stored_star_vary_revalidation =
        revalidation_cache.store(star_vary_revalidation_request, star_vary_revalidation_response);
    assert(stored_star_vary_revalidation);
    const auto star_vary_stale = revalidation_cache.lookup(star_vary_revalidation_request);
    assert(star_vary_stale.state == CacheState::NeedsValidation && star_vary_stale.response);
    HeaderList star_vary_not_modified_headers;
    star_vary_not_modified_headers.add("cache-control", "max-age=60");
    star_vary_not_modified_headers.add("vary", "*");
    star_vary_not_modified_headers.add("etag", "\"star-v1\"");
    const auto star_vary_merged = revalidation_cache.merge_304(
        *star_vary_stale.response, star_vary_revalidation_request, star_vary_not_modified_headers);
    assert(star_vary_merged && !star_vary_merged->retention_candidate &&
           star_vary_merged->delivery.body == star_vary_revalidation_response.body);
    const CacheLookup star_vary_after_merge =
        revalidation_cache.lookup(star_vary_revalidation_request);
    assert(star_vary_after_merge.state == CacheState::Miss);

    HeaderList vary_revalidation_request_headers;
    vary_revalidation_request_headers.add("accept-encoding", "gzip");
    const CacheRequest vary_revalidation_request{"GET", "https://cache.example/revalidate-vary",
                                                 vary_revalidation_request_headers, false};
    Response vary_revalidation_response;
    vary_revalidation_response.status_code = 200;
    vary_revalidation_response.headers.add("cache-control", "max-age=0");
    vary_revalidation_response.headers.add("vary", "accept-encoding");
    vary_revalidation_response.headers.add("etag", "\"vary-v1\"");
    vary_revalidation_response.body = {14};
    const bool stored_vary_revalidation =
        revalidation_cache.store(vary_revalidation_request, vary_revalidation_response);
    assert(stored_vary_revalidation);
    const auto vary_stale = revalidation_cache.lookup(vary_revalidation_request);
    assert(vary_stale.state == CacheState::NeedsValidation && vary_stale.response);
    HeaderList changed_vary_not_modified_headers;
    changed_vary_not_modified_headers.add("cache-control", "max-age=60");
    changed_vary_not_modified_headers.add("vary", "accept-language");
    changed_vary_not_modified_headers.add("etag", "\"vary-v1\"");
    const auto changed_vary = revalidation_cache.merge_304(
        *vary_stale.response, vary_revalidation_request, changed_vary_not_modified_headers);
    assert(changed_vary && changed_vary->retention_candidate);
    const CacheLookup changed_vary_hit = revalidation_cache.lookup(vary_revalidation_request);
    assert(changed_vary_hit.state == CacheState::Fresh);
    HeaderList changed_vary_probe_headers;
    changed_vary_probe_headers.add("accept-encoding", "gzip");
    changed_vary_probe_headers.add("accept-language", "ja");
    const CacheRequest changed_vary_probe{"GET", "https://cache.example/revalidate-vary",
                                          changed_vary_probe_headers, false};
    const CacheLookup changed_vary_probe_hit = revalidation_cache.lookup(changed_vary_probe);
    assert(changed_vary_probe_hit.state == CacheState::Miss);

    const CacheRequest last_modified_request{
        "GET", "https://cache.example/revalidate-last-modified", cache_request_headers, false};
    Response last_modified_response;
    last_modified_response.status_code = 200;
    last_modified_response.headers.add("cache-control", "max-age=0");
    last_modified_response.headers.add("last-modified", "Thu, 01 Jan 1970 00:16:40 GMT");
    last_modified_response.body = {15};
    const bool stored_last_modified =
        revalidation_cache.store(last_modified_request, last_modified_response);
    assert(stored_last_modified);
    const auto last_modified_stale = revalidation_cache.lookup(last_modified_request);
    assert(last_modified_stale.state == CacheState::NeedsValidation &&
           last_modified_stale.response && last_modified_stale.response->last_modified);
    HeaderList mismatched_last_modified_headers;
    mismatched_last_modified_headers.add("cache-control", "max-age=60");
    mismatched_last_modified_headers.add("last-modified", "Thu, 01 Jan 1970 00:16:41 GMT");
    const auto mismatched_last_modified = revalidation_cache.merge_304(
        *last_modified_stale.response, last_modified_request, mismatched_last_modified_headers);
    assert(!mismatched_last_modified);
    HeaderList missing_last_modified_headers;
    missing_last_modified_headers.add("cache-control", "max-age=60");
    const auto missing_last_modified = revalidation_cache.merge_304(
        *last_modified_stale.response, last_modified_request, missing_last_modified_headers);
    assert(!missing_last_modified);
    HeaderList matching_last_modified_headers;
    matching_last_modified_headers.add("cache-control", "max-age=60");
    matching_last_modified_headers.add("last-modified", "Thu, 01 Jan 1970 00:16:40 GMT");
    const auto matching_last_modified = revalidation_cache.merge_304(
        *last_modified_stale.response, last_modified_request, matching_last_modified_headers);
    assert(matching_last_modified && matching_last_modified->retention_candidate &&
           matching_last_modified->delivery.body == last_modified_response.body);
    const CacheLookup last_modified_refreshed = revalidation_cache.lookup(last_modified_request);
    assert(last_modified_refreshed.state == CacheState::Fresh);

    auto weak_etag_clock = std::make_shared<FakeCacheClock>();
    ResponseCache weak_etag_cache(
        ResponseCacheConfig{.max_entries = 4, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        weak_etag_clock);
    Response weak_etag_response;
    weak_etag_response.status_code = 200;
    weak_etag_response.headers.add("cache-control", "max-age=0");
    weak_etag_response.headers.add("etag", "\"weak-v1\"");
    weak_etag_response.body = {17};
    const CacheRequest weak_etag_request{"GET", "https://cache.example/revalidate-weak-etag",
                                         cache_request_headers, false};
    const bool stored_weak_etag = weak_etag_cache.store(weak_etag_request, weak_etag_response);
    assert(stored_weak_etag);
    const auto weak_etag_stale = weak_etag_cache.lookup(weak_etag_request);
    assert(weak_etag_stale.state == CacheState::NeedsValidation && weak_etag_stale.response);
    HeaderList weak_etag_not_modified_headers;
    weak_etag_not_modified_headers.add("cache-control", "max-age=60");
    weak_etag_not_modified_headers.add("etag", "W/\"weak-v1\"");
    const auto weak_etag_merged = weak_etag_cache.merge_304(
        *weak_etag_stale.response, weak_etag_request, weak_etag_not_modified_headers);
    assert(weak_etag_merged && weak_etag_merged->retention_candidate &&
           weak_etag_merged->delivery.body == weak_etag_response.body);
    const auto weak_etag_hit = weak_etag_cache.lookup(weak_etag_request);
    assert(weak_etag_hit.state == CacheState::Fresh && weak_etag_hit.response &&
           weak_etag_hit.response->etag && *weak_etag_hit.response->etag == "W/\"weak-v1\"");
    weak_etag_clock->monotonic += 60'000'000'000ULL;
    weak_etag_clock->wall += 60;
    const auto weak_stored_stale = weak_etag_cache.lookup(weak_etag_request);
    assert(weak_stored_stale.state == CacheState::NeedsValidation && weak_stored_stale.response);
    HeaderList strong_from_weak_headers;
    strong_from_weak_headers.add("cache-control", "max-age=60");
    strong_from_weak_headers.add("etag", "\"weak-v1\"");
    const auto strong_from_weak = weak_etag_cache.merge_304(
        *weak_stored_stale.response, weak_etag_request, strong_from_weak_headers);
    assert(!strong_from_weak);
    HeaderList weak_from_weak_headers;
    weak_from_weak_headers.add("cache-control", "max-age=60");
    weak_from_weak_headers.add("etag", "W/\"weak-v1\"");
    const auto weak_from_weak = weak_etag_cache.merge_304(
        *weak_stored_stale.response, weak_etag_request, weak_from_weak_headers);
    assert(weak_from_weak && weak_from_weak->retention_candidate);

    auto revalidation_race_clock = std::make_shared<FakeCacheClock>();
    ResponseCache revalidation_race_cache(
        ResponseCacheConfig{.max_entries = 4, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        revalidation_race_clock);
    Response race_v1;
    race_v1.status_code = 200;
    race_v1.headers.add("cache-control", "max-age=0");
    race_v1.headers.add("etag", "\"race-v1\"");
    race_v1.body = {18};
    const CacheRequest race_request{"GET", "https://cache.example/revalidate-race",
                                    cache_request_headers, false};
    const bool stored_race_v1 = revalidation_race_cache.store(race_request, race_v1);
    assert(stored_race_v1);
    const auto stale_race = revalidation_race_cache.lookup(race_request);
    assert(stale_race.state == CacheState::NeedsValidation && stale_race.response);
    Response race_v2;
    race_v2.status_code = 200;
    race_v2.headers.add("cache-control", "max-age=60");
    race_v2.headers.add("etag", "\"race-v2\"");
    race_v2.body = {19};
    const bool stored_race_v2 = revalidation_race_cache.store(race_request, race_v2);
    assert(stored_race_v2);
    HeaderList delayed_race_not_modified_headers;
    delayed_race_not_modified_headers.add("cache-control", "max-age=60");
    delayed_race_not_modified_headers.add("etag", "\"race-v1\"");
    const auto delayed_race_merge = revalidation_race_cache.merge_304(
        *stale_race.response, race_request, delayed_race_not_modified_headers);
    assert(delayed_race_merge && !delayed_race_merge->retention_candidate &&
           delayed_race_merge->delivery.body == race_v1.body);
    const auto race_hit = revalidation_race_cache.lookup(race_request);
    assert(race_hit.state == CacheState::Fresh && race_hit.response &&
           race_hit.response->body == race_v2.body && race_hit.response->etag &&
           *race_hit.response->etag == "\"race-v2\"");

    auto validation_failure_clock = std::make_shared<FakeCacheClock>();
    ResponseCache validation_failure_cache(
        ResponseCacheConfig{.max_entries = 4, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        validation_failure_clock);
    Response validation_v1 = race_v1;
    validation_v1.headers.clear();
    validation_v1.headers.add("cache-control", "max-age=0");
    validation_v1.headers.add("etag", "\"failure-v1\"");
    validation_v1.body = {23};
    const CacheRequest validation_failure_request{"GET", "https://cache.example/revalidate-failure",
                                                  cache_request_headers, false};
    const bool stored_validation_v1 =
        validation_failure_cache.store(validation_failure_request, validation_v1);
    assert(stored_validation_v1);
    const auto stale_validation_failure =
        validation_failure_cache.lookup(validation_failure_request);
    assert(stale_validation_failure.state == CacheState::NeedsValidation &&
           stale_validation_failure.response);
    Response validation_v2 = validation_v1;
    validation_v2.headers.clear();
    validation_v2.headers.add("cache-control", "max-age=60");
    validation_v2.headers.add("etag", "\"failure-v2\"");
    validation_v2.body = {24};
    const bool stored_validation_v2 =
        validation_failure_cache.store(validation_failure_request, validation_v2);
    assert(stored_validation_v2);
    HeaderList failed_validation_headers;
    failed_validation_headers.add("etag", "\"unexpected\"");
    const auto failed_validation = validation_failure_cache.merge_304(
        *stale_validation_failure.response, validation_failure_request, failed_validation_headers);
    assert(!failed_validation);
    const bool removed_old_validation =
        validation_failure_cache.invalidate_entry(stale_validation_failure.response->entry_id);
    assert(!removed_old_validation);
    const auto validation_failure_hit = validation_failure_cache.lookup(validation_failure_request);
    assert(validation_failure_hit.state == CacheState::Fresh && validation_failure_hit.response &&
           validation_failure_hit.response->body == validation_v2.body);

    auto variant_invalidation_clock = std::make_shared<FakeCacheClock>();
    ResponseCache variant_invalidation_cache(
        ResponseCacheConfig{.max_entries = 4, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        variant_invalidation_clock);
    HeaderList en_request_headers;
    en_request_headers.add("accept-language", "en");
    HeaderList ja_request_headers;
    ja_request_headers.add("accept-language", "ja");
    const CacheRequest en_request{"GET", "https://cache.example/invalidate-variant",
                                  en_request_headers, false};
    const CacheRequest ja_request{"GET", "https://cache.example/invalidate-variant",
                                  ja_request_headers, false};
    Response en_response;
    en_response.status_code = 200;
    en_response.headers.add("cache-control", "max-age=60");
    en_response.headers.add("vary", "accept-language");
    en_response.body = {25};
    Response ja_response = en_response;
    ja_response.body = {26};
    const bool stored_en_response = variant_invalidation_cache.store(en_request, en_response);
    const bool stored_ja_response = variant_invalidation_cache.store(ja_request, ja_response);
    assert(stored_en_response && stored_ja_response);
    const auto en_hit = variant_invalidation_cache.lookup(en_request);
    assert(en_hit.state == CacheState::Fresh && en_hit.response);
    const bool removed_en = variant_invalidation_cache.invalidate_entry(en_hit.response->entry_id);
    assert(removed_en);
    const auto ja_hit = variant_invalidation_cache.lookup(ja_request);
    assert(ja_hit.state == CacheState::Fresh && ja_hit.response &&
           ja_hit.response->body == ja_response.body);

    auto selection_clock = std::make_shared<FakeCacheClock>();
    ResponseCache selection_cache(
        ResponseCacheConfig{.max_entries = 8, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        selection_clock);
    HeaderList encoding_request_headers;
    encoding_request_headers.add("accept-encoding", "gzip");
    HeaderList language_request_headers;
    language_request_headers.add("accept-language", "ja");
    const CacheRequest encoding_request{"GET", "https://cache.example/selection",
                                        encoding_request_headers, false};
    const CacheRequest language_request{"GET", "https://cache.example/selection",
                                        language_request_headers, false};
    Response encoding_response;
    encoding_response.status_code = 200;
    encoding_response.headers.add("cache-control", "max-age=60");
    encoding_response.headers.add("vary", "accept-encoding");
    encoding_response.headers.add("date", "Thu, 01 Jan 1970 00:16:40 GMT");
    encoding_response.body = {27};
    Response language_response;
    language_response.status_code = 200;
    language_response.headers.add("cache-control", "max-age=60");
    language_response.headers.add("vary", "accept-language");
    language_response.headers.add("date", "Thu, 01 Jan 1970 00:16:50 GMT");
    language_response.body = {28};
    const bool stored_encoding_response =
        selection_cache.store(encoding_request, encoding_response);
    const bool stored_language_response =
        selection_cache.store(language_request, language_response);
    assert(stored_encoding_response && stored_language_response);
    const auto encoding_only_hit = selection_cache.lookup(encoding_request);
    assert(encoding_only_hit.state == CacheState::Fresh && encoding_only_hit.response &&
           encoding_only_hit.response->body == encoding_response.body);
    HeaderList combined_selection_headers = encoding_request_headers;
    combined_selection_headers.add("accept-language", "ja");
    const CacheRequest combined_selection_request{"GET", "https://cache.example/selection",
                                                  combined_selection_headers, false};
    const auto combined_selection_hit = selection_cache.lookup(combined_selection_request);
    assert(combined_selection_hit.state == CacheState::Fresh && combined_selection_hit.response &&
           combined_selection_hit.response->body == language_response.body);

    Response order_newer = language_response;
    order_newer.headers.clear();
    order_newer.headers.add("cache-control", "max-age=60");
    order_newer.headers.add("date", "Thu, 01 Jan 1970 00:17:00 GMT");
    order_newer.body = {29};
    Response order_older = order_newer;
    order_older.headers.clear();
    order_older.headers.add("cache-control", "max-age=60");
    order_older.headers.add("date", "Thu, 01 Jan 1970 00:16:59 GMT");
    order_older.body = {30};
    const CacheRequest order_request{"GET", "https://cache.example/selection-order",
                                     cache_request_headers, false};
    const bool stored_order_newer = selection_cache.store(order_request, order_newer);
    const bool stored_order_older = selection_cache.store(order_request, order_older);
    assert(stored_order_newer && stored_order_older);
    const auto order_hit = selection_cache.lookup(order_request);
    assert(order_hit.state == CacheState::Fresh && order_hit.response &&
           order_hit.response->body == order_newer.body);

    auto delivery_limit_clock = std::make_shared<FakeCacheClock>();
    ResponseCache delivery_limit_cache(
        ResponseCacheConfig{.max_entries = 4, .max_bytes = 1 << 14, .max_entry_bytes = 4096},
        delivery_limit_clock);
    Response delivery_limit_response;
    delivery_limit_response.status_code = 200;
    delivery_limit_response.headers.add("cache-control", "max-age=0");
    delivery_limit_response.headers.add("etag", "\"limit-v1\"");
    delivery_limit_response.headers.add("x-padding", std::string(3000, 'a'));
    delivery_limit_response.body = {20};
    const CacheRequest delivery_limit_request{
        "GET", "https://cache.example/revalidate-delivery-limit", cache_request_headers, false};
    const bool stored_delivery_limit =
        delivery_limit_cache.store(delivery_limit_request, delivery_limit_response);
    assert(stored_delivery_limit);
    const auto delivery_limit_stale = delivery_limit_cache.lookup(delivery_limit_request);
    assert(delivery_limit_stale.state == CacheState::NeedsValidation &&
           delivery_limit_stale.response);
    HeaderList delivery_limit_not_modified_headers;
    delivery_limit_not_modified_headers.add("cache-control", "max-age=60");
    delivery_limit_not_modified_headers.add("etag", "\"limit-v1\"");
    delivery_limit_not_modified_headers.add("x-new-padding", std::string(1000, 'b'));
    const auto delivery_limit_merge =
        delivery_limit_cache.merge_304(*delivery_limit_stale.response, delivery_limit_request,
                                       delivery_limit_not_modified_headers);
    assert(delivery_limit_merge && !delivery_limit_merge->retention_candidate &&
           delivery_limit_merge->delivery.body == delivery_limit_response.body);
    const CacheLookup delivery_limit_after_merge =
        delivery_limit_cache.lookup(delivery_limit_request);
    assert(delivery_limit_after_merge.state == CacheState::Miss);

    ResponseCache lru_cache(
        ResponseCacheConfig{.max_entries = 1, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        revalidation_clock);
    Response lru_response = cache_response;
    const CacheRequest lru_a{"GET", "https://cache.example/lru-a", cache_request_headers, false};
    const CacheRequest lru_b{"GET", "https://cache.example/lru-b", cache_request_headers, false};
    const bool stored_lru_a = lru_cache.store(lru_a, lru_response);
    assert(stored_lru_a);
    const bool stored_lru_b = lru_cache.store(lru_b, lru_response);
    assert(stored_lru_b);
    const CacheLookup lru_a_hit = lru_cache.lookup(lru_a);
    assert(lru_a_hit.state == CacheState::Miss);
    const CacheLookup lru_b_hit = lru_cache.lookup(lru_b);
    assert(lru_b_hit.state == CacheState::Fresh);

    auto clock_failure_cache = std::make_shared<ResponseCache>(
        ResponseCacheConfig{.max_entries = 2, .max_bytes = 1 << 20, .max_entry_bytes = 1 << 16},
        cache_clock);
    const bool stored_clock_response = clock_failure_cache->store(cache_request, cache_response);
    assert(stored_clock_response);
    cache_clock->wall_available = false;
    const bool stored_without_wall_clock =
        clock_failure_cache->store(cache_request, cache_response);
    assert(!stored_without_wall_clock);
    const CacheLookup clock_failure_hit = clock_failure_cache->lookup(cache_request);
    assert(clock_failure_hit.state == CacheState::NeedsValidation && clock_failure_hit.response);
    HeaderList clock_failure_not_modified_headers;
    clock_failure_not_modified_headers.add("cache-control", "max-age=60");
    clock_failure_not_modified_headers.add("etag", "\"v1\"");
    const auto clock_failure_merge = clock_failure_cache->merge_304(
        *clock_failure_hit.response, cache_request, clock_failure_not_modified_headers);
    assert(clock_failure_merge && !clock_failure_merge->retention_candidate &&
           clock_failure_merge->delivery.body == cache_response.body);
    assert(clock_failure_cache->lookup(cache_request).state == CacheState::Miss);
    cache_clock->wall_available = true;

    Response must_revalidate_response = stale_error_response;
    must_revalidate_response.headers.add("cache-control", "must-revalidate");
    const CacheRequest must_revalidate_request{"GET", "https://cache.example/must-revalidate",
                                               cache_request_headers, false};
    const bool stored_must_revalidate_response =
        response_cache.store(must_revalidate_request, must_revalidate_response);
    assert(stored_must_revalidate_response);
    cache_clock->monotonic += 3'000'000'000ULL;
    const auto must_revalidate_lookup = response_cache.lookup(must_revalidate_request);
    assert(must_revalidate_lookup.response &&
           !response_cache.can_serve_stale_if_error(*must_revalidate_lookup.response));

    size_t body_remaining = 0;
    const bool has_remaining_body = request_body_remaining(10, 4, &body_remaining);
    assert(has_remaining_body);
    assert(body_remaining == 6);
    const bool rejected_body_offset = request_body_remaining(4, 10, &body_remaining);
    assert(!rejected_body_offset);
    assert(request_body_can_advance(4, 6, 10));
    assert(!request_body_can_advance(4, 7, 10));
    assert(request_body_next_chunk_size(kMaxHttp3DataReaderBytes + 1) == kMaxHttp3DataReaderBytes);

    HandshakeStreamBuffer handshake_stream_buffer;
    const uint8_t settings[] = {0x00, 0x04, 0x00};
    const bool buffered_settings =
        handshake_stream_buffer.append(0, 3, 0, settings, sizeof(settings));
    assert(buffered_settings);
    const bool buffered_qpack_fin = handshake_stream_buffer.append(1, 7, 0, nullptr, 0);
    assert(buffered_qpack_fin);
    assert(handshake_stream_buffer.buffered_bytes() == sizeof(settings));
    assert(handshake_stream_buffer.events().size() == 2);
    assert(handshake_stream_buffer.events()[0].stream_id == 3);
    assert(handshake_stream_buffer.events()[0].data[1] == 0x04);
    assert(handshake_stream_buffer.events()[1].stream_id == 7);
    std::vector<uint8_t> oversized_handshake_data(HandshakeStreamBuffer::kMaxBytes + 1);
    const bool rejected_oversized_handshake_data = handshake_stream_buffer.append(
        0, 11, 0, oversized_handshake_data.data(), oversized_handshake_data.size());
    assert(!rejected_oversized_handshake_data);
    handshake_stream_buffer.clear();
    assert(handshake_stream_buffer.events().empty());
    assert(handshake_stream_buffer.buffered_bytes() == 0);

    // Local streaming backpressure is not a peer read-idle failure.
    assert(!receive_credit_blocked_by_consumer(0, 0));
    assert(receive_credit_blocked_by_consumer(kReceiveBufferPerStreamHighWatermark, 0));
    assert(receive_credit_blocked_by_consumer(0, kReceiveBufferPerConnectionLimit));

    // Linux/Android drains all immediately available UDP packets with one
    // non-blocking recvmmsg() call while preserving datagram boundaries.
    UdpSocket receiver;
    const bool receiver_opened = receiver.open(AF_INET);
    assert(receiver_opened);
    const bool receiver_bound = receiver.bind_any();
    assert(receiver_bound);
    receiver.set_nonblocking();
    sockaddr_storage receiver_address{};
    socklen_t receiver_address_length = sizeof(receiver_address);
    const bool receiver_address_available =
        receiver.local_address(receiver_address, receiver_address_length);
    assert(receiver_address_available);
    const auto* receiver_v4 = reinterpret_cast<const sockaddr_in*>(&receiver_address);
    UdpSocket sender;
    const bool sender_opened = sender.open(AF_INET);
    assert(sender_opened);
    const bool sender_connected =
        sender.connect({"127.0.0.1", ntohs(receiver_v4->sin_port), static_cast<int>(AF_INET)});
    assert(sender_connected);
    const std::array<uint8_t, 3> first{{1, 2, 3}};
    const std::array<uint8_t, 2> second{{4, 5}};
    const std::array<uint8_t, 1> third{{6}};
    const ssize_t first_sent = sender.send({first.data(), first.size(), 0});
    const ssize_t second_sent = sender.send({second.data(), second.size(), 0});
    const ssize_t third_sent = sender.send({third.data(), third.size(), 0});
    assert(first_sent == static_cast<ssize_t>(first.size()));
    assert(second_sent == static_cast<ssize_t>(second.size()));
    assert(third_sent == static_cast<ssize_t>(third.size()));
    std::array<std::array<uint8_t, 16>, 3> receive_storage{};
    std::array<UdpReceiveDatagram, 3> received_datagrams{};
    for (size_t i = 0; i < received_datagrams.size(); ++i) {
        received_datagrams[i].data = receive_storage[i].data();
        received_datagrams[i].capacity = receive_storage[i].size();
    }
    const ssize_t received_count =
        receiver.recv_batch(received_datagrams.data(), received_datagrams.size());
    assert(received_count == 3);
    assert(received_datagrams[0].size == first.size());
    assert(received_datagrams[1].size == second.size());
    assert(received_datagrams[2].size == third.size());
    assert(receive_storage[0][0] == 1 && receive_storage[1][0] == 4 && receive_storage[2][0] == 6);

    JniBodyBatch jni_batch;
    const std::array<uint8_t, 4> jni_chunk{{1, 2, 3, 4}};
    const size_t first_jni_append = jni_batch.append(jni_chunk.data(), jni_chunk.size(), 100);
    assert(first_jni_append == jni_chunk.size());
    assert(!jni_batch.should_flush(100));
    const size_t second_jni_append =
        jni_batch.append(jni_chunk.data(), jni_chunk.size(), 100 + JniBodyBatch::kFlushDelayNs - 1);
    assert(second_jni_append == jni_chunk.size());
    assert(!jni_batch.should_flush(100 + JniBodyBatch::kFlushDelayNs - 1));
    const size_t third_jni_append =
        jni_batch.append(jni_chunk.data(), jni_chunk.size(), 100 + JniBodyBatch::kFlushDelayNs);
    assert(third_jni_append == jni_chunk.size());
    assert(jni_batch.should_flush(100 + JniBodyBatch::kFlushDelayNs));
    assert(jni_batch.size() == jni_chunk.size() * 3);
    jni_batch.clear();
    std::vector<uint8_t> full_jni_batch(JniBodyBatch::kFlushBytes);
    const size_t full_jni_append =
        jni_batch.append(full_jni_batch.data(), full_jni_batch.size(), 200);
    assert(full_jni_append == full_jni_batch.size());
    assert(jni_batch.should_flush(200));

    WakeupCoalescer credit_wakeup;
    const bool first_credit_wakeup = credit_wakeup.request();
    const bool duplicate_credit_wakeup = credit_wakeup.request();
    assert(first_credit_wakeup);
    assert(!duplicate_credit_wakeup);
    assert(credit_wakeup.pending());
    credit_wakeup.reset();
    const bool reset_credit_wakeup = credit_wakeup.request();
    assert(reset_credit_wakeup);

    DnsWaitState dns_wait;
    bool dns_wait_observed = false;
    std::thread dns_wait_thread([&] {
        std::unique_lock<std::mutex> lock(dns_wait.mutex);
        dns_wait.changed.wait(lock, [&] { return dns_wait.complete; });
        dns_wait_observed = true;
    });
    {
        std::lock_guard<std::mutex> lock(dns_wait.mutex);
        dns_wait.complete = true;
    }
    dns_wait.changed.notify_all();
    dns_wait_thread.join();
    assert(dns_wait_observed);

    DnsCache cache({.max_entries = 1, .positive_ttl_ms = 1000, .negative_ttl_ms = 1000});
    cache.put_success("ONE.TEST.", 443, 1, endpoints);
    std::vector<ResolvedEndpoint> cached;
    const bool positive_cache_hit = cache.lookup("one.test", 443, 1, cached);
    assert(positive_cache_hit && cached.size() == 2);
    cache.put_failure("missing.test", 443, 1);
    cached.clear();
    const bool negative_cache_hit = cache.lookup("missing.test", 443, 1, cached);
    assert(negative_cache_hit && cached.empty());
    cache.invalidate_network(2);
    const bool invalidated_cache_hit = cache.lookup("one.test", 443, 1, cached);
    assert(!invalidated_cache_hit);

    DnsCache short_success_cache;
    short_success_cache.put_success("platform.test", 443, 1, endpoints);
    cached.clear();
    const bool platform_positive_cache_hit =
        short_success_cache.lookup("platform.test", 443, 1, cached);
    assert(platform_positive_cache_hit);
    short_success_cache.put_failure("missing-platform.test", 443, 1);
    const bool platform_negative_cache_hit =
        short_success_cache.lookup("missing-platform.test", 443, 1, cached);
    assert(!platform_negative_cache_hit);

    // Network generation identity is exact: generation 1 must not retain the
    // entries for 10, 11, or any other decimal string with the same prefix.
    DnsCache generation_exact_cache(
        {.max_entries = 8, .positive_ttl_ms = 1000, .negative_ttl_ms = 0});
    generation_exact_cache.put_success("generation.test", 443, 1, endpoints);
    generation_exact_cache.put_success("generation.test", 443, 10, endpoints);
    generation_exact_cache.put_success("generation.test", 443, 2, endpoints);
    generation_exact_cache.put_success("generation.test", 443, 20, endpoints);
    generation_exact_cache.invalidate_network(1);
    cached.clear();
    const bool generation_one_hit =
        generation_exact_cache.lookup("generation.test", 443, 1, cached);
    assert(generation_one_hit);
    const bool generation_ten_hit =
        generation_exact_cache.lookup("generation.test", 443, 10, cached);
    assert(!generation_ten_hit);
    const bool generation_two_hit =
        generation_exact_cache.lookup("generation.test", 443, 2, cached);
    assert(!generation_two_hit);
    const bool generation_twenty_hit =
        generation_exact_cache.lookup("generation.test", 443, 20, cached);
    assert(!generation_twenty_hit);
    std::cout << "core tests passed\n";
}
