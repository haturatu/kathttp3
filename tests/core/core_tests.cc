#include <sys/socket.h>

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <memory>
#include <mutex>

#include "cookie_jar.h"
#include "dns.h"
#include "flow_control.h"
#include "handshake_race.h"
#include "header_list.h"
#include "precommit_failover.h"
#include "redirect.h"
#include "time_util.h"
#include "url.h"

using namespace kathttp3;
int main() {
    Url u;
    assert(parse_url("https://example.com/a?q=1#ignored", u));
    assert(u.host == "example.com" && u.request_target() == "/a?q=1");
    assert(!parse_url("http://example.com", u));
    assert(!parse_url("https://example.com:99999/", u));
    assert(parse_url("https://[::1]:443/", u));
    HeaderList h;
    h.add("Content-Type", "text/plain");
    assert(h.get("content-type") == "text/plain");
    Response response;
    response.status_code = 303;
    response.headers.add("location", "/next");
    Url from;
    assert(parse_url("https://example.com/a/b", from));
    RedirectPolicy redirects;
    auto d = redirects.evaluate("POST", from, response, true, 3);
    assert(d.follow && d.new_method == "GET" && d.new_url == "https://example.com/next");
    response.status_code = 307;
    response.headers.clear();
    response.headers.add("location", "https://other.example/next");
    d = redirects.evaluate("POST", from, response, true, 3);
    assert(d.follow && d.cross_origin && d.new_method == "POST");
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
    const HappyEyeballsPlan v6_primary = make_happy_eyeballs_plan(endpoints);
    assert(v6_primary.enabled() && v6_primary.primary == 0 && v6_primary.fallback == 1);
    std::vector<ResolvedEndpoint> v4_primary{
        {"192.0.2.2", 443, AF_INET}, {"2001:db8::2", 443, AF_INET6}, {"192.0.2.3", 443, AF_INET}};
    const HappyEyeballsPlan v4_plan = make_happy_eyeballs_plan(v4_primary);
    assert(v4_plan.enabled() && v4_plan.primary == 0 && v4_plan.fallback == 1);
    assert(!make_happy_eyeballs_plan({v4_primary.front()}).enabled());
    assert(!make_happy_eyeballs_plan({{"invalid", 443, 0}, v4_primary.front()}).enabled());

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

    // Local streaming backpressure is not a peer read-idle failure.
    assert(!receive_credit_blocked_by_consumer(0, 0));
    assert(receive_credit_blocked_by_consumer(kReceiveBufferPerStreamHighWatermark, 0));
    assert(receive_credit_blocked_by_consumer(0, kReceiveBufferPerConnectionLimit));

    DnsCache cache({.max_entries = 1, .positive_ttl_ms = 1000, .negative_ttl_ms = 1000});
    cache.put_success("one.test", 443, 1, endpoints);
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
    std::cout << "core tests passed\n";
}
