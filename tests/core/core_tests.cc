#include <sys/socket.h>

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <memory>
#include <mutex>

#include "connection_state.h"
#include "cookie_jar.h"
#include "dns.h"
#include "flow_control.h"
#include "handshake_race.h"
#include "handshake_stream_buffer.h"
#include "header_list.h"
#include "network_change.h"
#include "precommit_failover.h"
#include "redirect.h"
#include "request_body_offset.h"
#include "time_util.h"
#include "udp_error.h"
#include "url.h"

using namespace kathttp3;
int main() {
    Url u;
    assert(parse_url("https://example.com/a?q=1#ignored", u));
    assert(u.host == "example.com" && u.request_target() == "/a?q=1");
    assert(u.port == 0 && u.authority() == "example.com");
    assert(parse_url("https://example.com:8443/a", u));
    assert(u.authority() == "example.com:8443");
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
    std::cout << "core tests passed\n";
}
