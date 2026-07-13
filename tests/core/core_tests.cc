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
#include "header_list.h"
#include "redirect.h"
#include "url.h"

using namespace kathttp;
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

    DnsCache cache(1, 1000, 1000);
    cache.put_success("one.test", 443, 1, endpoints);
    std::vector<ResolvedEndpoint> cached;
    assert(cache.lookup("one.test", 443, 1, cached) && cached.size() == 2);
    cache.put_failure("missing.test", 443, 1);
    cached.clear();
    assert(cache.lookup("missing.test", 443, 1, cached) && cached.empty());
    cache.invalidate_network(2);
    assert(!cache.lookup("one.test", 443, 1, cached));
    std::cout << "core tests passed\n";
}
