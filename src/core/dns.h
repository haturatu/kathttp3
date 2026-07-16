#ifndef KATHTTP3_DNS_H
#define KATHTTP3_DNS_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace kathttp3 {

struct ResolvedEndpoint {
    std::string ip; /* textual IPv4 or IPv6 */
    uint16_t port = 0;
    int family = 0; /* AF_INET / AF_INET6 */
};

/* The first two independently-startable address candidates.  The primary
 * preserves resolver ordering; fallback is the first address in the other
 * family and is scheduled after the Happy Eyeballs delay. */
struct HappyEyeballsPlan {
    size_t primary = static_cast<size_t>(-1);
    size_t fallback = static_cast<size_t>(-1);

    bool enabled() const {
        return primary != static_cast<size_t>(-1) && fallback != static_cast<size_t>(-1);
    }
};

HappyEyeballsPlan make_happy_eyeballs_plan(const std::vector<ResolvedEndpoint>& endpoints);

/* Pluggable name resolution. resolve() runs on the QUIC worker thread;
 * `stop` (when non-null) lets a long/blocking resolution abort when the
 * request is cancelled. The default GetAddrInfoResolver covers non-Android
 * builds; on Android the per-request addresses are usually supplied via
 * kathttp3_request_add_address(). A custom Resolver (e.g. DNS-over-HTTPS)
 * can be injected through the client options. */
class Resolver {
   public:
    virtual ~Resolver() = default;
    virtual std::vector<ResolvedEndpoint> resolve(const std::string& host, uint16_t port,
                                                  const std::atomic<bool>* stop = nullptr) = 0;
    /* Partitions asynchronous single-flight work. Network-aware resolvers
     * return their current generation so a request on a replacement Android
     * Network never joins an older in-flight lookup. */
    virtual uint64_t flight_generation() const {
        return 0;
    }
};

class GetAddrInfoResolver : public Resolver {
   public:
    explicit GetAddrInfoResolver(std::shared_ptr<std::atomic<uint64_t>> network_handle =
                                     std::make_shared<std::atomic<uint64_t>>(0))
        : network_handle_(std::move(network_handle)) {}
    std::vector<ResolvedEndpoint> resolve(const std::string& host, uint16_t port,
                                          const std::atomic<bool>* stop = nullptr) override;

   private:
    std::shared_ptr<std::atomic<uint64_t>> network_handle_;
};

/* Small, network-scoped cache for resolver results. A zero lifetime disables
 * that cache class. getaddrinfo/InetAddress do not expose authoritative TTLs,
 * so the default leaves caching to the platform resolver instead of extending
 * DNS data past its authoritative lifetime. Certificate, timeout and protocol
 * failures must never be inserted here. */
class DnsCache {
   public:
    struct Config {
        size_t max_entries = 128;
        /* getaddrinfo does not expose TTL. Keep this fallback deliberately
         * short; TTL-aware resolvers (such as DohResolver) retain their own
         * authoritative cache and this layer only absorbs immediate bursts. */
        uint64_t positive_ttl_ms = 5000;
        uint64_t negative_ttl_ms = 0;
    };

    DnsCache();
    explicit DnsCache(Config config);
    bool lookup(const std::string& host, uint16_t port, uint64_t network_generation,
                std::vector<ResolvedEndpoint>& endpoints);
    void put_success(const std::string& host, uint16_t port, uint64_t network_generation,
                     const std::vector<ResolvedEndpoint>& endpoints);
    void put_failure(const std::string& host, uint16_t port, uint64_t network_generation);
    void invalidate_network(uint64_t network_generation);

   private:
    struct Entry {
        std::string key;
        uint64_t expires_at_ms = 0;
        bool negative = false;
        std::vector<ResolvedEndpoint> endpoints;
    };
    std::string key(const std::string& host, uint16_t port, uint64_t network_generation) const;
    void put(Entry entry);
    size_t max_entries_;
    uint64_t positive_ttl_ms_;
    uint64_t negative_ttl_ms_;
    std::mutex mutex_;
    std::list<Entry> entries_;
};

class CachedResolver : public Resolver {
   public:
    CachedResolver(std::shared_ptr<Resolver> upstream, std::shared_ptr<DnsCache> cache,
                   std::shared_ptr<std::atomic<uint64_t>> network_generation)
        : upstream_(std::move(upstream)),
          cache_(std::move(cache)),
          generation_(std::move(network_generation)) {}
    std::vector<ResolvedEndpoint> resolve(const std::string& host, uint16_t port,
                                          const std::atomic<bool>* stop = nullptr) override;
    uint64_t flight_generation() const override {
        return generation_->load(std::memory_order_acquire);
    }

   private:
    std::shared_ptr<Resolver> upstream_;
    std::shared_ptr<DnsCache> cache_;
    std::shared_ptr<std::atomic<uint64_t>> generation_;
};

/* Resolver backed by a C++ callback, used to adapt the C kathttp3_resolve_cb
 * hook into the Resolver interface. */
class CallbackResolver : public Resolver {
   public:
    using Fn = std::function<std::vector<ResolvedEndpoint>(const std::string&, uint16_t,
                                                           const std::atomic<bool>*)>;
    explicit CallbackResolver(Fn fn) : fn_(std::move(fn)) {}
    std::vector<ResolvedEndpoint> resolve(const std::string& host, uint16_t port,
                                          const std::atomic<bool>* stop = nullptr) override {
        return fn_ ? fn_(host, port, stop) : std::vector<ResolvedEndpoint>{};
    }

   private:
    Fn fn_;
};

/* Submit resolution to KatHttp3's bounded DNS worker pool.  The callback runs
 * on a DNS worker, therefore it must not touch a QuicClient directly.  The
 * caller owns its result state and can discard it by setting `cancelled`.
 * Returning false means that both the worker queue and bounded per-host
 * overflow queue are full. */
using DnsResolveCallback = std::function<void(std::vector<ResolvedEndpoint>)>;
bool resolve_async(std::shared_ptr<Resolver> resolver, std::string host, uint16_t port,
                   std::shared_ptr<std::atomic<bool>> cancelled, DnsResolveCallback callback);
/* Remove a waiter immediately when its request is cancelled or expires. If it
 * was the last waiter, queued resolver work is discarded before execution and
 * an already-running resolver receives its cooperative stop flag. */
void cancel_resolve(const std::shared_ptr<std::atomic<bool>>& cancelled);

} /* namespace kathttp3 */

#endif /* KATHTTP3_DNS_H */
