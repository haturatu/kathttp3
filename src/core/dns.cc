#include "dns.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#if defined(__ANDROID__)
#include <android/multinetwork.h>
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <deque>
#include <iterator>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "log.h"

namespace kathttp3 {

namespace {
/* RFC 8305-style interleave: emit the i-th address of each family before the
 * (i+1)-th, so a dual-stack client races one v6 and one v4 together. */
std::vector<ResolvedEndpoint> interleave(const std::vector<ResolvedEndpoint>& a,
                                         const std::vector<ResolvedEndpoint>& b) {
    std::vector<ResolvedEndpoint> out;
    out.reserve(a.size() + b.size());
    size_t n = std::max(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        if (i < a.size()) out.push_back(a[i]);
        if (i < b.size()) out.push_back(b[i]);
    }
    return out;
}

/* DNS must never execute getaddrinfo on a QUIC worker.  A deliberately small
 * process-wide pool bounds resolver pressure during an outage; queued work is
 * cancellable before it starts.  Resolver callbacks receive owned endpoint
 * values and never access connection state. */
class DnsWorkerPool {
   public:
    DnsWorkerPool() {
        constexpr size_t kWorkerCount = 2;
        for (size_t i = 0; i < kWorkerCount; ++i) workers_.emplace_back([this] { worker(); });
    }

    ~DnsWorkerPool() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        cv_.notify_all();
        for (auto& thread : workers_)
            if (thread.joinable()) thread.join();
    }

    bool submit(std::function<void()> task, std::shared_ptr<std::atomic<bool>> cancelled) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) return false;
        prune_queue(tasks_);
        prune_queue(pending_hosts_);
        promote_pending();
        Work work{std::move(task), std::move(cancelled)};
        if (tasks_.size() < kMaxQueuedTasks) {
            tasks_.push_back(std::move(work));
        } else {
            if (pending_hosts_.size() >= kMaxPendingHosts) return false;
            pending_hosts_.push_back(std::move(work));
        }
        cv_.notify_one();
        return true;
    }

    void prune_cancelled() {
        std::lock_guard<std::mutex> lock(mutex_);
        prune_queue(tasks_);
        prune_queue(pending_hosts_);
        promote_pending();
        if (!tasks_.empty()) cv_.notify_all();
    }

   private:
    struct Work {
        std::function<void()> run;
        std::shared_ptr<std::atomic<bool>> cancelled;
    };

    static void prune_queue(std::deque<Work>& queue) {
        queue.erase(std::remove_if(queue.begin(), queue.end(),
                                   [](const Work& work) {
                                       return work.cancelled &&
                                              work.cancelled->load(std::memory_order_acquire);
                                   }),
                    queue.end());
    }

    void promote_pending() {
        while (tasks_.size() < kMaxQueuedTasks && !pending_hosts_.empty()) {
            tasks_.push_back(std::move(pending_hosts_.front()));
            pending_hosts_.pop_front();
        }
    }

    void worker() {
        for (;;) {
            Work work;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] { return stopping_ || !tasks_.empty(); });
                if (stopping_ && tasks_.empty()) return;
                work = std::move(tasks_.front());
                tasks_.pop_front();
                prune_queue(tasks_);
                prune_queue(pending_hosts_);
                promote_pending();
            }
            if (!work.cancelled || !work.cancelled->load(std::memory_order_acquire)) work.run();
        }
    }

    static constexpr size_t kMaxQueuedTasks = 32;
    static constexpr size_t kMaxPendingHosts = 128;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Work> tasks_;
    std::deque<Work> pending_hosts_;
    std::vector<std::thread> workers_;
    bool stopping_ = false;
};

DnsWorkerPool& dns_worker_pool() {
    static DnsWorkerPool pool;
    return pool;
}

std::string canonical_host(std::string host) {
    std::transform(host.begin(), host.end(), host.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (host.size() > 1 && host.back() == '.') host.pop_back();
    return host;
}

struct DnsWaiter {
    std::shared_ptr<std::atomic<bool>> cancelled;
    DnsResolveCallback callback;
};

struct DnsFlight {
    std::shared_ptr<std::atomic<bool>> cancelled = std::make_shared<std::atomic<bool>>(false);
    std::vector<DnsWaiter> waiters;
};

struct DnsTaskContext {
    std::shared_ptr<Resolver> resolver;
    std::string host;
    uint16_t port = 0;
    std::string key;
    std::shared_ptr<DnsFlight> flight;
};

constexpr size_t kMaxDnsFlightWaiters = 1024;

std::mutex& dns_flights_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::unordered_map<std::string, std::shared_ptr<DnsFlight>>& dns_flights() {
    static std::unordered_map<std::string, std::shared_ptr<DnsFlight>> flights;
    return flights;
}

std::string dns_flight_key(const Resolver* resolver, const std::string& host, uint16_t port,
                           uint64_t generation) {
    return std::to_string(reinterpret_cast<uintptr_t>(resolver)) + "|" + canonical_host(host) +
           ":" + std::to_string(port) + "@" + std::to_string(generation);
}
}  // namespace

HappyEyeballsPlan make_happy_eyeballs_plan(const std::vector<ResolvedEndpoint>& endpoints) {
    HappyEyeballsPlan plan;
    if (endpoints.empty()) return plan;
    plan.primary = 0;
    const int primary_family = endpoints.front().family;
    if (primary_family != AF_INET && primary_family != AF_INET6) {
        plan.primary = static_cast<size_t>(-1);
        return plan;
    }
    const auto fallback =
        std::find_if(std::next(endpoints.begin()), endpoints.end(),
                     [primary_family](const ResolvedEndpoint& endpoint) {
                         return endpoint.family != primary_family &&
                                (endpoint.family == AF_INET || endpoint.family == AF_INET6);
                     });
    if (fallback != endpoints.end()) {
        plan.fallback = static_cast<size_t>(std::distance(endpoints.begin(), fallback));
        return plan;
    }
    plan.primary = static_cast<size_t>(-1);
    return plan;
}

namespace {
uint64_t monotonic_ms() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now().time_since_epoch())
                                     .count());
}
}  // namespace

DnsCache::DnsCache() : DnsCache(Config{}) {}

DnsCache::DnsCache(Config config)
    : max_entries_(std::max<size_t>(1, config.max_entries)),
      positive_ttl_ms_(config.positive_ttl_ms),
      negative_ttl_ms_(config.negative_ttl_ms) {}

// Kept as a private member to centralize the cache key contract.
// cppcheck-suppress functionStatic
std::string DnsCache::key(const std::string& host, uint16_t port,
                          uint64_t network_generation) const {
    return canonical_host(host) + ":" + std::to_string(port) + "@" +
           std::to_string(network_generation);
}

bool DnsCache::lookup(const std::string& host, uint16_t port, uint64_t network_generation,
                      std::vector<ResolvedEndpoint>& endpoints) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto cache_key = key(host, port, network_generation);
    const auto now = monotonic_ms();
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (it->key != cache_key) continue;
        if (it->expires_at_ms <= now) {
            entries_.erase(it);
            return false;
        }
        entries_.splice(entries_.begin(), entries_, it);
        if (entries_.front().negative) return true;
        endpoints = entries_.front().endpoints;
        return true;
    }
    return false;
}

void DnsCache::put_success(const std::string& host, uint16_t port, uint64_t network_generation,
                           const std::vector<ResolvedEndpoint>& endpoints) {
    if (endpoints.empty()) return put_failure(host, port, network_generation);
    if (positive_ttl_ms_ == 0) return;
    put({key(host, port, network_generation), monotonic_ms() + positive_ttl_ms_, false, endpoints});
}

void DnsCache::put_failure(const std::string& host, uint16_t port, uint64_t network_generation) {
    if (negative_ttl_ms_ == 0) return;
    put({key(host, port, network_generation), monotonic_ms() + negative_ttl_ms_, true, {}});
}

void DnsCache::put(Entry entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.remove_if([&](const Entry& existing) { return existing.key == entry.key; });
    entries_.push_front(std::move(entry));
    while (entries_.size() > max_entries_) entries_.pop_back();
}

void DnsCache::invalidate_network(uint64_t network_generation) {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::string suffix = "@" + std::to_string(network_generation);
    entries_.remove_if(
        [&](const Entry& entry) { return entry.key.find(suffix) == std::string::npos; });
}

std::vector<ResolvedEndpoint> CachedResolver::resolve(const std::string& host, uint16_t port,
                                                      const std::atomic<bool>* stop) {
    const uint64_t network = generation_->load(std::memory_order_acquire);
    std::vector<ResolvedEndpoint> endpoints;
    if (cache_->lookup(host, port, network, endpoints)) return endpoints;
    endpoints = upstream_->resolve(host, port, stop);
    if (stop && stop->load(std::memory_order_acquire)) return {};
    if (endpoints.empty())
        cache_->put_failure(host, port, network);
    else
        cache_->put_success(host, port, network, endpoints);
    return endpoints;
}

bool resolve_async(std::shared_ptr<Resolver> resolver, std::string host, uint16_t port,
                   std::shared_ptr<std::atomic<bool>> cancelled, DnsResolveCallback callback) {
    if (!resolver || !cancelled || !callback) return false;
    if (cancelled->load(std::memory_order_acquire)) return true;

    const std::string key =
        dns_flight_key(resolver.get(), host, port, resolver->flight_generation());
    std::lock_guard<std::mutex> lock(dns_flights_mutex());
    auto existing = dns_flights().find(key);
    if (existing != dns_flights().end()) {
        if (existing->second->waiters.size() >= kMaxDnsFlightWaiters) return false;
        existing->second->waiters.push_back({std::move(cancelled), std::move(callback)});
        return true;
    }

    auto flight = std::make_shared<DnsFlight>();
    flight->waiters.push_back({std::move(cancelled), std::move(callback)});
    dns_flights().emplace(key, flight);
    auto task = std::make_shared<DnsTaskContext>(
        DnsTaskContext{std::move(resolver), std::move(host), port, key, flight});
    const bool submitted = dns_worker_pool().submit(
        [task]() noexcept {
            try {
                const auto& active_flight = task->flight;
                if (active_flight->cancelled->load(std::memory_order_acquire)) return;
                std::vector<ResolvedEndpoint> endpoints;
                try {
                    endpoints = task->resolver->resolve(task->host, task->port,
                                                        active_flight->cancelled.get());
                } catch (...) {
                    KATHTTP3_LOG_ERR("resolver threw for %s:%u\n", task->host.c_str(), task->port);
                }

                std::vector<DnsWaiter> waiters;
                {
                    std::lock_guard<std::mutex> flights_lock(dns_flights_mutex());
                    auto it = dns_flights().find(task->key);
                    if (it != dns_flights().end() && it->second == active_flight) {
                        waiters = std::move(it->second->waiters);
                        dns_flights().erase(it);
                    }
                }
                if (waiters.size() > 1) {
                    KATHTTP3_LOG_DEBUG(
                        "DNS single-flight completed %s:%u waiters=%zu endpoints=%zu\n",
                        task->host.c_str(), task->port, waiters.size(), endpoints.size());
                }
                for (auto& waiter : waiters) {
                    if (waiter.cancelled->load(std::memory_order_acquire)) continue;
                    try {
                        waiter.callback(endpoints);
                    } catch (...) {
                        KATHTTP3_LOG_WARN("DNS completion callback threw for %s:%u\n",
                                          task->host.c_str(), task->port);
                    }
                }
            } catch (...) {
                KATHTTP3_LOG_ERR("DNS single-flight completion failed for %s:%u\n",
                                 task->host.c_str(), task->port);
                std::lock_guard<std::mutex> flights_lock(dns_flights_mutex());
                auto it = dns_flights().find(task->key);
                if (it != dns_flights().end() && it->second == task->flight) {
                    task->flight->cancelled->store(true, std::memory_order_release);
                    dns_flights().erase(it);
                }
            }
        },
        flight->cancelled);
    if (!submitted) dns_flights().erase(key);
    return submitted;
}

void cancel_resolve(const std::shared_ptr<std::atomic<bool>>& cancelled) {
    if (!cancelled) return;
    cancelled->store(true, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(dns_flights_mutex());
        for (auto it = dns_flights().begin(); it != dns_flights().end();) {
            const auto& flight = it->second;
            flight->waiters.erase(std::remove_if(flight->waiters.begin(), flight->waiters.end(),
                                                 [&](const DnsWaiter& waiter) {
                                                     return waiter.cancelled == cancelled;
                                                 }),
                                  flight->waiters.end());
            if (flight->waiters.empty()) {
                flight->cancelled->store(true, std::memory_order_release);
                it = dns_flights().erase(it);
            } else {
                ++it;
            }
        }
    }
    dns_worker_pool().prune_cancelled();
}

std::vector<ResolvedEndpoint> GetAddrInfoResolver::resolve(const std::string& host, uint16_t port,
                                                           const std::atomic<bool>* stop) {
    std::vector<ResolvedEndpoint> v4, v6;
    auto one = [&](int family, std::vector<ResolvedEndpoint>& out) {
        if (stop && stop->load(std::memory_order_relaxed)) return;
        addrinfo hints{};
        hints.ai_family = family;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        std::string port_str = std::to_string(port);
        addrinfo* res = nullptr;
        int result = 0;
#if defined(__ANDROID__)
        const uint64_t network_handle = network_handle_->load(std::memory_order_acquire);
        result = network_handle == 0
                     ? getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res)
                     : android_getaddrinfofornetwork(static_cast<net_handle_t>(network_handle),
                                                     host.c_str(), port_str.c_str(), &hints, &res);
#else
        result = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
#endif
        if (result != 0) {
            KATHTTP3_LOG_ERR("getaddrinfo failed for %s:%u\n", host.c_str(), port);
            return;
        }
        for (addrinfo* rp = res; rp; rp = rp->ai_next) {
            if (rp->ai_family != family) continue;
            char buf[INET6_ADDRSTRLEN] = {0};
            if (family == AF_INET) {
                auto* sa = reinterpret_cast<sockaddr_in*>(rp->ai_addr);
                inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
            } else {
                auto* sa = reinterpret_cast<sockaddr_in6*>(rp->ai_addr);
                inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(buf));
            }
            out.push_back({std::string(buf), port, family});
        }
        freeaddrinfo(res);
    };
    one(AF_INET6, v6);
    if (stop && stop->load(std::memory_order_relaxed)) return v6;
    one(AF_INET, v4);
    return interleave(v6, v4);
}

} /* namespace kathttp3 */
