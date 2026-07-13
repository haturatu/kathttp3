#include "dns.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

#include "log.h"

namespace kathttp {

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

    bool submit(std::function<void()> task) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_ || tasks_.size() >= kMaxQueuedTasks) return false;
        tasks_.push_back(std::move(task));
        cv_.notify_one();
        return true;
    }

   private:
    void worker() {
        for (;;) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] { return stopping_ || !tasks_.empty(); });
                if (stopping_ && tasks_.empty()) return;
                task = std::move(tasks_.front());
                tasks_.pop_front();
            }
            task();
        }
    }

    static constexpr size_t kMaxQueuedTasks = 32;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::function<void()>> tasks_;
    std::vector<std::thread> workers_;
    bool stopping_ = false;
};

DnsWorkerPool& dns_worker_pool() {
    static DnsWorkerPool pool;
    return pool;
}
}  // namespace

bool resolve_async(std::shared_ptr<Resolver> resolver, std::string host, uint16_t port,
                   std::shared_ptr<std::atomic<bool>> cancelled, DnsResolveCallback callback) {
    if (!resolver || !cancelled || !callback) return false;
    return dns_worker_pool().submit([resolver = std::move(resolver), host = std::move(host), port,
                                     cancelled = std::move(cancelled),
                                     callback = std::move(callback)]() mutable {
        if (cancelled->load(std::memory_order_acquire)) return;
        auto endpoints = resolver->resolve(host, port, cancelled.get());
        if (!cancelled->load(std::memory_order_acquire)) callback(std::move(endpoints));
    });
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
        if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
            KATHTTP_LOG_ERR("getaddrinfo failed for %s:%u\n", host.c_str(), port);
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

} /* namespace kathttp */
