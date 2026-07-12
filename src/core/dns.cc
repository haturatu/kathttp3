#include "dns.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <atomic>

#include "log.h"

namespace kathttp {

namespace {
/* RFC 8305-style interleave: emit the i-th address of each family before the
 * (i+1)-th, so a dual-stack client races one v6 and one v4 together. */
std::vector<ResolvedEndpoint> interleave(const std::vector<ResolvedEndpoint> &a,
                                         const std::vector<ResolvedEndpoint> &b) {
  std::vector<ResolvedEndpoint> out;
  out.reserve(a.size() + b.size());
  size_t n = std::max(a.size(), b.size());
  for (size_t i = 0; i < n; ++i) {
    if (i < a.size()) out.push_back(a[i]);
    if (i < b.size()) out.push_back(b[i]);
  }
  return out;
}
}  // namespace

std::vector<ResolvedEndpoint> GetAddrInfoResolver::resolve(
    const std::string &host, uint16_t port, const std::atomic<bool> *stop) {
  std::vector<ResolvedEndpoint> v4, v6;
  auto one = [&](int family, std::vector<ResolvedEndpoint> &out) {
    if (stop && stop->load(std::memory_order_relaxed)) return;
    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    std::string port_str = std::to_string(port);
    addrinfo *res = nullptr;
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
      KATHTTP_LOG_ERR("getaddrinfo failed for %s:%u\n", host.c_str(), port);
      return;
    }
    for (addrinfo *rp = res; rp; rp = rp->ai_next) {
      if (rp->ai_family != family) continue;
      char buf[INET6_ADDRSTRLEN] = {0};
      if (family == AF_INET) {
        auto *sa = reinterpret_cast<sockaddr_in *>(rp->ai_addr);
        inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
      } else {
        auto *sa = reinterpret_cast<sockaddr_in6 *>(rp->ai_addr);
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
