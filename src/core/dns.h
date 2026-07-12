#ifndef KATHTTP_DNS_H
#define KATHTTP_DNS_H

#include <cstdint>
#include <string>
#include <vector>

namespace kathttp {

struct ResolvedEndpoint {
  std::string ip;   /* textual IPv4 or IPv6 */
  uint16_t port;
  int family;       /* AF_INET / AF_INET6 */
};

/* Pluggable name resolution. The QUIC layer calls resolve() on its own
 * worker thread, so a blocking implementation is acceptable. The default
 * GetAddrInfoResolver covers non-Android builds; on Android the resolved
 * IPs are normally supplied per-request via kathttp_request_add_address()
 * (obtained from the platform DnsResolver bound to a Network). */
class Resolver {
public:
  virtual ~Resolver() = default;
  virtual std::vector<ResolvedEndpoint> resolve(const std::string &host,
                                                uint16_t port) = 0;
};

class GetAddrInfoResolver : public Resolver {
public:
  std::vector<ResolvedEndpoint> resolve(const std::string &host,
                                        uint16_t port) override;
};

} /* namespace kathttp */

#endif /* KATHTTP_DNS_H */
