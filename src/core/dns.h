#ifndef KATHTTP_DNS_H
#define KATHTTP_DNS_H

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace kathttp {

struct ResolvedEndpoint {
  std::string ip;   /* textual IPv4 or IPv6 */
  uint16_t port;
  int family;       /* AF_INET / AF_INET6 */
};

/* Pluggable name resolution. resolve() runs on the QUIC worker thread;
 * `stop` (when non-null) lets a long/blocking resolution abort when the
 * request is cancelled. The default GetAddrInfoResolver covers non-Android
 * builds; on Android the per-request addresses are usually supplied via
 * kathttp_request_add_address(). A custom Resolver (e.g. DNS-over-HTTPS)
 * can be injected through the client options. */
class Resolver {
public:
  virtual ~Resolver() = default;
  virtual std::vector<ResolvedEndpoint> resolve(
      const std::string &host, uint16_t port,
      const std::atomic<bool> *stop = nullptr) = 0;
};

class GetAddrInfoResolver : public Resolver {
public:
  std::vector<ResolvedEndpoint> resolve(
      const std::string &host, uint16_t port,
      const std::atomic<bool> *stop = nullptr) override;
};

/* Resolver backed by a C++ callback, used to adapt the C kathttp_resolve_cb
 * hook into the Resolver interface. */
class CallbackResolver : public Resolver {
public:
  using Fn = std::function<std::vector<ResolvedEndpoint>(
      const std::string &, uint16_t, const std::atomic<bool> *)>;
  explicit CallbackResolver(Fn fn) : fn_(std::move(fn)) {}
  std::vector<ResolvedEndpoint> resolve(
      const std::string &host, uint16_t port,
      const std::atomic<bool> *stop = nullptr) override {
    return fn_ ? fn_(host, port, stop) : std::vector<ResolvedEndpoint>{};
  }

private:
  Fn fn_;
};

} /* namespace kathttp */

#endif /* KATHTTP_DNS_H */
