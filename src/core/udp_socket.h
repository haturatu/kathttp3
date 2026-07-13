#ifndef KATHTTP_UDP_SOCKET_H
#define KATHTTP_UDP_SOCKET_H

#include <sys/socket.h>

#include <cstdint>
#include <deque>
#include <string>
#include <vector>

#include "dns.h"

namespace kathttp {

/* Non-blocking UDP socket used by a QUIC connection. Optionally connected
 * to a single peer so send()/recv() can be used, with ECN support. */
class UdpSocket {
   public:
    UdpSocket() = default;
    ~UdpSocket();

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    /* Create a socket for the given address family (AF_INET/AF_INET6). */
    bool open(int family);
    void close();

    int fd() const {
        return fd_;
    }

    /* Connect to a resolved endpoint (enables send/recv without peer addr). */
    bool connect(const ResolvedEndpoint& ep);

    /* Bind to any local address of the socket's family. */
    bool bind_any();

    void set_nonblocking();

    /* Send a datagram. `ecn` is the explicit congestion notification byte
     * (0, 1, 2, 3). Returns bytes sent or -1 on error. */
    ssize_t send(const uint8_t* data, size_t len, unsigned int ecn);
    bool flush_send_queue();
    bool wants_write() const { return !send_queue_.empty(); }

    /* Receive one datagram into buf. Fills `from` (sockaddr storage),
     * `fromlen` and `ecn`. Returns bytes received or -1. */
    ssize_t recv(uint8_t* buf, size_t buflen, sockaddr_storage& from, socklen_t& fromlen,
                 unsigned int& ecn);

   private:
    ssize_t send_now(const uint8_t* data, size_t len, unsigned int ecn);
    int fd_ = -1;
    int family_ = 0;
    bool connected_ = false;
    struct QueuedPacket { std::vector<uint8_t> data; unsigned int ecn; };
    std::deque<QueuedPacket> send_queue_;
    size_t queued_bytes_ = 0;
    static constexpr size_t kMaxQueuedPackets = 1024;
    static constexpr size_t kMaxQueuedBytes = 4 * 1024 * 1024;
};

} /* namespace kathttp */

#endif /* KATHTTP_UDP_SOCKET_H */
