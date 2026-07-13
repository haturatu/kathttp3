#include "udp_socket.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/udp.h>
#endif

#include <cerrno>
#include <cstring>

#include "log.h"

namespace kathttp3 {

static void enable_ecn(int fd, int family) {
    int on = 1;
    if (family == AF_INET) {
        setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on));
    } else if (family == AF_INET6) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on));
    }
}

UdpSocket::~UdpSocket() {
    close();
}

UdpSocket::UdpSocket(UdpSocket&& other) noexcept
    : fd_(other.fd_),
      family_(other.family_),
      connected_(other.connected_),
      send_queue_(std::move(other.send_queue_)),
      queued_bytes_(other.queued_bytes_),
      gso_supported_(other.gso_supported_) {
    other.fd_ = -1;
    other.family_ = 0;
    other.connected_ = false;
    other.queued_bytes_ = 0;
    other.gso_supported_ = true;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& other) noexcept {
    if (this == &other) return *this;
    close();
    fd_ = other.fd_;
    family_ = other.family_;
    connected_ = other.connected_;
    send_queue_ = std::move(other.send_queue_);
    queued_bytes_ = other.queued_bytes_;
    gso_supported_ = other.gso_supported_;
    other.fd_ = -1;
    other.family_ = 0;
    other.connected_ = false;
    other.queued_bytes_ = 0;
    other.gso_supported_ = true;
    return *this;
}

void UdpSocket::close() {
    send_queue_.clear();
    queued_bytes_ = 0;
    if (fd_ != -1) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool UdpSocket::open(int family) {
    family_ = family;
    fd_ = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ == -1) {
        KATHTTP3_LOG_ERR("socket() failed: %s\n", strerror(errno));
        return false;
    }
    enable_ecn(fd_, family);
    return true;
}

void UdpSocket::set_nonblocking() {
    if (fd_ == -1) return;
    int flags = fcntl(fd_, F_GETFL, 0);
    fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
}

bool UdpSocket::bind_any() {
    if (fd_ == -1) return false;
    if (family_ == AF_INET6) {
        sockaddr_in6 v6{};
        v6.sin6_family = AF_INET6;
        v6.sin6_addr = in6addr_any;
        v6.sin6_port = 0;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&v6), sizeof(v6)) != 0) {
            KATHTTP3_LOG_ERR("bind() v6 failed: %s\n", strerror(errno));
            return false;
        }
    } else {
        sockaddr_in v4{};
        v4.sin_family = AF_INET;
        v4.sin_addr.s_addr = INADDR_ANY;
        v4.sin_port = 0;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&v4), sizeof(v4)) != 0) {
            KATHTTP3_LOG_ERR("bind() v4 failed: %s\n", strerror(errno));
            return false;
        }
    }
    connected_ = false;
    return true;
}

bool UdpSocket::connect(const ResolvedEndpoint& ep) {
    sockaddr_storage ss{};
    socklen_t len = 0;
    family_ = ep.family;
    if (ep.family == AF_INET) {
        auto* sa = reinterpret_cast<sockaddr_in*>(&ss);
        sa->sin_family = AF_INET;
        sa->sin_port = htons(ep.port);
        inet_pton(AF_INET, ep.ip.c_str(), &sa->sin_addr);
        len = sizeof(*sa);
    } else if (ep.family == AF_INET6) {
        auto* sa = reinterpret_cast<sockaddr_in6*>(&ss);
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(ep.port);
        inet_pton(AF_INET6, ep.ip.c_str(), &sa->sin6_addr);
        len = sizeof(*sa);
    } else {
        return false;
    }
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&ss), len) != 0) {
        KATHTTP3_LOG_ERR("connect() to %s:%u failed: %s\n", ep.ip.c_str(), ep.port,
                         strerror(errno));
        return false;
    }
    connected_ = true;
    return true;
}

ssize_t UdpSocket::send_now(const uint8_t* data, size_t len, unsigned int ecn) {
    if (fd_ == -1) return -1;
    msghdr msg{};
    iovec iov{};
    iov.iov_base = const_cast<uint8_t*>(data);
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    uint8_t ctrl[CMSG_SPACE(sizeof(int))]{};
    msg.msg_control = ctrl;
    msg.msg_controllen = sizeof(ctrl);
    auto* cm = CMSG_FIRSTHDR(&msg);
    if (family_ == AF_INET) {
        cm->cmsg_level = IPPROTO_IP;
        cm->cmsg_type = IP_TOS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        *reinterpret_cast<int*>(CMSG_DATA(cm)) = static_cast<int>(ecn);
    } else {
        cm->cmsg_level = IPPROTO_IPV6;
        cm->cmsg_type = IPV6_TCLASS;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        *reinterpret_cast<int*>(CMSG_DATA(cm)) = static_cast<int>(ecn);
    }

    return ::sendmsg(fd_, &msg, 0);
}

ssize_t UdpSocket::send_now_gso(const uint8_t* data, size_t len, uint16_t segment_size,
                                unsigned int ecn) {
#if defined(__linux__) && defined(UDP_SEGMENT)
    if (fd_ == -1 || segment_size == 0) return -1;
    msghdr msg{};
    iovec iov{};
    iov.iov_base = const_cast<uint8_t*>(data);
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    alignas(cmsghdr) uint8_t ctrl[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint16_t))]{};
    msg.msg_control = ctrl;
    msg.msg_controllen = sizeof(ctrl);
    auto* ecn_cm = CMSG_FIRSTHDR(&msg);
    ecn_cm->cmsg_level = family_ == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
    ecn_cm->cmsg_type = family_ == AF_INET ? IP_TOS : IPV6_TCLASS;
    ecn_cm->cmsg_len = CMSG_LEN(sizeof(int));
    *reinterpret_cast<int*>(CMSG_DATA(ecn_cm)) = static_cast<int>(ecn);
    auto* gso_cm = CMSG_NXTHDR(&msg, ecn_cm);
    if (!gso_cm) {
        errno = EINVAL;
        return -1;
    }
    gso_cm->cmsg_level = SOL_UDP;
    gso_cm->cmsg_type = UDP_SEGMENT;
    gso_cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    *reinterpret_cast<uint16_t*>(CMSG_DATA(gso_cm)) = segment_size;
    return ::sendmsg(fd_, &msg, 0);
#else
    (void)data;
    (void)len;
    (void)segment_size;
    (void)ecn;
    errno = ENOTSUP;
    return -1;
#endif
}

ssize_t UdpSocket::send(const uint8_t* data, size_t len, unsigned int ecn) {
    ssize_t n = send_now(data, len, ecn);
    if (n == static_cast<ssize_t>(len)) return n;
    if (n >= 0) {
        errno = EIO;
        return -1;
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS) return -1;
    if (send_queue_.size() >= kMaxQueuedPackets || queued_bytes_ + len > kMaxQueuedBytes) {
        errno = ENOBUFS;
        return -1;
    }
    send_queue_.push_back({std::vector<uint8_t>(data, data + len), ecn});
    queued_bytes_ += len;
    return static_cast<ssize_t>(len);
}

bool UdpSocket::flush_send_queue() {
    while (!send_queue_.empty()) {
        auto& packet = send_queue_.front();
        // Linux/Android UDP GSO may only combine identically sized datagrams.
        // Batch only queued packets, preserving strict FIFO order and falling
        // back permanently after a runtime capability error.
        if (gso_supported_ && packet.data.size() <= UINT16_MAX && send_queue_.size() > 1) {
            const size_t segment_size = packet.data.size();
            const unsigned int ecn = packet.ecn;
            size_t count = 1;
            size_t bytes = segment_size;
            for (auto it = std::next(send_queue_.begin()); it != send_queue_.end() && count < 16;
                 ++it) {
                if (it->ecn != ecn || it->data.size() != segment_size) break;
                ++count;
                bytes += segment_size;
            }
            if (count > 1) {
                std::vector<uint8_t> aggregate;
                aggregate.reserve(bytes);
                for (size_t i = 0; i < count; ++i) {
                    const auto& queued = send_queue_[i];
                    aggregate.insert(aggregate.end(), queued.data.begin(), queued.data.end());
                }
                ssize_t n = send_now_gso(aggregate.data(), aggregate.size(),
                                         static_cast<uint16_t>(segment_size), ecn);
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS))
                    return true;
                if (n < 0 && (errno == EINVAL || errno == ENOPROTOOPT || errno == ENOTSUP)) {
                    gso_supported_ = false;
                    continue;
                }
                if (n != static_cast<ssize_t>(aggregate.size())) return false;
                for (size_t i = 0; i < count; ++i) {
                    queued_bytes_ -= send_queue_.front().data.size();
                    send_queue_.pop_front();
                }
                continue;
            }
        }
        ssize_t n = send_now(packet.data.data(), packet.data.size(), packet.ecn);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) return true;
        if (n != static_cast<ssize_t>(packet.data.size())) return false;
        queued_bytes_ -= packet.data.size();
        send_queue_.pop_front();
    }
    return true;
}

ssize_t UdpSocket::recv(uint8_t* buf, size_t buflen, sockaddr_storage& from, socklen_t& fromlen,
                        unsigned int& ecn) {
    if (fd_ == -1) return -1;
    fromlen = sizeof(from);
    msghdr msg{};
    iovec iov{};
    iov.iov_base = buf;
    iov.iov_len = buflen;
    msg.msg_name = &from;
    msg.msg_namelen = fromlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    uint8_t ctrl[256]{};
    msg.msg_control = ctrl;
    msg.msg_controllen = sizeof(ctrl);

    ssize_t n = ::recvmsg(fd_, &msg, 0);
    ecn = 0;
    if (n <= 0) return n;
    fromlen = msg.msg_namelen;
    for (auto* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
        if (family_ == AF_INET && cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_TOS) {
            ecn = static_cast<unsigned int>(*reinterpret_cast<int*>(CMSG_DATA(cm)));
        } else if (family_ == AF_INET6 && cm->cmsg_level == IPPROTO_IPV6 &&
                   cm->cmsg_type == IPV6_TCLASS) {
            ecn = static_cast<unsigned int>(*reinterpret_cast<int*>(CMSG_DATA(cm)));
        }
    }
    return n;
}

} /* namespace kathttp3 */
