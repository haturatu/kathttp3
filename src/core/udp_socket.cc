#include "udp_socket.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#if defined(__ANDROID__)
#include <android/multinetwork.h>
#endif
#if defined(__linux__)
#include <linux/udp.h>
#endif

#include <cerrno>
#include <cstring>

#include "log.h"

namespace kathttp3 {

namespace {
void decode_receive_metadata(int family, msghdr& msg, UdpReceiveDatagram& datagram) {
    datagram.peer_length = msg.msg_namelen;
    datagram.ecn = 0;
    for (auto* cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
        if (family == AF_INET && cm->cmsg_level == IPPROTO_IP && cm->cmsg_type == IP_TOS) {
            datagram.ecn = static_cast<uint8_t>(*reinterpret_cast<int*>(CMSG_DATA(cm)));
        } else if (family == AF_INET6 && cm->cmsg_level == IPPROTO_IPV6 &&
                   cm->cmsg_type == IPV6_TCLASS) {
            datagram.ecn = static_cast<uint8_t>(*reinterpret_cast<int*>(CMSG_DATA(cm)));
        }
    }
}
}  // namespace

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

bool UdpSocket::open(int family, NetworkHandle network) {
    family_ = family;
    fd_ = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ == -1) {
        KATHTTP3_LOG_ERR("socket() failed: %s\n", strerror(errno));
        return false;
    }
#if defined(__ANDROID__)
    if (network.value != 0 &&
        android_setsocknetwork(static_cast<net_handle_t>(network.value), fd_) != 0) {
        KATHTTP3_LOG_WARN("android_setsocknetwork failed: %s\n", strerror(errno));
        close();
        return false;
    }
#else
    (void)network;
#endif
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

bool UdpSocket::local_address(sockaddr_storage& address, socklen_t& length) const {
    length = sizeof(address);
    return fd_ != -1 && getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &length) == 0;
}

bool UdpSocket::remote_address(sockaddr_storage& address, socklen_t& length) const {
    length = sizeof(address);
    return fd_ != -1 && getpeername(fd_, reinterpret_cast<sockaddr*>(&address), &length) == 0;
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
    // IPPROTO_UDP is the portable socket-level spelling used for UDP_SEGMENT;
    // some host libc headers used by clang-tidy do not expose SOL_UDP.
    gso_cm->cmsg_level = IPPROTO_UDP;
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

ssize_t UdpSocket::send(UdpSendDatagram datagram) {
    if (!datagram.data || datagram.size == 0) {
        errno = EINVAL;
        return -1;
    }
    const unsigned int ecn = datagram.ecn;
    ssize_t n = send_now(datagram.data, datagram.size, ecn);
    if (n == static_cast<ssize_t>(datagram.size)) return n;
    if (n >= 0) {
        errno = EIO;
        return -1;
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS) return -1;
    if (send_queue_.size() >= kMaxQueuedPackets ||
        queued_bytes_ + datagram.size > kMaxQueuedBytes) {
        errno = ENOBUFS;
        return -1;
    }
    send_queue_.push_back(
        {std::vector<uint8_t>(datagram.data, datagram.data + datagram.size), ecn});
    queued_bytes_ += datagram.size;
    return static_cast<ssize_t>(datagram.size);
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

ssize_t UdpSocket::recv(UdpReceiveDatagram& datagram) {
    if (fd_ == -1) return -1;
    if (!datagram.data || datagram.capacity == 0) {
        errno = EINVAL;
        return -1;
    }
    datagram.peer_length = sizeof(datagram.peer);
    msghdr msg{};
    iovec iov{};
    iov.iov_base = datagram.data;
    iov.iov_len = datagram.capacity;
    msg.msg_name = &datagram.peer;
    msg.msg_namelen = datagram.peer_length;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    uint8_t ctrl[256]{};
    msg.msg_control = ctrl;
    msg.msg_controllen = sizeof(ctrl);

    ssize_t n = ::recvmsg(fd_, &msg, 0);
    datagram.size = 0;
    datagram.ecn = 0;
    if (n <= 0) return n;
    if ((msg.msg_flags & MSG_TRUNC) != 0) {
        errno = EMSGSIZE;
        return -1;
    }
    datagram.size = static_cast<size_t>(n);
    decode_receive_metadata(family_, msg, datagram);
    return n;
}

ssize_t UdpSocket::recv_batch(UdpReceiveDatagram* datagrams, size_t count) {
    if (fd_ == -1) return -1;
    if (!datagrams || count == 0 || count > kMaxReceiveBatch) {
        errno = EINVAL;
        return -1;
    }
#if defined(__linux__) || defined(__ANDROID__)
    std::array<mmsghdr, kMaxReceiveBatch> messages{};
    std::array<iovec, kMaxReceiveBatch> iov{};
    std::array<std::array<uint8_t, 256>, kMaxReceiveBatch> controls{};
    for (size_t i = 0; i < count; ++i) {
        auto& datagram = datagrams[i];
        if (!datagram.data || datagram.capacity == 0) {
            errno = EINVAL;
            return -1;
        }
        datagram.size = 0;
        datagram.ecn = 0;
        datagram.peer_length = sizeof(datagram.peer);
        iov[i].iov_base = datagram.data;
        iov[i].iov_len = datagram.capacity;
        messages[i].msg_hdr.msg_name = &datagram.peer;
        messages[i].msg_hdr.msg_namelen = datagram.peer_length;
        messages[i].msg_hdr.msg_iov = &iov[i];
        messages[i].msg_hdr.msg_iovlen = 1;
        messages[i].msg_hdr.msg_control = controls[i].data();
        messages[i].msg_hdr.msg_controllen = controls[i].size();
    }
    const int received =
        ::recvmmsg(fd_, messages.data(), static_cast<unsigned int>(count), MSG_DONTWAIT, nullptr);
    if (received <= 0) return received;
    for (int i = 0; i < received; ++i) {
        auto& datagram = datagrams[static_cast<size_t>(i)];
        auto& message = messages[static_cast<size_t>(i)];
        if ((message.msg_hdr.msg_flags & MSG_TRUNC) != 0) {
            datagram.size = 0;
            continue;
        }
        datagram.size = message.msg_len;
        decode_receive_metadata(family_, message.msg_hdr, datagram);
    }
    return received;
#else
    ssize_t received = 0;
    while (static_cast<size_t>(received) < count) {
        const ssize_t size = recv(datagrams[static_cast<size_t>(received)]);
        if (size > 0) {
            ++received;
            continue;
        }
        if (received > 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return received;
        return received > 0 ? received : size;
    }
    return received;
#endif
}

} /* namespace kathttp3 */
