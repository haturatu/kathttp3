#include "udp_socket.h"

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"

namespace kathttp {

static void enable_ecn(int fd, int family) {
  int on = 1;
  if (family == AF_INET) {
    setsockopt(fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on));
  } else if (family == AF_INET6) {
    setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on));
  }
}

UdpSocket::~UdpSocket() { close(); }

void UdpSocket::close() {
  if (fd_ != -1) {
    ::close(fd_);
    fd_ = -1;
  }
}

bool UdpSocket::open(int family) {
  family_ = family;
  fd_ = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (fd_ == -1) {
    KATHTTP_LOG_ERR("socket() failed: %s\n", strerror(errno));
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
    if (::bind(fd_, reinterpret_cast<sockaddr *>(&v6), sizeof(v6)) != 0) {
      KATHTTP_LOG_ERR("bind() v6 failed: %s\n", strerror(errno));
      return false;
    }
  } else {
    sockaddr_in v4{};
    v4.sin_family = AF_INET;
    v4.sin_addr.s_addr = INADDR_ANY;
    v4.sin_port = 0;
    if (::bind(fd_, reinterpret_cast<sockaddr *>(&v4), sizeof(v4)) != 0) {
      KATHTTP_LOG_ERR("bind() v4 failed: %s\n", strerror(errno));
      return false;
    }
  }
  connected_ = false;
  return true;
}

bool UdpSocket::connect(const ResolvedEndpoint &ep) {
  sockaddr_storage ss{};
  socklen_t len = 0;
  family_ = ep.family;
  if (ep.family == AF_INET) {
    auto *sa = reinterpret_cast<sockaddr_in *>(&ss);
    sa->sin_family = AF_INET;
    sa->sin_port = htons(ep.port);
    inet_pton(AF_INET, ep.ip.c_str(), &sa->sin_addr);
    len = sizeof(*sa);
  } else if (ep.family == AF_INET6) {
    auto *sa = reinterpret_cast<sockaddr_in6 *>(&ss);
    sa->sin6_family = AF_INET6;
    sa->sin6_port = htons(ep.port);
    inet_pton(AF_INET6, ep.ip.c_str(), &sa->sin6_addr);
    len = sizeof(*sa);
  } else {
    return false;
  }
  if (::connect(fd_, reinterpret_cast<sockaddr *>(&ss), len) != 0) {
    KATHTTP_LOG_ERR("connect() to %s:%u failed: %s\n", ep.ip.c_str(), ep.port,
                    strerror(errno));
    return false;
  }
  connected_ = true;
  return true;
}

ssize_t UdpSocket::send(const uint8_t *data, size_t len, unsigned int ecn) {
  if (fd_ == -1) return -1;
  msghdr msg{};
  iovec iov{};
  iov.iov_base = const_cast<uint8_t *>(data);
  iov.iov_len = len;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  uint8_t ctrl[CMSG_SPACE(sizeof(int))]{};
  msg.msg_control = ctrl;
  msg.msg_controllen = sizeof(ctrl);
  auto *cm = CMSG_FIRSTHDR(&msg);
  if (family_ == AF_INET) {
    cm->cmsg_level = IPPROTO_IP;
    cm->cmsg_type = IP_TOS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    *reinterpret_cast<int *>(CMSG_DATA(cm)) = static_cast<int>(ecn);
  } else {
    cm->cmsg_level = IPPROTO_IPV6;
    cm->cmsg_type = IPV6_TCLASS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    *reinterpret_cast<int *>(CMSG_DATA(cm)) = static_cast<int>(ecn);
  }

  ssize_t n = ::sendmsg(fd_, &msg, 0);
  return n;
}

ssize_t UdpSocket::recv(uint8_t *buf, size_t buflen, sockaddr_storage &from,
                        socklen_t &fromlen, unsigned int &ecn) {
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
  for (auto *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
    if (family_ == AF_INET && cm->cmsg_level == IPPROTO_IP &&
        cm->cmsg_type == IP_TOS) {
      ecn = static_cast<unsigned int>(*reinterpret_cast<int *>(CMSG_DATA(cm)));
    } else if (family_ == AF_INET6 && cm->cmsg_level == IPPROTO_IPV6 &&
               cm->cmsg_type == IPV6_TCLASS) {
      ecn = static_cast<unsigned int>(*reinterpret_cast<int *>(CMSG_DATA(cm)));
    }
  }
  return n;
}

} /* namespace kathttp */
