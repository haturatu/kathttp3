#ifndef KATHTTP3_UDP_ERROR_H
#define KATHTTP3_UDP_ERROR_H

#include <cerrno>

namespace kathttp3 {

inline bool udp_error_is_temporary(int error) {
    return error == EAGAIN || error == EWOULDBLOCK || error == ENOBUFS || error == EINTR;
}

inline bool udp_error_is_network_lost(int error) {
    return error == ENETUNREACH || error == EHOSTUNREACH || error == ENETDOWN ||
           error == ECONNRESET;
}

}  // namespace kathttp3

#endif
