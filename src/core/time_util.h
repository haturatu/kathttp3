#ifndef KATHTTP3_TIME_UTIL_H
#define KATHTTP3_TIME_UTIL_H

#include <cstdint>
#include <ctime>

namespace kathttp3 {

/* Nanosecond timestamp used throughout ngtcp2 / nghttp3. */
inline uint64_t timestamp_now_ns() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + ts.tv_nsec;
}

} /* namespace kathttp3 */

#endif /* KATHTTP3_TIME_UTIL_H */
