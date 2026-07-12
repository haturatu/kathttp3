#ifndef KATHTTP_TIME_UTIL_H
#define KATHTTP_TIME_UTIL_H

#include <cstdint>
#include <ctime>

namespace kathttp {

/* Nanosecond timestamp used throughout ngtcp2 / nghttp3. */
inline uint64_t timestamp_now_ns() {
  struct timespec ts {};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + ts.tv_nsec;
}

} /* namespace kathttp */

#endif /* KATHTTP_TIME_UTIL_H */
