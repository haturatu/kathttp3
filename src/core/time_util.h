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

/* Monotonic elapsed time with defensive saturation. A timestamp recorded by
 * a callback later in the current event-loop iteration can be newer than the
 * loop's snapshot; that is zero elapsed time, never uint64_t wraparound. */
inline uint64_t saturating_elapsed(uint64_t now, uint64_t started_at) {
    return now >= started_at ? now - started_at : 0;
}

inline uint64_t elapsed_ns(uint64_t now, uint64_t started_at) {
    return saturating_elapsed(now, started_at);
}

inline bool deadline_elapsed_ns(uint64_t now, uint64_t started_at, uint64_t timeout_ns) {
    return started_at != 0 && timeout_ns != 0 && elapsed_ns(now, started_at) >= timeout_ns;
}

} /* namespace kathttp3 */

#endif /* KATHTTP3_TIME_UTIL_H */
