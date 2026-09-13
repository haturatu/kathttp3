#ifndef KATHTTP3_TIME_UTIL_H
#define KATHTTP3_TIME_UTIL_H

#include <cstdint>
#include <ctime>
#include <limits>
#include <optional>
#include <type_traits>

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

/* Convert an untrusted/public millisecond duration without allowing the
 * multiplication to wrap into a short deadline.  UINT64_MAX represents an
 * effectively unbounded duration to callers that use this helper. */
inline constexpr uint64_t milliseconds_to_ns_saturated(uint64_t milliseconds) noexcept {
    constexpr uint64_t kNanosecondsPerMillisecond = 1'000'000ULL;
    constexpr uint64_t kMax = std::numeric_limits<uint64_t>::max();
    if (milliseconds > kMax / kNanosecondsPerMillisecond) return kMax;
    return milliseconds * kNanosecondsPerMillisecond;
}

/* std::time() returns (time_t)-1 on failure.  Never turn that sentinel into a
 * huge unsigned timestamp: callers can fail closed or retain session-only
 * state when the wall clock is unavailable. */
inline std::optional<uint64_t> wall_clock_seconds() noexcept {
    const std::time_t now = std::time(nullptr);
    if (now == static_cast<std::time_t>(-1)) return std::nullopt;
    if constexpr (std::is_signed_v<std::time_t>) {
        if (now < 0) return std::nullopt;
    }
    return static_cast<uint64_t>(now);
}

} /* namespace kathttp3 */

#endif /* KATHTTP3_TIME_UTIL_H */
