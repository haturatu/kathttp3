#ifndef KATHTTP3_TIME_UTIL_H
#define KATHTTP3_TIME_UTIL_H

#include <chrono>
#include <cstdint>
#include <ctime>
#include <limits>
#include <optional>
#include <type_traits>

namespace kathttp3 {

/* Nanosecond timestamp used throughout ngtcp2 / nghttp3. */
inline uint64_t timestamp_now_ns() {
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0) return 0;
    constexpr uint64_t kNanosecondsPerSecond = 1'000'000'000ULL;
    constexpr uint64_t kMax = std::numeric_limits<uint64_t>::max();
    const uint64_t seconds = static_cast<uint64_t>(ts.tv_sec);
    const uint64_t nanoseconds = static_cast<uint64_t>(ts.tv_nsec);
    if (seconds > kMax / kNanosecondsPerSecond) return kMax;
    const uint64_t base = seconds * kNanosecondsPerSecond;
    return nanoseconds > kMax - base ? kMax : base + nanoseconds;
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

/* Build a condition-variable deadline without first narrowing a public
 * uint64 millisecond value into a signed duration or overflowing the clock's
 * time_point. Values that cannot fit before time_point::max() use max() as
 * the deadline and remain bounded by the caller's other stop conditions. */
inline std::chrono::steady_clock::time_point steady_deadline_after_ms(
    uint64_t milliseconds) noexcept {
    using Clock = std::chrono::steady_clock;
    using Milliseconds = std::chrono::milliseconds;

    const auto now = Clock::now();
    const auto remaining = Clock::time_point::max() - now;
    const auto remaining_ms = std::chrono::duration_cast<Milliseconds>(remaining);
    if (remaining_ms.count() <= 0) return Clock::time_point::max();
    const uint64_t max_milliseconds = static_cast<uint64_t>(remaining_ms.count());
    if (milliseconds >= max_milliseconds) return Clock::time_point::max();

    return now + std::chrono::duration_cast<Clock::duration>(Milliseconds(
                         static_cast<Milliseconds::rep>(milliseconds)));
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
