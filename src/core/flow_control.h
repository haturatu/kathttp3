#pragma once

#include <cstddef>
#include <cstdint>

namespace kathttp3 {

// These values are advertised as QUIC receive windows for streaming response
// bodies. They bound data delivered to Kotlin but not yet acknowledged.
constexpr uint64_t kReceiveBufferPerStreamHighWatermark = 1ULL * 1024 * 1024;
constexpr uint64_t kReceiveBufferPerStreamLowWatermark = 512ULL * 1024;
constexpr uint64_t kReceiveBufferPerConnectionLimit = 8ULL * 1024 * 1024;
constexpr size_t kReceiveCreditThreshold = 64U * 1024;

inline bool receive_credit_blocked_by_consumer(size_t stream_unconsumed,
                                               size_t connection_unconsumed) {
    return stream_unconsumed >= kReceiveBufferPerStreamHighWatermark ||
           connection_unconsumed >= kReceiveBufferPerConnectionLimit;
}

}  // namespace kathttp3
