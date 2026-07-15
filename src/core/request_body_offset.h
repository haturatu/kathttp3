#ifndef KATHTTP3_REQUEST_BODY_OFFSET_H
#define KATHTTP3_REQUEST_BODY_OFFSET_H

#include <algorithm>
#include <cstddef>

namespace kathttp3 {

/* Keep each nghttp3 data-reader result bounded and make every offset
 * subtraction explicit. This prevents a stale or duplicate reader state from
 * turning size_t underflow into an enormous HTTP/3 DATA frame. */
constexpr size_t kMaxHttp3DataReaderBytes = 64 * 1024;

inline bool request_body_remaining(size_t total, size_t offset, size_t* remaining) {
    if (offset > total) return false;
    *remaining = total - offset;
    return true;
}

inline bool request_body_can_advance(size_t offset, size_t amount, size_t limit) {
    return offset <= limit && amount <= limit - offset;
}

inline size_t request_body_next_chunk_size(size_t remaining) {
    return std::min(remaining, kMaxHttp3DataReaderBytes);
}

}  // namespace kathttp3

#endif  // KATHTTP3_REQUEST_BODY_OFFSET_H
