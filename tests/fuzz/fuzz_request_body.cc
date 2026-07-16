#include <cstddef>
#include <cstdint>

#include "request_body_offset.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    const size_t total = static_cast<size_t>(data[0]);
    const size_t offset = static_cast<size_t>(data[1]);
    size_t remaining = 0;
    if (kathttp3::request_body_remaining(total, offset, &remaining)) {
        const size_t chunk = kathttp3::request_body_next_chunk_size(remaining);
        (void)kathttp3::request_body_can_advance(offset, chunk, total);
    }
    return 0;
}
