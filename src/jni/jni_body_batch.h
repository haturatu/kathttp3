#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace kathttp3 {

class JniBodyBatch {
   public:
    static constexpr size_t kFlushBytes = 64U * 1024;
    static constexpr uint64_t kFlushDelayNs = 1U * 1000 * 1000;

    size_t append(const uint8_t* data, size_t len, uint64_t now_ns) {
        if (!data || len == 0 || size_ == bytes_.size()) return 0;
        if (size_ == 0) first_byte_at_ns_ = now_ns;
        const size_t copied = std::min(len, bytes_.size() - size_);
        std::memcpy(bytes_.data() + size_, data, copied);
        size_ += copied;
        return copied;
    }

    bool should_flush(uint64_t now_ns) const {
        return size_ == bytes_.size() || (size_ != 0 && now_ns >= first_byte_at_ns_ &&
                                          now_ns - first_byte_at_ns_ >= kFlushDelayNs);
    }

    const uint8_t* data() const {
        return bytes_.data();
    }

    size_t size() const {
        return size_;
    }

    bool empty() const {
        return size_ == 0;
    }

    void clear() {
        size_ = 0;
        first_byte_at_ns_ = 0;
    }

   private:
    std::array<uint8_t, kFlushBytes> bytes_{};
    size_t size_ = 0;
    uint64_t first_byte_at_ns_ = 0;
};

}  // namespace kathttp3
