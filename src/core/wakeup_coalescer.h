#pragma once

#include <atomic>

namespace kathttp3 {

class WakeupCoalescer {
   public:
    bool request() {
        return !pending_.exchange(true, std::memory_order_acq_rel);
    }

    void reset() {
        pending_.store(false, std::memory_order_release);
    }

    bool pending() const {
        return pending_.load(std::memory_order_acquire);
    }

   private:
    std::atomic<bool> pending_{false};
};

}  // namespace kathttp3
