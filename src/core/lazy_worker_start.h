#pragma once

#include <atomic>

namespace kathttp3 {

/*
 * A connection worker must not start until its first request has been
 * published to the pending queue. claim_after_enqueue() elects exactly one
 * submitting thread to start the worker after that publication.
 */
class LazyWorkerStart {
   public:
    bool claim_after_enqueue() {
        bool expected = false;
        return started_.compare_exchange_strong(expected, true, std::memory_order_acq_rel);
    }

    bool started() const {
        return started_.load(std::memory_order_acquire);
    }

   private:
    std::atomic<bool> started_{false};
};

}  // namespace kathttp3
