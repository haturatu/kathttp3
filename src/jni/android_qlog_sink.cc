#include "android_qlog_sink.h"

#include <android/log.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace kathttp3 {
namespace {
constexpr size_t kMaxQueuedBytes = 256 * 1024;
constexpr size_t kMaxRecordBytes = 16 * 1024;
constexpr size_t kMaxLogcatMessageBytes = 3500;
constexpr char kTag[] = "kathttp3-qlog";
}  // namespace

class AndroidQlogLogcatSink::Impl {
   public:
    Impl() : worker_([this] { drain(); }) {}

    ~Impl() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
            // Destruction is part of client close. Do not turn a diagnostic
            // backlog into a shutdown delay; a record already being written
            // may finish, but queued records are intentionally discarded.
            queue_.clear();
            queued_bytes_ = 0;
        }
        available_.notify_one();
        if (worker_.joinable()) worker_.join();
    }

    void enqueue(uint32_t flags, const uint8_t* data, size_t len) noexcept {
        if (!data || len == 0) return;
        const size_t accepted = std::min(len, kMaxRecordBytes);
        std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
        if (!lock.owns_lock() || stopping_ || accepted > kMaxQueuedBytes ||
            queued_bytes_ + accepted > kMaxQueuedBytes) {
            dropped_records_.fetch_add(1, std::memory_order_relaxed);
            dropped_bytes_.fetch_add(len, std::memory_order_relaxed);
            return;
        }
        queue_.emplace_back(reinterpret_cast<const char*>(data), accepted);
        queued_bytes_ += accepted;
        if (accepted != len) {
            dropped_records_.fetch_add(1, std::memory_order_relaxed);
            dropped_bytes_.fetch_add(len - accepted, std::memory_order_relaxed);
        }
        (void)flags;  // The ngtcp2 flags are preserved by core sinks; Logcat is text-only.
        lock.unlock();
        available_.notify_one();
    }

   private:
    void write_record(const std::string& record) noexcept {
        size_t offset = 0;
        while (offset < record.size()) {
            const size_t count = std::min(kMaxLogcatMessageBytes, record.size() - offset);
            std::string line = "qlog ";
            line.append(record.data() + offset, count);
            __android_log_write(ANDROID_LOG_DEBUG, kTag, line.c_str());
            offset += count;
        }
    }

    void drain() noexcept {
        for (;;) {
            std::string record;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                available_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                if (queue_.empty() && stopping_) return;
                record = std::move(queue_.front());
                queued_bytes_ -= record.size();
                queue_.pop_front();
            }
            const size_t dropped_records = dropped_records_.exchange(0, std::memory_order_relaxed);
            const size_t dropped_bytes = dropped_bytes_.exchange(0, std::memory_order_relaxed);
            if (dropped_records != 0) {
                const std::string notice =
                    "qlog diagnostics dropped records=" + std::to_string(dropped_records) +
                    " bytes=" + std::to_string(dropped_bytes);
                __android_log_write(ANDROID_LOG_WARN, kTag, notice.c_str());
            }
            write_record(record);
        }
    }

    std::mutex mutex_;
    std::condition_variable available_;
    std::deque<std::string> queue_;
    size_t queued_bytes_ = 0;
    bool stopping_ = false;
    std::thread worker_;
    std::atomic<size_t> dropped_records_{0};
    std::atomic<size_t> dropped_bytes_{0};
};

AndroidQlogLogcatSink::AndroidQlogLogcatSink() : impl_(new Impl()) {}

AndroidQlogLogcatSink::~AndroidQlogLogcatSink() {
    delete impl_;
}

void AndroidQlogLogcatSink::callback(void* userdata, uint32_t flags, const uint8_t* data,
                                     size_t len) {
    auto* sink = static_cast<AndroidQlogLogcatSink*>(userdata);
    if (sink && sink->impl_) sink->impl_->enqueue(flags, data, len);
}

}  // namespace kathttp3
