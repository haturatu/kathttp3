#ifndef KATHTTP3_ANDROID_QLOG_SINK_H
#define KATHTTP3_ANDROID_QLOG_SINK_H

#include <cstddef>
#include <cstdint>

namespace kathttp3 {

/* Android-only qlog destination. enqueue() never waits for the logging
 * thread: contention or a full bounded queue drops diagnostics rather than
 * delaying QUIC packet processing. */
class AndroidQlogLogcatSink {
   public:
    AndroidQlogLogcatSink();
    ~AndroidQlogLogcatSink();

    AndroidQlogLogcatSink(const AndroidQlogLogcatSink&) = delete;
    AndroidQlogLogcatSink& operator=(const AndroidQlogLogcatSink&) = delete;

    static void callback(void* userdata, uint32_t flags, const uint8_t* data, size_t len);

   private:
    class Impl;
    Impl* impl_;
};

}  // namespace kathttp3

#endif  // KATHTTP3_ANDROID_QLOG_SINK_H
