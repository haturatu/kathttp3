#ifndef KATHTTP3_HTTP3_SESSION_H
#define KATHTTP3_HTTP3_SESSION_H

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

#include <cstdint>
#include <unordered_map>

#include "quic_client.h"

namespace kathttp3 {

/* Wraps an nghttp3 connection: manages HTTP/3 streams (control, QPACK and
 * request/response), QPACK and the read/write bridge to ngtcp2. */
class Http3Session {
   public:
    Http3Session(QuicClient* client, ngtcp2_conn* conn);
    ~Http3Session();

    Http3Session(const Http3Session&) = delete;
    Http3Session& operator=(const Http3Session&) = delete;

    bool setup_codec();
    bool submit_request(Job* job);
    void pump_write(ngtcp2_tstamp ts);

    bool recv_stream_data(uint32_t flags, int64_t stream_id, const uint8_t* data, size_t len,
                          bool fin, ngtcp2_tstamp ts);
    bool acked_stream_data_offset(int64_t stream_id, uint64_t datalen);
    bool extend_max_stream_data(int64_t stream_id, uint64_t max_data);
    bool on_stream_close(int64_t stream_id, uint64_t app_error_code);
    bool on_stream_reset(int64_t stream_id);
    bool on_stream_stop_sending(int64_t stream_id);
    void early_data_rejected();
    void reset_stream(int64_t stream_id);
    void resume_stream(int64_t stream_id);

    bool ready() const {
        return httpconn_ != nullptr;
    }

    QuicClient* client() {
        return client_;
    }
    Job* find_job(int64_t stream_id);
    void unmap_stream(int64_t stream_id);

   private:
    void map_stream(int64_t stream_id, Job* job);

    QuicClient* client_;
    ngtcp2_conn* conn_;
    nghttp3_conn* httpconn_ = nullptr;
    std::unordered_map<int64_t, Job*> streams_;
};

} /* namespace kathttp3 */

#endif /* KATHTTP3_HTTP3_SESSION_H */
