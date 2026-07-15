#include "http3_session.h"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

#include <array>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <limits>

#include "kathttp3.h"
#include "log.h"
#include "request.h"
#include "request_body_offset.h"
#include "time_util.h"
#include "url.h"

namespace kathttp3 {

#ifndef NGTCP2_MAX_PKTLEN
#define NGTCP2_MAX_PKTLEN 2048
#endif

namespace {

int begin_headers_cb(nghttp3_conn*, int64_t stream_id, void* conn_user_data,
                     void* /*stream_user_data*/) {
    auto* c = static_cast<Http3Session*>(conn_user_data);
    auto* job = c->find_job(stream_id);
    if (job && !job->saw_headers) {
        job->response.headers.clear();
        job->response.status_code = 0;
        job->status_field_count = 0;
        job->saw_regular_response_header = false;
    }
    return 0;
}

int recv_header_cb(nghttp3_conn*, int64_t stream_id, int32_t token, nghttp3_rcbuf* name,
                   nghttp3_rcbuf* value, uint8_t, void* conn_user_data,
                   void* /*stream_user_data*/) {
    (void)token;
    auto* c = static_cast<Http3Session*>(conn_user_data);
    auto* job = c->find_job(stream_id);
    if (!job) return 0;
    nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
    if (n.len == 0 || v.len > (1U << 20)) return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
    const auto* name_bytes = reinterpret_cast<const uint8_t*>(n.base);
    for (size_t i = 0; i < n.len; ++i) {
        const uint8_t ch = name_bytes[i];
        if (ch <= 0x20 || ch >= 0x7f || (ch >= 'A' && ch <= 'Z')) {
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
    }
    if (n.len == 7 && std::memcmp(n.base, ":status", 7) == 0) {
        if (job->saw_regular_response_header || ++job->status_field_count != 1) {
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        // nghttp3_vec is a length-delimited view, not a NUL-terminated string.
        // strtol could read past a short :status buffer and crash on a PATCH
        // response.  Parse exactly the received bytes instead.
        int status = 0;
        const char* first = reinterpret_cast<const char*>(v.base);
        const char* last = first + v.len;
        auto [end, error] = std::from_chars(first, last, status);
        if (error != std::errc{} || end != last || status < 100 || status > 599) {
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        job->response.status_code = status;
    } else {
        if (n.base[0] == ':') return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        job->saw_regular_response_header = true;
        const std::string header_name(reinterpret_cast<const char*>(n.base), n.len);
        const std::string header_value(reinterpret_cast<const char*>(v.base), v.len);
        if (header_name == "connection" || header_name == "keep-alive" ||
            header_name == "proxy-connection" || header_name == "transfer-encoding" ||
            header_name == "upgrade" || (header_name == "te" && header_value != "trailers")) {
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        job->response.headers.add(header_name, header_value);
    }
    return 0;
}

int end_headers_cb(nghttp3_conn*, int64_t stream_id, int /*fin*/, void* conn_user_data,
                   void* /*stream_user_data*/) {
    auto* c = static_cast<Http3Session*>(conn_user_data);
    auto* job = c->find_job(stream_id);
    if (job) {
        if (!job->saw_headers && job->status_field_count != 1) {
            return NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
        }
        job->saw_headers = true;
        job->response_headers_at = timestamp_now_ns();
        job->last_read_progress_at = job->response_headers_at;
        c->client()->notify_job_headers(job, job->response.status_code, job->response.headers);
    }
    return 0;
}

int recv_data_cb(nghttp3_conn*, int64_t stream_id, const uint8_t* data, size_t len,
                 void* conn_user_data, void* /*stream_user_data*/) {
    auto* c = static_cast<Http3Session*>(conn_user_data);
    auto* job = c->find_job(stream_id);
    if (!job) return 0;
    job->last_read_progress_at = timestamp_now_ns();
    {
        std::lock_guard<std::mutex> receive_lock(job->receive_credit_mutex);
        job->delivered_body_bytes += len;
        if (job->streaming) job->delivered_unconsumed_bytes += len;
    }
    c->client()->notify_job_body(job, data, len);
    // Streaming (Flow) requests apply HTTP/3 receive flow-control: the window
    // is extended only as the application consumes chunks (via consume()),
    // so a slow consumer exerts backpressure on the peer. Buffered requests
    // extend immediately.
    if (!job->streaming) {
        ngtcp2_conn_extend_max_stream_offset(c->client()->conn(), stream_id, len);
        ngtcp2_conn_extend_max_offset(c->client()->conn(), len);
    }
    return 0;
}

// nghttp3 can defer consumption of HTTP/3 wire bytes while synchronizing
// QPACK state between streams. These bytes are not payload delivered through
// recv_data_cb, but they still consume QUIC stream and connection credit.
int deferred_consume_cb(nghttp3_conn*, int64_t stream_id, size_t consumed, void* conn_user_data,
                        void* /*stream_user_data*/) {
    auto* c = static_cast<Http3Session*>(conn_user_data);
    return c->deferred_consume(stream_id, consumed) ? 0 : NGHTTP3_ERR_CALLBACK_FAILURE;
}

int end_stream_cb(nghttp3_conn*, int64_t stream_id, void* conn_user_data,
                  void* /*stream_user_data*/) {
    auto* c = static_cast<Http3Session*>(conn_user_data);
    auto* job = c->find_job(stream_id);
    if (job) {
        job->completed = true;
        c->client()->notify_job_complete(job);
    }
    return 0;
}

int stream_close_cb(nghttp3_conn*, int64_t stream_id, uint64_t app_error_code, void* conn_user_data,
                    void* /*stream_user_data*/) {
    auto* c = static_cast<Http3Session*>(conn_user_data);
    auto* job = c->find_job(stream_id);
    if (job && !job->completed) {
        int err = KATHTTP3_ERR_HTTP3;
        // The stream ended without end_stream while a Content-Length was promised:
        // treat as a truncated/length-mismatched body.
        if (job->declared_content_length >= 0 &&
            job->received_body_bytes < static_cast<uint64_t>(job->declared_content_length)) {
            err = KATHTTP3_ERR_BODY;
        }
        c->client()->notify_job_error(job, err);
    }
    c->unmap_stream(stream_id);
    return 0;
}

int reset_stream_cb(nghttp3_conn*, int64_t stream_id, uint64_t app_error_code, void* conn_user_data,
                    void* /*stream_user_data*/) {
    auto* c = static_cast<Http3Session*>(conn_user_data);
    ngtcp2_conn_shutdown_stream_write(c->client()->conn(), 0, stream_id, app_error_code);
    return 0;
}

int stop_sending_cb(nghttp3_conn*, int64_t stream_id, uint64_t app_error_code, void* conn_user_data,
                    void* /*stream_user_data*/) {
    auto* c = static_cast<Http3Session*>(conn_user_data);
    ngtcp2_conn_shutdown_stream_read(c->client()->conn(), 0, stream_id, app_error_code);
    return 0;
}

int acked_stream_data_cb(nghttp3_conn*, int64_t, uint64_t, void*, void*) {
    return 0;
}

int extend_max_stream_data_cb(nghttp3_conn*, int64_t, uint64_t, void*, void*) {
    return 0;
}

int recv_settings_cb(nghttp3_conn*, const nghttp3_settings*, void* conn_user_data) {
    (void)conn_user_data;
    return 0;
}

int shutdown_cb(nghttp3_conn*, int64_t stream_id, void* conn_user_data) {
    static_cast<Http3Session*>(conn_user_data)->client()->on_goaway(stream_id);
    return 0;
}

nghttp3_ssize data_read_cb(nghttp3_conn*, int64_t stream_id, nghttp3_vec* vec, size_t veccnt,
                           uint32_t* pflags, void* stream_user_data, void* conn_user_data) {
    (void)conn_user_data;
    auto* job = static_cast<Job*>(stream_user_data);
    if (!job || !job->request || !vec || veccnt == 0 || !pflags)
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    auto* req = job->request;
    vec[0].base = nullptr;
    vec[0].len = 0;
    *pflags = 0;
    if (req->streaming_body) {
        std::lock_guard<std::mutex> lock(job->request_body_mutex);
        while (!job->request_body_chunks.empty()) {
            const size_t chunk_size = job->request_body_chunks.front().size();
            if (job->request_body_chunk_offset > chunk_size) {
                KATHTTP3_LOG_ERR("request body offset overflow stream=%lld offset=%zu chunk=%zu\n",
                                 static_cast<long long>(stream_id), job->request_body_chunk_offset,
                                 chunk_size);
                return NGHTTP3_ERR_CALLBACK_FAILURE;
            }
            if (job->request_body_chunk_offset != chunk_size) break;
            job->request_body_chunks.pop_front();
            job->request_body_chunk_offset = 0;
        }
        if (job->request_body_chunks.empty()) {
            if (job->request_body_finished) {
                if (req->streaming_body_length >= 0 &&
                    job->body_sent != static_cast<size_t>(req->streaming_body_length))
                    return NGHTTP3_ERR_CALLBACK_FAILURE;
                *pflags = NGHTTP3_DATA_FLAG_EOF;
                return 0;
            }
            return NGHTTP3_ERR_WOULDBLOCK;
        }
        auto& chunk = job->request_body_chunks.front();
        size_t remaining = 0;
        if (!request_body_remaining(chunk.size(), job->request_body_chunk_offset, &remaining) ||
            remaining == 0)
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        const size_t offered = request_body_next_chunk_size(remaining);
        if (!request_body_can_advance(job->body_sent, offered, std::numeric_limits<size_t>::max()))
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        if (req->streaming_body_length >= 0) {
            const uint64_t declared_length = static_cast<uint64_t>(req->streaming_body_length);
            if (declared_length > std::numeric_limits<size_t>::max() ||
                !request_body_can_advance(job->body_sent, offered,
                                          static_cast<size_t>(declared_length)))
                return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        if (job->request_body_buffered_bytes < offered) {
            KATHTTP3_LOG_ERR(
                "request body buffer accounting underflow stream=%lld buffered=%zu "
                "offered=%zu\n",
                static_cast<long long>(stream_id), job->request_body_buffered_bytes, offered);
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        vec[0].base = chunk.data() + job->request_body_chunk_offset;
        vec[0].len = offered;
        job->body_sent += vec[0].len;
        job->request_body_buffered_bytes -= vec[0].len;
        job->request_body_chunk_offset += vec[0].len;
        *pflags = job->request_body_finished && job->request_body_chunks.size() == 1 &&
                          job->request_body_chunk_offset == job->request_body_chunks.front().size()
                      ? NGHTTP3_DATA_FLAG_EOF
                      : 0;
        return 1;
    }
    size_t remaining = 0;
    if (!request_body_remaining(req->body.size(), job->body_sent, &remaining)) {
        KATHTTP3_LOG_ERR("request body offset overflow stream=%lld offset=%zu body=%zu\n",
                         static_cast<long long>(stream_id), job->body_sent, req->body.size());
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    if (remaining != 0) {
        const size_t offered = request_body_next_chunk_size(remaining);
        vec[0].base = req->body.data() + job->body_sent;
        vec[0].len = offered;
        job->body_sent += vec[0].len;
        // EOF must accompany the last non-empty DATA vector.  Waiting for a
        // later zero-length callback leaves the request stream open and makes
        // servers wait indefinitely for the end of a POST/PUT/PATCH body.
        *pflags = job->body_sent == req->body.size() ? NGHTTP3_DATA_FLAG_EOF : 0;
        return 1;
    }
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    return 0;
}

constexpr nghttp3_callbacks kH3Callbacks = {
    .acked_stream_data = acked_stream_data_cb,
    .stream_close = stream_close_cb,
    .recv_data = recv_data_cb,
    .deferred_consume = deferred_consume_cb,
    .begin_headers = begin_headers_cb,
    .recv_header = recv_header_cb,
    .end_headers = end_headers_cb,
    .begin_trailers = nullptr,
    .recv_trailer = nullptr,
    .end_trailers = nullptr,
    .stop_sending = stop_sending_cb,
    .end_stream = end_stream_cb,
    .reset_stream = reset_stream_cb,
    .shutdown = shutdown_cb,
    .recv_settings = recv_settings_cb,
    .recv_origin = nullptr,
    .end_origin = nullptr,
    .rand = nullptr,
    .recv_settings2 = nullptr,
};

}  // namespace

Http3Session::Http3Session(QuicClient* client, ngtcp2_conn* conn) : client_(client), conn_(conn) {}

Http3Session::~Http3Session() {
    if (httpconn_) nghttp3_conn_del(httpconn_);
}

Job* Http3Session::find_job(int64_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) return nullptr;
    return it->second;
}

void Http3Session::map_stream(int64_t stream_id, Job* job) {
    streams_[stream_id] = job;
}

void Http3Session::unmap_stream(int64_t stream_id) {
    streams_.erase(stream_id);
}

bool Http3Session::setup_codec() {
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    nghttp3_conn* conn = nullptr;
    int rv = nghttp3_conn_client_new_versioned(&conn, NGHTTP3_CALLBACKS_VERSION, &kH3Callbacks,
                                               NGHTTP3_SETTINGS_VERSION, &settings, nullptr, this);
    if (rv != 0) {
        KATHTTP3_LOG_ERR("nghttp3_conn_client_new: %s\n", nghttp3_strerror(rv));
        return false;
    }
    httpconn_ = conn;
    int64_t control_id, encoder_id, decoder_id;
    if (ngtcp2_conn_open_uni_stream(conn_, &control_id, nullptr) != 0 ||
        ngtcp2_conn_open_uni_stream(conn_, &encoder_id, nullptr) != 0 ||
        ngtcp2_conn_open_uni_stream(conn_, &decoder_id, nullptr) != 0 ||
        nghttp3_conn_bind_control_stream(httpconn_, control_id) != 0 ||
        nghttp3_conn_bind_qpack_streams(httpconn_, encoder_id, decoder_id) != 0) {
        KATHTTP3_LOG_ERR("failed to bind HTTP/3 critical streams\n");
        nghttp3_conn_del(httpconn_);
        httpconn_ = nullptr;
        return false;
    }
    return true;
}

bool Http3Session::submit_request(Job* job) {
    std::vector<nghttp3_nv> nva;
    auto& url = job->url;
    const auto& req = *job->request;

    auto add_nv = [&](const char* name, size_t nlen, const std::string& val) {
        nva.push_back({reinterpret_cast<const uint8_t*>(name),
                       reinterpret_cast<const uint8_t*>(val.data()), nlen, val.size(),
                       NGHTTP3_NV_FLAG_NONE});
    };
    add_nv(":method", 7, req.method);
    add_nv(":scheme", 7, url.scheme);
    // Url stores an omitted port as zero.  Building :authority directly from
    // url.port therefore produced "host:0" for ordinary HTTPS URLs even
    // though the QUIC connection used the effective port 443.
    const std::string authority = url.authority();
    add_nv(":authority", 10, authority);
    std::string path = url.path.empty() ? "/" : url.path;
    if (!url.query.empty()) {
        path += "?";
        path += url.query;
    }
    add_nv(":path", 5, path);

    for (const auto& h : req.headers.list()) {
        nva.push_back({reinterpret_cast<const uint8_t*>(h.name.data()),
                       reinterpret_cast<const uint8_t*>(h.value.data()), h.name.size(),
                       h.value.size(), NGHTTP3_NV_FLAG_NONE});
    }

    nghttp3_data_reader dr{data_read_cb};
    const nghttp3_data_reader* drp = nullptr;
    if (!req.body.empty() || req.streaming_body) {
        // Ensure a Content-Length is present so servers parse the body.
        bool has_cl = false;
        for (const auto& h : req.headers.list()) {
            if (strcasecmp(h.name.c_str(), "content-length") == 0) {
                has_cl = true;
                break;
            }
        }
        if (!has_cl && (!req.streaming_body || req.streaming_body_length >= 0)) {
            std::string cl =
                std::to_string(req.streaming_body ? req.streaming_body_length
                                                  : static_cast<int64_t>(req.body.size()));
            nva.push_back({reinterpret_cast<const uint8_t*>("content-length"),
                           reinterpret_cast<const uint8_t*>(cl.data()), 14, cl.size(),
                           NGHTTP3_NV_FLAG_NONE});
        }
        drp = &dr;
    }

    int rv =
        nghttp3_conn_submit_request(httpconn_, job->stream_id, nva.data(), nva.size(), drp, job);
    if (rv != 0) {
        KATHTTP3_LOG_ERR("nghttp3_conn_submit_request: %s\n", nghttp3_strerror(rv));
        return false;
    }
    map_stream(job->stream_id, job);
    return true;
}

void Http3Session::resume_stream(int64_t stream_id) {
    if (httpconn_) nghttp3_conn_resume_stream(httpconn_, stream_id);
}

void Http3Session::pump_write(ngtcp2_tstamp ts) {
    if (!httpconn_) return;
    uint8_t pkt[NGTCP2_MAX_PKTLEN];
    // nghttp3 returns references to its queued stream bytes.  It does not write
    // encoded bytes into a caller-provided buffer, and its return value is the
    // number of vectors, not a byte length.  Passing a single pre-filled vector
    // here used to forward a null data pointer to ngtcp2 for request bodies.
    std::array<nghttp3_vec, 16> h3vec{};
    for (;;) {
        int64_t stream_id = -1;
        int fin = 0;
        nghttp3_ssize h3veccnt =
            nghttp3_conn_writev_stream(httpconn_, &stream_id, &fin, h3vec.data(), h3vec.size());
        if (h3veccnt < 0) {
            KATHTTP3_LOG_ERR("nghttp3_conn_writev_stream: %s\n", nghttp3_strerror((int)h3veccnt));
            return;
        }
        if (h3veccnt == 0 && stream_id == -1) return;

        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        if (fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        ngtcp2_pkt_info pi{};
        ngtcp2_ssize ndatalen = -1;
        ngtcp2_ssize w = ngtcp2_conn_writev_stream(
            client_->conn(), &client_->path(), &pi, pkt, sizeof(pkt), &ndatalen, flags, stream_id,
            reinterpret_cast<const ngtcp2_vec*>(h3vec.data()), static_cast<size_t>(h3veccnt), ts);
        if (w == NGTCP2_ERR_WRITE_MORE) {
            if (ndatalen >= 0 && nghttp3_conn_add_write_offset(
                                     httpconn_, stream_id, static_cast<size_t>(ndatalen)) != 0) {
                KATHTTP3_LOG_ERR("nghttp3_conn_add_write_offset failed\n");
                return;
            }
            continue;
        }
        if (w == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            nghttp3_conn_block_stream(httpconn_, stream_id);
            continue;
        }
        if (w == NGTCP2_ERR_STREAM_SHUT_WR) {
            nghttp3_conn_shutdown_stream_write(httpconn_, stream_id);
            continue;
        }
        if (w < 0) {
            KATHTTP3_LOG_ERR("ngtcp2_conn_writev_stream: %s\n", ngtcp2_strerror((int)w));
            return;
        }
        if (ndatalen >= 0 && nghttp3_conn_add_write_offset(httpconn_, stream_id,
                                                           static_cast<size_t>(ndatalen)) != 0) {
            KATHTTP3_LOG_ERR("nghttp3_conn_add_write_offset failed\n");
            return;
        }
        if (ndatalen > 0) client_->note_write_progress(stream_id);
        if (w == 0) return;
        if (w > 0) {
            client_->send_packet(pkt, static_cast<size_t>(w));
            // write_pending will call us again after ngtcp2's paced send
            // quantum opens. Do not construct more packets in this turn.
            if (client_->send_quantum_exhausted()) return;
        }
    }
}

bool Http3Session::recv_stream_data(uint32_t, int64_t stream_id, const uint8_t* data, size_t len,
                                    bool fin, ngtcp2_tstamp ts) {
    if (!httpconn_) return false;
    const nghttp3_ssize rv = nghttp3_conn_read_stream(httpconn_, stream_id, data, len, fin ? 1 : 0);
    if (rv < 0) {
        KATHTTP3_LOG_ERR("nghttp3_conn_read_stream: %s\n", nghttp3_strerror(static_cast<int>(rv)));
        return false;
    }
    Job* job = find_job(stream_id);
    if (!job || !job->streaming) {
        ngtcp2_conn_extend_max_stream_offset(client_->conn(), stream_id, static_cast<uint64_t>(rv));
        ngtcp2_conn_extend_max_offset(client_->conn(), static_cast<uint64_t>(rv));
    }
    return true;
}

bool Http3Session::acked_stream_data_offset(int64_t stream_id, uint64_t n) {
    return !httpconn_ || nghttp3_conn_add_ack_offset(httpconn_, stream_id, n) == 0;
}

bool Http3Session::extend_max_stream_data(int64_t, uint64_t) {
    return true;
}

bool Http3Session::deferred_consume(int64_t stream_id, size_t consumed) {
    if (!conn_ || consumed == 0) return true;
    const int rv = ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, consumed);
    if (rv != 0) {
        KATHTTP3_LOG_ERR("ngtcp2_conn_extend_max_stream_offset: %s\n", ngtcp2_strerror(rv));
        return false;
    }
    ngtcp2_conn_extend_max_offset(conn_, consumed);
    return true;
}

bool Http3Session::on_stream_close(int64_t stream_id, uint64_t app_error_code) {
    if (httpconn_) {
        nghttp3_conn_close_stream(httpconn_, stream_id, app_error_code);
    }
    return true;
}

bool Http3Session::on_stream_reset(int64_t stream_id) {
    if (httpconn_) nghttp3_conn_shutdown_stream_read(httpconn_, stream_id);
    return true;
}

bool Http3Session::on_stream_stop_sending(int64_t stream_id) {
    if (httpconn_) nghttp3_conn_shutdown_stream_write(httpconn_, stream_id);
    return true;
}

void Http3Session::early_data_rejected() {
    // We do not pipeline early-data requests; nothing to roll back.
}

void Http3Session::reset_stream(int64_t stream_id) {
    if (httpconn_) {
        nghttp3_conn_shutdown_stream_read(httpconn_, stream_id);
        nghttp3_conn_shutdown_stream_write(httpconn_, stream_id);
    }
    ngtcp2_conn_shutdown_stream_read(conn_, 0, stream_id, NGHTTP3_H3_REQUEST_CANCELLED);
    ngtcp2_conn_shutdown_stream_write(conn_, 0, stream_id, NGHTTP3_H3_REQUEST_CANCELLED);
}

}  // namespace kathttp3
