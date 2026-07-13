#ifndef KATHTTP3_QUIC_CLIENT_H
#define KATHTTP3_QUIC_CLIENT_H

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "dns.h"
#include "request.h"
#include "response.h"
#include "tls.h"
#include "udp_socket.h"
#include "url.h"

struct kathttp3_request;

namespace kathttp3 {

class Engine;
class Http3Session;
struct HandshakeCandidate;

enum class ConnectionState { Connecting, Active, Draining, Closing, Closed };

/* One HTTP/3 request/response exchange multiplexed over a QuicClient. */
struct Job {
    int64_t id = 0;
    kathttp3_request* request = nullptr; /* owned by Job */
    Url url;
    int64_t stream_id = -1;
    bool http3_ready = false;
    bool cancelled = false;
    bool completed = false;
    bool redirected = false;
    Response response;
    bool saw_headers = false;
    uint8_t status_field_count = 0;
    bool saw_regular_response_header = false;
    size_t body_sent = 0; /* request body bytes already offered to nghttp3 */
    std::mutex request_body_mutex;
    std::deque<std::vector<uint8_t>> request_body_chunks;
    size_t request_body_chunk_offset = 0;
    size_t request_body_buffered_bytes = 0;
    bool request_body_finished = false;
    uint64_t submitted_at = 0; /* monotonic timestamp; 0 until queued */
    uint64_t response_headers_at = 0;
    uint64_t last_read_progress_at = 0;
    uint64_t last_write_progress_at = 0;
    size_t delivered_unconsumed_bytes = 0;
    size_t delivered_body_bytes = 0;
    size_t consumed_body_bytes = 0;
    size_t pending_credit_bytes = 0; /* coalesced receive-window credit */
    int redirect_count = 0;
    /* Response body length accounting for Content-Length validation. */
    int64_t declared_content_length = -1; /* from Content-Length header, or -1 */
    uint64_t received_body_bytes = 0;     /* running total of BODY bytes */
    bool streaming = false;               /* streaming (Flow) request: apply
                                             HTTP/3 receive flow-control */
    Job() = default;
    Job(const Job&) = delete;
    Job& operator=(const Job&) = delete;
    ~Job() {
        delete request;
    }
};

/* Owns a single ngtcp2 QUIC connection plus its UDP socket and its own
 * worker thread running a poll() loop. Multiplexes many Job (streams) over
 * the one connection. Reused by the Engine's connection pool. */
class QuicClient {
   public:
    QuicClient(Engine* engine, TlsClientContext& tls_ctx, const Url& origin,
               std::shared_ptr<Resolver> resolver, bool enable_0rtt, uint64_t connect_timeout_ms,
               uint64_t request_timeout_ms, uint64_t idle_timeout_ms, uint64_t dns_timeout_ms,
               uint64_t handshake_timeout_ms, uint64_t response_headers_timeout_ms,
               uint64_t read_timeout_ms, uint64_t write_timeout_ms, uint64_t call_timeout_ms,
               uint32_t quic_version, std::string qlog_path_prefix);
    ~QuicClient();

    QuicClient(const QuicClient&) = delete;
    QuicClient& operator=(const QuicClient&) = delete;

    /* Called from the Engine thread. Queues the job and wakes the loop. */
    void submit_job(std::unique_ptr<Job> job);

    /* Called from any thread. Marks the job cancelled; the loop stops
     * delivering its events and resets the stream if open. */
    void cancel_job(int64_t job_id);

    bool is_ready() const {
        return handshake_confirmed_.load();
    }
    bool is_closed() const {
        return closed_.load();
    }
    bool is_draining() const {
        return state_.load() == ConnectionState::Draining;
    }

    /* Human-readable BoringSSL/OpenSSL error queue (clears it). */
    const std::string& lastTlsError() const {
        return tls_session_.lastTlsError();
    }

    /* Forwards to TlsClientSession::captureLastError. */
    void captureTlsError(SSL* ssl, int rc) {
        tls_session_.captureLastError(ssl, rc);
    }

    const Url& origin() const {
        return origin_;
    }
    ngtcp2_conn* conn() {
        return conn_;
    }
    ngtcp2_path& path() {
        return path_;
    }
    void send_packet(const uint8_t* data, size_t len) {
        sock_.send(data, len, 0);
    }

    void notify_job_headers(Job* job, int status, const HeaderList& headers);
    void notify_job_body(Job* job, const uint8_t* data, size_t len);
    void notify_job_complete(Job* job);
    void notify_job_error(Job* job, int err);

    void set_wakeup_fd(int fd);

    /* Streaming flow-control: record that `bytes` of a streamed response body
     * were consumed by the application; the window extension is applied on the
     * worker thread. Looks up the job's stream id from `request_id`. */
    int consume(int64_t request_id, size_t bytes);
    int append_request_body(int64_t request_id, const uint8_t* data, size_t len, bool finished);

    /* Invoked by ngtcp2/nghttp3 C callbacks (defined as free functions in
     * quic_client.cc / http3_session.cc). Public so those callbacks can reach
     * them without friendship gymnastics. */
    bool on_handshake_completed();
    void on_handshake_confirmed();
    void setup_codec();
    bool on_extend_max_stream_data(int64_t stream_id);
    bool on_acked_stream_data(int64_t stream_id, uint64_t datalen);
    bool on_recv_stream_data(uint32_t flags, int64_t stream_id, const uint8_t* data, size_t len);
    bool on_stream_close(int64_t stream_id, uint64_t app_error_code);
    bool on_stream_reset(int64_t stream_id, uint64_t app_error_code);
    bool on_stream_stop_sending(int64_t stream_id, uint64_t app_error_code);
    void generate_reset_token(uint8_t* token, const ngtcp2_cid* cid);
    void on_early_data_rejected();
    void on_goaway(int64_t stream_id);
    void try_submit_pending();
    void write_pending();
    void note_write_progress(int64_t stream_id);
    int open_qlog_file();
    void write_qlog(uint32_t flags, const void* data, size_t len) const;

   private:
    bool prepare_endpoints();
    bool has_live_pending_job();
    bool connect_to_endpoint();
    bool setup_connection();
    /* Run the first IPv6 and IPv4 candidates as independent QUIC/TLS
     * handshakes.  No request stream is opened until one candidate has
     * completed its cryptographic handshake, so non-idempotent requests are
     * never duplicated by the race. */
    bool run_handshake_race();
    bool start_handshake_candidate(const ResolvedEndpoint& endpoint);
    bool adopt_handshake_winner(HandshakeCandidate& candidate);
    void run();
    int event_loop();
    int compute_timeout(uint64_t now);
    void drain_wakeup();
    void on_readable();
    void process_wakeup();
    void expire_requests(uint64_t now);
    void update_keep_alive();

    /* Pending HTTP/3 receive-window extensions (streaming backpressure),
     * drained on the worker thread. Pair = (stream_id, bytes). */
    std::mutex consume_mutex_;
    std::vector<std::pair<int64_t, size_t>> pending_consumes_;

    // nghttp3 is owned exclusively by the QUIC worker. Producers append
    // request-body chunks from arbitrary threads and queue stream resumes
    // here; process_wakeup() performs the actual nghttp3 call.
    std::mutex request_body_resume_mutex_;
    std::vector<int64_t> pending_request_body_resumes_;

    void fail_all_pending(int err);
    void wakeup();

    Engine* engine_;
    TlsClientContext& tls_ctx_;
    Url origin_;
    std::shared_ptr<Resolver> resolver_;
    bool enable_0rtt_;
    uint64_t connect_timeout_ms_;
    uint64_t request_timeout_ms_;
    uint64_t idle_timeout_ms_;
    uint64_t dns_timeout_ms_;
    uint64_t handshake_timeout_ms_;
    uint64_t response_headers_timeout_ms_;
    uint64_t read_timeout_ms_;
    uint64_t write_timeout_ms_;
    uint64_t call_timeout_ms_;
    uint32_t quic_version_;
    std::string qlog_path_prefix_;
    int qlog_fd_ = -1;
    bool http3_ready_ = false;

    std::thread thread_;
    std::atomic<bool> closed_{false};
    std::atomic<bool> handshake_confirmed_{false};
    std::atomic<bool> stop_{false};
    std::atomic<ConnectionState> state_{ConnectionState::Connecting};

    UdpSocket sock_;
    int wakeup_fd_ = -1;
    std::vector<ResolvedEndpoint> endpoints_;
    size_t endpoint_idx_ = 0;

    ngtcp2_conn* conn_ = nullptr;
    ngtcp2_crypto_conn_ref conn_ref_{};
    std::vector<uint8_t> stateless_reset_secret_;
    ngtcp2_path path_{};
    sockaddr_storage local_addr_{};
    sockaddr_storage remote_addr_{};

    /* A winner remains alive for the connection lifetime because BoringSSL's
     * ngtcp2 glue stores a pointer to its conn_ref in the SSL object.  These
     * declarations intentionally precede tls_session_: C++ destroys members
     * in reverse order, keeping conn_ref alive through SSL_free. */
    std::vector<std::unique_ptr<HandshakeCandidate>> handshake_candidates_;
    std::unique_ptr<HandshakeCandidate> handshake_winner_;
    TlsClientSession tls_session_;
    std::unique_ptr<Http3Session> http3_;

    std::mutex job_mutex_;
    std::vector<std::unique_ptr<Job>> pending_jobs_;  // not yet submitted
    std::vector<std::unique_ptr<Job>> active_jobs_;   // submitted (stream open)
    uint64_t last_active_ = 0;
    uint64_t connection_started_at_ = 0;
    uint64_t handshake_started_at_ = 0;
    int terminal_error_ = KATHTTP3_ERR_QUIC;
};

} /* namespace kathttp3 */

#endif /* KATHTTP3_QUIC_CLIENT_H */
