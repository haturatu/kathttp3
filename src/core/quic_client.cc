#include "quic_client.h"

#include <fcntl.h>
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>

#include "engine.h"
#include "flow_control.h"
#include "handshake_race.h"
#include "handshake_stream_buffer.h"
#include "http3_session.h"
#include "log.h"
#include "precommit_failover.h"
#include "request.h"
#include "time_util.h"
#include "udp_error.h"

#ifndef NGTCP2_MAX_PKTLEN
#define NGTCP2_MAX_PKTLEN 2048
#endif
#ifndef NGTCP2_WRITE_STREAM_FLAG_FIN
#define NGTCP2_WRITE_STREAM_FLAG_FIN 0x1
#endif

namespace kathttp3 {

namespace {
std::atomic<uint64_t> next_connection_instance_id{1};

const char* connection_state_name(ConnectionState state) {
    switch (state) {
        case ConnectionState::None:
            return "none";
        case ConnectionState::Connecting:
            return "connecting";
        case ConnectionState::Active:
            return "active";
        case ConnectionState::Draining:
            return "draining";
        case ConnectionState::Closing:
            return "closing";
        case ConnectionState::Closed:
            return "closed";
    }
    return "unknown";
}
constexpr size_t kMinimumSendQuantum = NGTCP2_MAX_PKTLEN;

// Every route to a client connection must advertise the same bounded receive
// capacity. In particular, Happy Eyeballs candidates are adopted in-place, so
// their transport parameters become the parameters of the winning connection.
void configure_receive_windows(ngtcp2_transport_params* params) {
    params->initial_max_stream_data_bidi_local = kReceiveBufferPerStreamHighWatermark;
    params->initial_max_stream_data_bidi_remote = kReceiveBufferPerStreamHighWatermark;
    // Server-initiated unidirectional streams carry the peer HTTP/3 control
    // stream and the QPACK encoder/decoder streams.  Leaving this at ngtcp2's
    // zero default makes the peer immediately send STREAM_DATA_BLOCKED and
    // prevents SETTINGS and header decoding from progressing.
    params->initial_max_stream_data_uni = kReceiveBufferPerStreamHighWatermark;
    params->initial_max_data = kReceiveBufferPerConnectionLimit;
}

bool is_0rtt_replay_safe(const Job& job) {
    if (!job.request || !job.request->body.empty() || job.request->streaming_body) return false;
    if (job.request->method != "GET" && job.request->method != "HEAD") return false;
    for (const auto& header : job.request->headers.all()) {
        if (header.name == "authorization" || header.name == "proxy-authorization" ||
            header.name == "cookie")
            return false;
    }
    return true;
}
}  // namespace

/* A pre-HTTP/3 connection attempt.  Each candidate owns every object which
 * carries peer-specific state: UDP fd, ngtcp2 connection, TLS SSL object and
 * path addresses.  This is deliberately separate from QuicClient so an IPv4
 * fallback cannot overwrite an IPv6 handshake in flight. */
struct HandshakeCandidate {
    explicit HandshakeCandidate(QuicClient* owner_in, ResolvedEndpoint endpoint_in)
        : owner(owner_in), endpoint(std::move(endpoint_in)), qlog_fd(owner->open_qlog_file()) {}

    ~HandshakeCandidate() {
        if (owns_connection && conn) ngtcp2_conn_del(conn);
        if (qlog_fd != -1) ::close(qlog_fd);
    }

    HandshakeCandidate(const HandshakeCandidate&) = delete;
    HandshakeCandidate& operator=(const HandshakeCandidate&) = delete;

    QuicClient* owner;
    ResolvedEndpoint endpoint;
    UdpSocket sock;
    ngtcp2_conn* conn = nullptr;
    ngtcp2_crypto_conn_ref conn_ref{};
    TlsClientSession tls;
    ngtcp2_path path{};
    sockaddr_storage local_addr{};
    sockaddr_storage remote_addr{};
    uint64_t started_at = 0;
    bool handshake_completed = false;
    // TLS handshake completion alone does not guarantee that ngtcp2 has
    // installed the receive 1-RTT AEAD context.  The connection must not be
    // adopted by the main event loop until recv_rx_key has observed it.
    bool rx_1rtt_key_ready = false;
    // Written exactly once when recv_rx_key reports the 1-RTT receive key.
    // This is the race result; vector/poll callback order must not decide it.
    uint64_t one_rtt_ready_at = 0;
    bool handshake_confirmed = false;
    // A server can send its HTTP/3 control and QPACK streams in the same
    // packet that makes 1-RTT keys available.  The main HTTP/3 codec does not
    // exist until this candidate wins, so retain those callbacks and replay
    // them after adoption instead of rejecting an otherwise healthy path.
    HandshakeStreamBuffer buffered_stream_data;
    bool adopted = false;
    bool abandoned = false;
    bool failed = false;
    bool owns_connection = true;
    int qlog_fd = -1;
};

namespace {

uint64_t now_ns() {
    return timestamp_now_ns();
}

ngtcp2_conn* get_conn_cb(ngtcp2_crypto_conn_ref* ref) {
    return static_cast<QuicClient*>(ref->user_data)->conn();
}

void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx*) {
    RAND_bytes(dest, static_cast<int>(destlen));
}

void write_qlog_fd(int fd, uint32_t /*flags*/, const void* data, size_t len) {
    if (fd == -1 || !data) return;
    const auto* p = static_cast<const uint8_t*>(data);
    while (len != 0) {
        const ssize_t n = ::write(fd, p, len);
        if (n > 0) {
            p += n;
            len -= static_cast<size_t>(n);
            continue;
        }
        if (n == -1 && errno == EINTR) continue;
        return;  // qlog is diagnostic-only; never fail the QUIC connection.
    }
}

void qlog_write_cb(void* user_data, uint32_t flags, const void* data, size_t len) {
    static_cast<QuicClient*>(user_data)->write_qlog(flags, data, len);
}

int get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen,
                             void* user_data) {
    auto* c = static_cast<QuicClient*>(user_data);
    if (RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid->datalen = cidlen;
    c->generate_reset_token(token, cid);
    return 0;
}

int get_new_connection_id2_cb(ngtcp2_conn*, ngtcp2_cid* cid, ngtcp2_stateless_reset_token* token,
                              size_t cidlen, void* user_data) {
    auto* c = static_cast<QuicClient*>(user_data);
    if (RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid->datalen = cidlen;
    c->generate_reset_token(token->data, cid);
    return 0;
}

int recv_crypto_data_cb(ngtcp2_conn* conn, ngtcp2_encryption_level level, uint64_t offset,
                        const uint8_t* data, size_t datalen, void* user_data) {
    (void)user_data;
    int rv = ngtcp2_crypto_recv_crypto_data_cb(conn, level, offset, data, datalen, user_data);
    if (rv != 0) {
        auto* c = static_cast<QuicClient*>(user_data);
        SSL* ssl = static_cast<SSL*>(ngtcp2_conn_get_tls_native_handle2(conn));
        if (ssl) c->captureTlsError(ssl, rv);
        KATHTTP3_LOG_ERR("recv_crypto_data_cb: level=%d rv=%d ngtcp2=%s ssl='%s'\n", level, rv,
                         ngtcp2_strerror(rv), c->lastTlsError().c_str());
    }
    return rv;
}

int handshake_completed_cb(ngtcp2_conn* conn, void* user_data) {
    (void)conn;
    return static_cast<QuicClient*>(user_data)->on_handshake_completed() ? 0 : -1;
}

int handshake_confirmed_cb(ngtcp2_conn* conn, void* user_data) {
    (void)conn;
    static_cast<QuicClient*>(user_data)->on_handshake_confirmed();
    return 0;
}

int recv_rx_key_cb(ngtcp2_conn* conn, ngtcp2_encryption_level level, void* user_data) {
    if (level != NGTCP2_ENCRYPTION_LEVEL_1RTT) return 0;
    return static_cast<QuicClient*>(user_data)->on_handshake_completed() ? 0 : -1;
}

int stream_open_cb(ngtcp2_conn*, int64_t, void*) {
    return 0;
}

int recv_stream_data_cb(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id, uint64_t,
                        const uint8_t* data, size_t datalen, void* user_data, void*) {
    (void)conn;
    return static_cast<QuicClient*>(user_data)->on_recv_stream_data(flags, stream_id, data, datalen)
               ? 0
               : -1;
}

int acked_stream_data_offset_cb(ngtcp2_conn* conn, int64_t stream_id, uint64_t, uint64_t datalen,
                                void* user_data, void*) {
    (void)conn;
    return static_cast<QuicClient*>(user_data)->on_acked_stream_data(stream_id, datalen)
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

int stream_close_cb(ngtcp2_conn* conn, uint32_t, int64_t stream_id, uint64_t app_error_code,
                    void* user_data, void*) {
    (void)conn;
    return static_cast<QuicClient*>(user_data)->on_stream_close(stream_id, app_error_code) ? 0 : -1;
}

int stream_reset_cb(ngtcp2_conn* conn, int64_t stream_id, uint64_t, uint64_t app_error_code,
                    void* user_data, void*) {
    (void)conn;
    return static_cast<QuicClient*>(user_data)->on_stream_reset(stream_id, app_error_code) ? 0 : -1;
}

int stream_stop_sending_cb(ngtcp2_conn* conn, int64_t stream_id, uint64_t app_error_code,
                           void* user_data, void*) {
    (void)conn;
    return static_cast<QuicClient*>(user_data)->on_stream_stop_sending(stream_id, app_error_code)
               ? 0
               : -1;
}

int extend_max_local_streams_bidi_cb(ngtcp2_conn*, uint64_t, void* user_data) {
    static_cast<QuicClient*>(user_data)->try_submit_pending();
    return 0;
}

int extend_max_stream_data_cb(ngtcp2_conn*, int64_t stream_id, uint64_t, void* user_data, void*) {
    return static_cast<QuicClient*>(user_data)->on_extend_max_stream_data(stream_id) ? 0 : -1;
}

int update_key_cb(ngtcp2_conn*, uint8_t*, uint8_t*, ngtcp2_crypto_aead_ctx*, uint8_t*,
                  ngtcp2_crypto_aead_ctx*, uint8_t*, const uint8_t*, const uint8_t*, size_t,
                  void* user_data) {
    (void)user_data;
    return 0;
}

int path_validation_cb(ngtcp2_conn*, uint32_t, const ngtcp2_path*, const ngtcp2_path*,
                       ngtcp2_path_validation_result result, void* user_data) {
    static_cast<QuicClient*>(user_data)->on_path_validation(result);
    return 0;
}

int candidate_path_validation_cb(ngtcp2_conn*, uint32_t, const ngtcp2_path*, const ngtcp2_path*,
                                 ngtcp2_path_validation_result, void*) {
    return 0;
}

int select_preferred_addr_cb(ngtcp2_conn*, ngtcp2_path*, const ngtcp2_preferred_addr*,
                             void* user_data) {
    (void)user_data;
    return 0;
}

int early_data_rejected_cb(ngtcp2_conn*, void* user_data) {
    static_cast<QuicClient*>(user_data)->on_early_data_rejected();
    return 0;
}

int recv_new_token_cb(ngtcp2_conn*, const uint8_t*, size_t, void* user_data) {
    (void)user_data;
    return 0;
}

int recv_stateless_reset_cb(ngtcp2_conn*, const ngtcp2_pkt_stateless_reset*, void* user_data) {
    (void)user_data;
    return 0;
}

int recv_stateless_reset2_cb(ngtcp2_conn*, const ngtcp2_pkt_stateless_reset2*, void* user_data) {
    (void)user_data;
    return 0;
}

int recv_datagram_cb(ngtcp2_conn*, uint32_t, const uint8_t*, size_t, void* user_data) {
    (void)user_data;
    return 0;
}

int ack_datagram_cb(ngtcp2_conn*, uint64_t, void* user_data) {
    (void)user_data;
    return 0;
}

int lost_datagram_cb(ngtcp2_conn*, uint64_t, void* user_data) {
    (void)user_data;
    return 0;
}

int dcid_status_cb(ngtcp2_conn*, uint32_t, const ngtcp2_cid*, ngtcp2_connection_id_status,
                   void* user_data) {
    (void)user_data;
    return 0;
}

int dcid_status2_cb(ngtcp2_conn*, uint32_t, const ngtcp2_cid*, ngtcp2_connection_id_status,
                    void* user_data) {
    (void)user_data;
    return 0;
}

int begin_path_validation_cb(ngtcp2_conn*, uint32_t, const ngtcp2_path*, const ngtcp2_path*,
                             void* user_data) {
    (void)user_data;
    return 0;
}

int version_negotiation_cb(ngtcp2_conn*, const ngtcp2_pkt_hd*, const uint32_t*, size_t,
                           void* user_data) {
    (void)user_data;
    return 0;
}

constexpr ngtcp2_callbacks kCallbacks = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = recv_crypto_data_cb,
    .handshake_completed = handshake_completed_cb,
    .recv_version_negotiation = version_negotiation_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = recv_stream_data_cb,
    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .stream_open = stream_open_cb,
    .stream_close = stream_close_cb,
    .recv_stateless_reset = recv_stateless_reset_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .extend_max_local_streams_bidi = extend_max_local_streams_bidi_cb,
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
    .remove_connection_id = [](ngtcp2_conn*, const ngtcp2_cid*, void*) -> int { return 0; },
    .update_key = update_key_cb,
    .path_validation = path_validation_cb,
    .select_preferred_addr = select_preferred_addr_cb,
    .stream_reset = stream_reset_cb,
    .extend_max_stream_data = extend_max_stream_data_cb,
    .handshake_confirmed = handshake_confirmed_cb,
    .recv_new_token = recv_new_token_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .recv_datagram = recv_datagram_cb,
    .ack_datagram = ack_datagram_cb,
    .lost_datagram = lost_datagram_cb,
    .stream_stop_sending = stream_stop_sending_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    .recv_rx_key = recv_rx_key_cb,
    .tls_early_data_rejected = early_data_rejected_cb,
    .begin_path_validation = begin_path_validation_cb,
    .recv_stateless_reset2 = recv_stateless_reset2_cb,
    .get_new_connection_id2 = get_new_connection_id2_cb,
    .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
};

ngtcp2_conn* candidate_get_conn_cb(ngtcp2_crypto_conn_ref* ref) {
    return static_cast<HandshakeCandidate*>(ref->user_data)->conn;
}

HandshakeCandidate* candidate_from(void* user_data) {
    return static_cast<HandshakeCandidate*>(user_data);
}

int candidate_recv_crypto_data_cb(ngtcp2_conn* conn, ngtcp2_encryption_level level, uint64_t offset,
                                  const uint8_t* data, size_t datalen, void* user_data) {
    int rv = ngtcp2_crypto_recv_crypto_data_cb(conn, level, offset, data, datalen, user_data);
    if (rv != 0) {
        auto* candidate = candidate_from(user_data);
        SSL* ssl = static_cast<SSL*>(ngtcp2_conn_get_tls_native_handle2(conn));
        if (ssl) candidate->owner->captureTlsError(ssl, rv);
        candidate->failed = true;
    }
    return rv;
}

int candidate_handshake_completed_cb(ngtcp2_conn*, void* user_data) {
    candidate_from(user_data)->handshake_completed = true;
    return 0;
}

int candidate_handshake_confirmed_cb(ngtcp2_conn*, void* user_data) {
    auto* candidate = candidate_from(user_data);
    if (candidate->abandoned) return 0;
    candidate->handshake_confirmed = true;
    return 0;
}

int candidate_recv_rx_key_cb(ngtcp2_conn*, ngtcp2_encryption_level level, void* user_data) {
    if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT) {
        auto* candidate = candidate_from(user_data);
        if (candidate->abandoned) return 0;
        candidate->rx_1rtt_key_ready = true;
        candidate->handshake_completed = true;
        if (candidate->one_rtt_ready_at == 0) candidate->one_rtt_ready_at = now_ns();
    }
    return 0;
}

int candidate_recv_stream_data_cb(ngtcp2_conn*, uint32_t flags, int64_t stream_id, uint64_t offset,
                                  const uint8_t* data, size_t datalen, void* user_data, void*) {
    auto* candidate = candidate_from(user_data);
    if (candidate->abandoned) return 0;
    if (candidate->adopted) {
        return candidate->owner->on_recv_stream_data(flags, stream_id, data, datalen)
                   ? 0
                   : NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if (!candidate->buffered_stream_data.append(flags, stream_id, offset, data, datalen)) {
        candidate->failed = true;
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

int candidate_acked_stream_data_cb(ngtcp2_conn*, int64_t stream_id, uint64_t, uint64_t datalen,
                                   void* user_data, void*) {
    return candidate_from(user_data)->owner->on_acked_stream_data(stream_id, datalen)
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

int candidate_stream_close_cb(ngtcp2_conn*, uint32_t, int64_t stream_id, uint64_t app_error,
                              void* user_data, void*) {
    return candidate_from(user_data)->owner->on_stream_close(stream_id, app_error)
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

int candidate_stream_reset_cb(ngtcp2_conn*, int64_t stream_id, uint64_t, uint64_t app_error,
                              void* user_data, void*) {
    return candidate_from(user_data)->owner->on_stream_reset(stream_id, app_error)
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

int candidate_stream_stop_sending_cb(ngtcp2_conn*, int64_t stream_id, uint64_t app_error,
                                     void* user_data, void*) {
    return candidate_from(user_data)->owner->on_stream_stop_sending(stream_id, app_error)
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

int candidate_extend_max_stream_data_cb(ngtcp2_conn*, int64_t stream_id, uint64_t, void* user_data,
                                        void*) {
    return candidate_from(user_data)->owner->on_extend_max_stream_data(stream_id)
               ? 0
               : NGTCP2_ERR_CALLBACK_FAILURE;
}

int candidate_extend_max_streams_bidi_cb(ngtcp2_conn*, uint64_t, void* user_data) {
    candidate_from(user_data)->owner->try_submit_pending();
    return 0;
}

int candidate_get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen,
                                       void* user_data) {
    auto* owner = candidate_from(user_data)->owner;
    if (RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1) return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    owner->generate_reset_token(token, cid);
    return 0;
}

int candidate_get_new_connection_id2_cb(ngtcp2_conn*, ngtcp2_cid* cid,
                                        ngtcp2_stateless_reset_token* token, size_t cidlen,
                                        void* user_data) {
    return candidate_get_new_connection_id_cb(nullptr, cid, token->data, cidlen, user_data);
}

int candidate_early_data_rejected_cb(ngtcp2_conn*, void* user_data) {
    candidate_from(user_data)->owner->on_early_data_rejected();
    return 0;
}

void candidate_qlog_write_cb(void* user_data, uint32_t flags, const void* data, size_t len) {
    auto* candidate = candidate_from(user_data);
    candidate->owner->write_qlog_for_file(candidate->qlog_fd, flags, data, len);
}

constexpr ngtcp2_callbacks kCandidateCallbacks = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = candidate_recv_crypto_data_cb,
    .handshake_completed = candidate_handshake_completed_cb,
    .recv_version_negotiation = version_negotiation_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = candidate_recv_stream_data_cb,
    .acked_stream_data_offset = candidate_acked_stream_data_cb,
    .stream_open = stream_open_cb,
    .stream_close = candidate_stream_close_cb,
    .recv_stateless_reset = recv_stateless_reset_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .extend_max_local_streams_bidi = candidate_extend_max_streams_bidi_cb,
    .rand = rand_cb,
    .get_new_connection_id = candidate_get_new_connection_id_cb,
    .remove_connection_id = [](ngtcp2_conn*, const ngtcp2_cid*, void*) -> int { return 0; },
    .update_key = update_key_cb,
    .path_validation = candidate_path_validation_cb,
    .select_preferred_addr = select_preferred_addr_cb,
    .stream_reset = candidate_stream_reset_cb,
    .extend_max_stream_data = candidate_extend_max_stream_data_cb,
    .handshake_confirmed = candidate_handshake_confirmed_cb,
    .recv_new_token = recv_new_token_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .recv_datagram = recv_datagram_cb,
    .ack_datagram = ack_datagram_cb,
    .lost_datagram = lost_datagram_cb,
    .stream_stop_sending = candidate_stream_stop_sending_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    .recv_rx_key = candidate_recv_rx_key_cb,
    .tls_early_data_rejected = candidate_early_data_rejected_cb,
    .begin_path_validation = begin_path_validation_cb,
    .recv_stateless_reset2 = recv_stateless_reset2_cb,
    .get_new_connection_id2 = candidate_get_new_connection_id2_cb,
    .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
};

}  // namespace

QuicClient::QuicClient(Engine* engine, TlsClientContext& tls_ctx, const Url& origin,
                       std::shared_ptr<Resolver> resolver, bool enable_0rtt, QuicTimeouts timeouts,
                       uint32_t quic_version, std::string qlog_path_prefix,
                       kathttp3_qlog_sink_cb qlog_sink_cb, void* qlog_sink_userdata,
                       uint64_t network_handle)
    : engine_(engine),
      tls_ctx_(tls_ctx),
      origin_(origin),
      resolver_(std::move(resolver)),
      enable_0rtt_(enable_0rtt),
      timeouts_(timeouts),
      quic_version_(quic_version),
      qlog_path_prefix_(std::move(qlog_path_prefix)),
      qlog_sink_cb_(qlog_sink_cb),
      qlog_sink_userdata_(qlog_sink_userdata),
      connection_instance_id_(next_connection_instance_id.fetch_add(1, std::memory_order_relaxed)),
      current_network_handle_(network_handle) {
    timeouts_.dns_ms = timeouts_.dns_ms ? timeouts_.dns_ms : timeouts_.connect_ms;
    timeouts_.handshake_ms = timeouts_.handshake_ms ? timeouts_.handshake_ms : timeouts_.connect_ms;
    timeouts_.response_headers_ms =
        timeouts_.response_headers_ms ? timeouts_.response_headers_ms : timeouts_.request_ms;
    timeouts_.read_ms = timeouts_.read_ms ? timeouts_.read_ms : timeouts_.idle_ms;
    timeouts_.write_ms = timeouts_.write_ms ? timeouts_.write_ms : timeouts_.idle_ms;
    timeouts_.call_ms = timeouts_.call_ms ? timeouts_.call_ms : timeouts_.request_ms;
    timeouts_.consumer_stall_ms =
        timeouts_.consumer_stall_ms ? timeouts_.consumer_stall_ms : timeouts_.read_ms;
    conn_ref_.get_conn = get_conn_cb;
    conn_ref_.user_data = this;
    wakeup_fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    thread_ = std::thread([this] { run(); });
}

QuicClient::~QuicClient() {
    stop_.store(true);
    wakeup();
    if (thread_.joinable()) thread_.join();
    if (conn_) ngtcp2_conn_del(conn_);
    if (qlog_fd_ != -1) ::close(qlog_fd_);
    if (wakeup_fd_ != -1) ::close(wakeup_fd_);
}

int QuicClient::open_qlog_file() {
    if (qlog_path_prefix_.empty()) return -1;
    static std::atomic<uint64_t> next_qlog_id{0};
    for (unsigned attempt = 0; attempt != 16; ++attempt) {
        const uint64_t id = next_qlog_id.fetch_add(1, std::memory_order_relaxed);
        const std::string path =
            qlog_path_prefix_ + "-" + std::to_string(getpid()) + "-" + std::to_string(id) + ".qlog";
        const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd != -1) return fd;
        if (errno != EEXIST) {
            KATHTTP3_LOG_WARN("qlog disabled: cannot open diagnostic file: %s\n", strerror(errno));
            return -1;
        }
    }
    KATHTTP3_LOG_WARN("qlog disabled: unable to allocate a unique diagnostic file\n");
    return -1;
}

void QuicClient::write_qlog(uint32_t flags, const void* data, size_t len) const {
    write_qlog_for_file(qlog_fd_, flags, data, len);
}

void QuicClient::write_qlog_for_file(int fd, uint32_t flags, const void* data, size_t len) const {
    write_qlog_fd(fd, flags, data, len);
    if (!qlog_sink_cb_ || !data || len == 0) return;
    try {
        qlog_sink_cb_(qlog_sink_userdata_, flags, static_cast<const uint8_t*>(data), len);
    } catch (...) {
        KATHTTP3_LOG_WARN("qlog sink threw; ignoring diagnostic record\n");
    }
}

void QuicClient::generate_reset_token(uint8_t* token, const ngtcp2_cid* cid) {
    if (stateless_reset_secret_.empty()) {
        stateless_reset_secret_.resize(32);
        RAND_bytes(stateless_reset_secret_.data(), 32);
    }
    ngtcp2_crypto_generate_stateless_reset_token(token, stateless_reset_secret_.data(),
                                                 stateless_reset_secret_.size(), cid);
}

void QuicClient::wakeup() {
    if (wakeup_fd_ != -1) {
        uint64_t b = 1;
        ssize_t n = write(wakeup_fd_, &b, sizeof(b));
        (void)n;
    }
}

void QuicClient::submit_job(std::unique_ptr<Job> job) {
    job->submitted_at = now_ns();
    job->last_write_progress_at = job->submitted_at;
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        pending_jobs_.push_back(std::move(job));
    }
    wakeup();
}

void QuicClient::request_network_change(NetworkChangeRequest request) {
    // Engine serializes and filters these requests by generation. Publish the
    // handle first so an event-loop acquire of the generation can never see a
    // new generation paired with the previous network.
    requested_network_handle_.store(request.network.value, std::memory_order_relaxed);
    requested_network_generation_.store(request.generation, std::memory_order_release);
    wakeup();
}

void QuicClient::update_keep_alive() {
    if (!conn_) return;
    bool active = false;
    {
        std::lock_guard<std::mutex> lock(job_mutex_);
        active = !active_jobs_.empty();
    }
    const auto* peer = ngtcp2_conn_get_remote_transport_params(conn_);
    if (!active || !peer || peer->max_idle_timeout == 0) {
        ngtcp2_conn_set_keep_alive_timeout(conn_, UINT64_MAX);
        return;
    }
    ngtcp2_conn_set_keep_alive_timeout(conn_,
                                       std::max<ngtcp2_duration>(1, peer->max_idle_timeout / 2));
}

void QuicClient::cancel_job(int64_t job_id) {
    std::lock_guard<std::mutex> lk(job_mutex_);
    for (auto& j : pending_jobs_) {
        if (j->id == job_id) {
            j->cancelled = true;
            return;
        }
    }
    for (auto& j : active_jobs_) {
        if (j->id == job_id) {
            j->cancelled = true;
            wakeup();
            return;
        }
    }
}

bool QuicClient::prepare_endpoints() {
    struct ResolutionResult {
        std::mutex mutex;
        std::condition_variable ready;
        bool complete = false;
        std::vector<ResolvedEndpoint> endpoints;
    };

    std::vector<std::pair<std::string, uint16_t>> supplied_addresses;
    {
        std::lock_guard<std::mutex> jobs_lock(job_mutex_);
        if (pending_jobs_.empty()) return false;
        supplied_addresses = pending_jobs_.front()->request->addresses;
    }
    const uint64_t started = now_ns();
    if (requested_network_generation_.load(std::memory_order_acquire) >
        applied_network_generation_) {
        terminal_error_ = KATHTTP3_ERR_NETWORK_LOST;
        return false;
    }
    if (!supplied_addresses.empty()) {
        for (const auto& a : supplied_addresses) {
            int family = a.first.find(':') == std::string::npos ? AF_INET : AF_INET6;
            endpoints_.push_back({a.first, a.second, family});
        }
    } else {
        auto result = std::make_shared<ResolutionResult>();
        auto cancelled = std::make_shared<std::atomic<bool>>(false);
        if (!resolve_async(resolver_, origin_.host,
                           origin_.port ? origin_.port : default_port(origin_.scheme), cancelled,
                           [result](std::vector<ResolvedEndpoint> endpoints) {
                               std::lock_guard<std::mutex> lock(result->mutex);
                               result->endpoints = std::move(endpoints);
                               result->complete = true;
                               result->ready.notify_one();
                           })) {
            terminal_error_ = KATHTTP3_ERR_DNS;
            return false;
        }

        // This connection worker waits only for its asynchronous resolver;
        // getaddrinfo itself is always executed by the bounded DNS pool.
        // Wake at short intervals so cancellation, close and DNS deadlines
        // do not depend on a resolver implementation cooperating promptly.
        std::unique_lock<std::mutex> lock(result->mutex);
        while (!result->complete) {
            if (requested_network_generation_.load(std::memory_order_acquire) >
                applied_network_generation_) {
                cancel_resolve(cancelled);
                terminal_error_ = KATHTTP3_ERR_NETWORK_LOST;
                return false;
            }
            if (stop_.load(std::memory_order_acquire) || !has_live_pending_job()) {
                cancel_resolve(cancelled);
                return false;
            }
            if (deadline_elapsed_ns(now_ns(), started, timeouts_.dns_ms * NGTCP2_MILLISECONDS)) {
                cancel_resolve(cancelled);
                terminal_error_ = KATHTTP3_ERR_DNS_TIMEOUT;
                return false;
            }
            result->ready.wait_for(lock, std::chrono::milliseconds(10));
        }
        endpoints_ = std::move(result->endpoints);
    }
    if (deadline_elapsed_ns(now_ns(), started, timeouts_.dns_ms * NGTCP2_MILLISECONDS)) {
        endpoints_.clear();
        terminal_error_ = KATHTTP3_ERR_DNS_TIMEOUT;
    }
    return !endpoints_.empty();
}

bool QuicClient::has_live_pending_job() {
    std::lock_guard<std::mutex> lock(job_mutex_);
    for (const auto& job : pending_jobs_)
        if (!job->cancelled) return true;
    return false;
}

bool QuicClient::connect_to_endpoint() {
    return connect_to_endpoint(endpoints_[endpoint_idx_]);
}

bool QuicClient::connect_to_endpoint(const ResolvedEndpoint& ep) {
    if (!sock_.open(ep.family, NetworkHandle{current_network_handle_})) return false;
    sock_.set_nonblocking();
    if (!sock_.connect(ep)) {
        sock_.close();
        return false;
    }
    peer_endpoint_ = ep;
    return true;
}

bool QuicClient::configure_early_data(ngtcp2_conn* conn,
                                      TlsClientContext::ResumptionState* resumption) {
    if (!enable_0rtt_ || !conn || !resumption || !resumption->session ||
        resumption->transport_params.empty() || !resumption->early_data_capable) {
        return false;
    }
    const int rv = ngtcp2_conn_decode_and_set_0rtt_transport_params(
        conn, resumption->transport_params.data(), resumption->transport_params.size());
    if (rv != 0) {
        KATHTTP3_LOG_WARN("0-RTT disabled: cached transport parameters rejected: %s\n",
                          ngtcp2_strerror(rv));
        return false;
    }
    return true;
}

void QuicClient::cache_0rtt_transport_params() {
    if (!conn_) return;
    std::vector<uint8_t> encoded(1024);
    const ngtcp2_ssize n =
        ngtcp2_conn_encode_0rtt_transport_params2(conn_, encoded.data(), encoded.size());
    if (n < 0) {
        KATHTTP3_LOG_WARN("cannot cache 0-RTT transport parameters: %s\n",
                          ngtcp2_strerror(static_cast<int>(n)));
        return;
    }
    encoded.resize(static_cast<size_t>(n));
    tls_session_.set_resumption_transport_params(std::move(encoded));
}

bool QuicClient::setup_connection() {
    ngtcp2_cid scid{}, dcid{};
    scid.datalen = 8;
    RAND_bytes(scid.data, 8);
    dcid.datalen = 8;
    RAND_bytes(dcid.data, 8);

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();
    settings.handshake_timeout = timeouts_.handshake_ms * NGTCP2_MILLISECONDS;
    // PMTUD is deliberately enabled. ngtcp2 uses its safe built-in probe
    // sequence unless a future platform-specific policy supplies probes.
    settings.no_pmtud = 0;
    qlog_fd_ = open_qlog_file();
    if (qlog_fd_ != -1 || qlog_sink_cb_ != nullptr) settings.qlog_write = qlog_write_cb;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    // Streaming payload is not credited until Kotlin consumes it. These
    // advertised limits cap unconsumed native/JNI delivery per stream and for
    // the connection as a whole; consume() re-opens the window in batches.
    configure_receive_windows(&params);
    params.initial_max_streams_bidi = 16;
    params.initial_max_streams_uni = 3;
    params.max_idle_timeout = timeouts_.idle_ms * NGTCP2_MILLISECONDS;
    params.active_connection_id_limit = 4;

    // path: point ngtcp2 at our persistent address storage, then copy the
    // bound (local) and connected (remote) addresses into it.  ngtcp2_addr.addr
    // is a pointer to a caller-owned buffer, NOT an inline array.
    ngtcp2_path path{};
    path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&local_addr_);
    path.local.addrlen = 0;
    path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&remote_addr_);
    path.remote.addrlen = 0;
    sockaddr_storage ss{};
    socklen_t slen = sizeof(ss);
    if (getsockname(sock_.fd(), reinterpret_cast<sockaddr*>(&ss), &slen) == 0) {
        std::memcpy(&local_addr_, &ss, slen);
        path.local.addrlen = slen;
    }
    {
        sockaddr_storage rs{};
        socklen_t rlen = sizeof(rs);
        if (getpeername(sock_.fd(), reinterpret_cast<sockaddr*>(&rs), &rlen) == 0) {
            std::memcpy(&remote_addr_, &rs, rlen);
            path.remote.addrlen = rlen;
        }
    }

    int rv = ngtcp2_conn_client_new_versioned(
        &conn_, &dcid, &scid, &path, quic_version_ ? quic_version_ : NGTCP2_PROTO_VER_V1,
        NGTCP2_CALLBACKS_VERSION, &kCallbacks, NGTCP2_SETTINGS_VERSION, &settings,
        NGTCP2_TRANSPORT_PARAMS_VERSION, &params, nullptr, this);
    if (rv != 0) {
        KATHTTP3_LOG_ERR("ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
        return false;
    }

    auto resumption = tls_ctx_.acquire_resumption(origin_.host);
    early_data_enabled_ = configure_early_data(conn_, &resumption);
    const bool early_params_installed = early_data_enabled_;
    SSL_SESSION* resume_session = resumption.session;
    resumption.session = nullptr;  // ownership transfers to TlsClientSession::init
    if (!tls_session_.init(tls_ctx_, origin_.host, resume_session, &early_data_enabled_,
                           &conn_ref_)) {
        return false;
    }
    if (early_params_installed && !early_data_enabled_) ngtcp2_conn_tls_early_data_rejected(conn_);
    ngtcp2_conn_set_tls_native_handle(conn_, tls_session_.native());

    path_ = path;
    http3_ = std::make_unique<Http3Session>(this, conn_);
    if (early_data_enabled_ && http3_->setup_codec()) {
        http3_ready_ = true;
        // Only replay-safe requests can become observable before the server
        // confirms the TLS handshake. Others remain in FIFO order for 1-RTT.
        if (!precommit_failover_window_) try_submit_pending();
    }
    handshake_confirmed_.store(false);
    state_.store(ConnectionState::Connecting);
    return true;
}

bool QuicClient::start_handshake_candidate(const ResolvedEndpoint& endpoint) {
    auto candidate = std::make_unique<HandshakeCandidate>(this, endpoint);
    if (!candidate->sock.open(endpoint.family, NetworkHandle{current_network_handle_}))
        return false;
    candidate->sock.set_nonblocking();
    if (!candidate->sock.connect(endpoint)) return false;

    ngtcp2_cid scid{}, dcid{};
    scid.datalen = 8;
    dcid.datalen = 8;
    if (RAND_bytes(scid.data, static_cast<int>(scid.datalen)) != 1 ||
        RAND_bytes(dcid.data, static_cast<int>(dcid.datalen)) != 1) {
        return false;
    }

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    candidate->started_at = now_ns();
    settings.initial_ts = candidate->started_at;
    settings.handshake_timeout = timeouts_.handshake_ms * NGTCP2_MILLISECONDS;
    settings.no_pmtud = 0;
    if (candidate->qlog_fd != -1 || qlog_sink_cb_ != nullptr)
        settings.qlog_write = candidate_qlog_write_cb;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    configure_receive_windows(&params);
    params.initial_max_streams_bidi = 16;
    params.initial_max_streams_uni = 3;
    params.max_idle_timeout = timeouts_.idle_ms * NGTCP2_MILLISECONDS;
    params.active_connection_id_limit = 4;

    candidate->path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&candidate->local_addr);
    candidate->path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&candidate->remote_addr);
    sockaddr_storage address{};
    socklen_t address_len = sizeof(address);
    if (getsockname(candidate->sock.fd(), reinterpret_cast<sockaddr*>(&address), &address_len) ==
        0) {
        std::memcpy(&candidate->local_addr, &address, address_len);
        candidate->path.local.addrlen = address_len;
    }
    address_len = sizeof(address);
    if (getpeername(candidate->sock.fd(), reinterpret_cast<sockaddr*>(&address), &address_len) ==
        0) {
        std::memcpy(&candidate->remote_addr, &address, address_len);
        candidate->path.remote.addrlen = address_len;
    }

    int rv = ngtcp2_conn_client_new_versioned(
        &candidate->conn, &dcid, &scid, &candidate->path,
        quic_version_ ? quic_version_ : NGTCP2_PROTO_VER_V1, NGTCP2_CALLBACKS_VERSION,
        &kCandidateCallbacks, NGTCP2_SETTINGS_VERSION, &settings, NGTCP2_TRANSPORT_PARAMS_VERSION,
        &params, nullptr, candidate.get());
    if (rv != 0) {
        KATHTTP3_LOG_ERR("ngtcp2_conn_client_new (Happy Eyeballs): %s\n", ngtcp2_strerror(rv));
        return false;
    }
    candidate->conn_ref.get_conn = candidate_get_conn_cb;
    candidate->conn_ref.user_data = candidate.get();
    // 0-RTT intentionally avoids the parallel Happy Eyeballs path: opening
    // early request streams on two candidates could duplicate an observable
    // request before a handshake winner is known.
    auto resumption = tls_ctx_.acquire_resumption(origin_.host);
    bool candidate_early = configure_early_data(candidate->conn, &resumption);
    const bool candidate_early_params_installed = candidate_early;
    SSL_SESSION* resume_session = resumption.session;
    resumption.session = nullptr;
    if (!candidate->tls.init(tls_ctx_, origin_.host, resume_session, &candidate_early,
                             &candidate->conn_ref))
        return false;
    if (candidate_early_params_installed && !candidate_early)
        ngtcp2_conn_tls_early_data_rejected(candidate->conn);
    ngtcp2_conn_set_tls_native_handle(candidate->conn, candidate->tls.native());
    handshake_candidates_.push_back(std::move(candidate));
    return true;
}

bool QuicClient::adopt_handshake_winner(HandshakeCandidate& candidate) {
    if (!candidate.conn || !candidate.handshake_completed || !candidate.rx_1rtt_key_ready ||
        candidate.one_rtt_ready_at == 0)
        return false;

    /* The callbacks and the SSL conn_ref deliberately continue to point at
     * this candidate.  It is moved into handshake_winner_ below and retained
     * until this QuicClient is destroyed. */
    conn_ = candidate.conn;
    peer_endpoint_ = candidate.endpoint;
    tls_session_ = std::move(candidate.tls);
    std::memcpy(&local_addr_, &candidate.local_addr, sizeof(local_addr_));
    std::memcpy(&remote_addr_, &candidate.remote_addr, sizeof(remote_addr_));
    path_ = candidate.path;
    path_.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&local_addr_);
    path_.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&remote_addr_);
    handshake_started_at_ = candidate.started_at;
    remember_precommit_fallbacks(candidate.endpoint);
    // No request stream is committed until this selected connection is
    // confirmed.  If it fails first, the stored alternate endpoint is safe to
    // try because nghttp3 has not accepted any application request headers.
    precommit_failover_window_ = true;
    http3_ = std::make_unique<Http3Session>(this, conn_);
    http3_ready_ = false;
    handshake_confirmed_.store(false);
    state_.store(ConnectionState::Connecting);
    if (!on_handshake_completed()) {
        http3_.reset();
        candidate.tls = std::move(tls_session_);
        conn_ = nullptr;
        candidate.failed = true;
        terminal_error_ = KATHTTP3_ERR_HTTP3;
        return false;
    }
    candidate.adopted = true;
    for (const auto& buffered : candidate.buffered_stream_data.events()) {
        const uint8_t* data = buffered.data.empty() ? nullptr : buffered.data.data();
        if (!on_recv_stream_data(buffered.flags, buffered.stream_id, data, buffered.data.size())) {
            candidate.adopted = false;
            http3_.reset();
            candidate.tls = std::move(tls_session_);
            conn_ = nullptr;
            candidate.failed = true;
            terminal_error_ = KATHTTP3_ERR_HTTP3;
            return false;
        }
    }
    candidate.buffered_stream_data.clear();
    candidate.owns_connection = false;
    sock_ = std::move(candidate.sock);
    if (candidate.handshake_confirmed) on_handshake_confirmed();

    for (auto& attempt : handshake_candidates_) {
        if (attempt.get() == &candidate) {
            handshake_winner_ = std::move(attempt);
        } else if (attempt) {
            /* No request stream is ever created on a loser.  Closing its UDP
             * fd and destroying ngtcp2 makes the cancellation immediate and
             * prevents a late packet from becoming observable by the winner. */
            attempt->abandoned = true;
            attempt->sock.close();
            attempt.reset();
        }
    }
    handshake_candidates_.clear();
    KATHTTP3_LOG_INFO("Happy Eyeballs selected %s (%s) at 1-RTT-ready time\n",
                      candidate.endpoint.ip.c_str(),
                      candidate.endpoint.family == AF_INET6 ? "IPv6" : "IPv4");
    return true;
}

void QuicClient::remember_precommit_fallbacks(const ResolvedEndpoint& winner) {
    precommit_fallback_endpoints_.clear();
    auto add_if_distinct = [&](const ResolvedEndpoint& endpoint) {
        if (endpoint.family == winner.family && endpoint.ip == winner.ip &&
            endpoint.port == winner.port)
            return;
        for (const auto& existing : precommit_fallback_endpoints_) {
            if (existing.family == endpoint.family && existing.ip == endpoint.ip &&
                existing.port == endpoint.port)
                return;
        }
        precommit_fallback_endpoints_.push_back(endpoint);
    };
    for (const auto& candidate : handshake_candidates_) {
        if (candidate && !candidate->abandoned) add_if_distinct(candidate->endpoint);
    }
    for (const auto& endpoint : endpoints_) add_if_distinct(endpoint);
}

bool QuicClient::can_fail_over_before_request_commit() {
    const bool has_live_pending = has_live_pending_job();
    if (!::kathttp3::can_fail_over_before_request_commit(precommit_failover_window_,
                                                         stop_.load(std::memory_order_acquire),
                                                         false, has_live_pending)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(job_mutex_);
    for (const auto& job : active_jobs_) {
        if (job->native_request_committed || job->body_sent != 0) return false;
    }
    // The pre-commit gate keeps all live requests pending.  Do not attempt a
    // recovery if an unexpected active stream has appeared.
    return active_jobs_.empty() && !precommit_fallback_endpoints_.empty();
}

void QuicClient::discard_current_connection() {
    http3_.reset();
    http3_ready_ = false;
    // Free SSL before the candidate containing its conn_ref is released.
    tls_session_ = TlsClientSession{};
    if (conn_) {
        ngtcp2_conn_del(conn_);
        conn_ = nullptr;
    }
    sock_.close();
    handshake_winner_.reset();
    handshake_confirmed_.store(false);
    state_.store(ConnectionState::Connecting);
    early_data_enabled_ = false;
}

bool QuicClient::restart_precommit_fallback() {
    while (!precommit_fallback_endpoints_.empty() && !stop_.load(std::memory_order_acquire)) {
        const ResolvedEndpoint endpoint = precommit_fallback_endpoints_.front();
        precommit_fallback_endpoints_.erase(precommit_fallback_endpoints_.begin());
        discard_current_connection();
        tls_session_.resetFailure();
        if (!connect_to_endpoint(endpoint) || !setup_connection()) continue;
        handshake_started_at_ = now_ns();
        KATHTTP3_LOG_INFO("Happy Eyeballs retrying %s (%s) before request commit\n",
                          endpoint.ip.c_str(), endpoint.family == AF_INET6 ? "IPv6" : "IPv4");
        return true;
    }
    return false;
}

bool QuicClient::run_handshake_race() {
    constexpr uint64_t kFamilyFallbackDelayNs = 250 * NGTCP2_MILLISECONDS;
    const HappyEyeballsPlan plan = make_happy_eyeballs_plan(endpoints_);
    if (!plan.enabled()) return false;
    if (!start_handshake_candidate(endpoints_[plan.primary])) return false;
    const uint64_t race_started = now_ns();
    bool fallback_started = false;

    auto write_candidate = [](HandshakeCandidate& candidate, uint64_t now) -> bool {
        uint8_t packet[NGTCP2_MAX_PKTLEN];
        for (;;) {
            ngtcp2_pkt_info info{};
            ngtcp2_ssize n = ngtcp2_conn_write_pkt_versioned(candidate.conn, &candidate.path,
                                                             NGTCP2_PKT_INFO_VERSION, &info, packet,
                                                             sizeof(packet), now);
            if (n == NGTCP2_ERR_WRITE_MORE) continue;
            if (n < 0) return false;
            if (n == 0) return true;
            if (candidate.sock.send({packet, static_cast<size_t>(n), info.ecn}) < 0) return false;
        }
    };

    while (!stop_.load(std::memory_order_acquire)) {
        if (requested_network_generation_.load(std::memory_order_acquire) >
            applied_network_generation_) {
            terminal_error_ = KATHTTP3_ERR_NETWORK_LOST;
            return false;
        }
        const uint64_t now = now_ns();
        if (!fallback_started && (elapsed_ns(now, race_started) >= kFamilyFallbackDelayNs ||
                                  handshake_candidates_.front()->failed)) {
            fallback_started = true;
            if (!start_handshake_candidate(endpoints_[plan.fallback])) {
                terminal_error_ = KATHTTP3_ERR_QUIC;
            }
        }
        std::vector<uint64_t> ready_at;
        ready_at.reserve(handshake_candidates_.size());
        for (const auto& candidate : handshake_candidates_) {
            ready_at.push_back(candidate && !candidate->failed && !candidate->abandoned
                                   ? candidate->one_rtt_ready_at
                                   : 0);
        }
        const size_t winner_index = select_earliest_1rtt_candidate(ready_at);
        if (winner_index != kNoHandshakeRaceWinner) {
            return adopt_handshake_winner(*handshake_candidates_[winner_index]);
        }
        if (timeouts_.connect_ms != 0 &&
            deadline_elapsed_ns(now, connection_started_at_,
                                timeouts_.connect_ms * NGTCP2_MILLISECONDS)) {
            terminal_error_ = KATHTTP3_ERR_CONNECT_TIMEOUT;
            return false;
        }

        std::vector<pollfd> fds;
        std::vector<HandshakeCandidate*> polled;
        for (auto& candidate : handshake_candidates_) {
            if (!candidate || candidate->failed || !candidate->conn) continue;
            fds.push_back(
                {candidate->sock.fd(),
                 static_cast<short>(POLLIN | (candidate->sock.wants_write() ? POLLOUT : 0)), 0});
            polled.push_back(candidate.get());
        }
        if (fds.empty() && fallback_started) {
            terminal_error_ = KATHTTP3_ERR_QUIC;
            return false;
        }
        int timeout_ms = 10;
        if (!fallback_started) {
            uint64_t remaining = kFamilyFallbackDelayNs -
                                 std::min(elapsed_ns(now, race_started), kFamilyFallbackDelayNs);
            timeout_ms = static_cast<int>(std::min<uint64_t>(remaining / NGTCP2_MILLISECONDS, 10));
        }
        if (!fds.empty() && poll(fds.data(), fds.size(), timeout_ms) < 0 && errno != EINTR) {
            terminal_error_ = KATHTTP3_ERR_QUIC;
            return false;
        }
        const uint64_t progressed_at = now_ns();
        for (size_t i = 0; i < polled.size(); ++i) {
            HandshakeCandidate& candidate = *polled[i];
            if (fds[i].revents & POLLIN) {
                for (int packets = 0; packets < 16; ++packets) {
                    uint8_t packet[NGTCP2_MAX_PKTLEN];
                    UdpReceiveDatagram datagram{packet, sizeof(packet)};
                    ssize_t n = candidate.sock.recv(datagram);
                    if (n <= 0) break;
                    ngtcp2_pkt_info info{};
                    info.ecn = datagram.ecn;
                    if (ngtcp2_conn_read_pkt_versioned(
                            candidate.conn, &candidate.path, NGTCP2_PKT_INFO_VERSION, &info, packet,
                            static_cast<size_t>(n), progressed_at) != 0) {
                        candidate.failed = true;
                        break;
                    }
                }
            }
            if (!candidate.failed && (fds[i].revents & POLLOUT) &&
                !candidate.sock.flush_send_queue()) {
                candidate.failed = true;
            }
            if (!candidate.failed &&
                ngtcp2_conn_handle_expiry(candidate.conn, progressed_at) != 0) {
                candidate.failed = true;
            }
            if (!candidate.failed && !write_candidate(candidate, progressed_at))
                candidate.failed = true;
            if (!candidate.failed && timeouts_.handshake_ms != 0 &&
                deadline_elapsed_ns(progressed_at, candidate.started_at,
                                    timeouts_.handshake_ms * NGTCP2_MILLISECONDS)) {
                candidate.failed = true;
                terminal_error_ = KATHTTP3_ERR_HANDSHAKE_TIMEOUT;
            }
        }
    }
    return false;
}

void QuicClient::run() {
    connection_started_at_ = now_ns();
    if (!prepare_endpoints()) {
        KATHTTP3_LOG_ERR("run: prepare_endpoints failed -> DNS err\n");
        fail_all_pending(terminal_error_ == KATHTTP3_ERR_QUIC ? KATHTTP3_ERR_DNS : terminal_error_);
        return;
    }

    bool has_ipv4 = false;
    bool has_ipv6 = false;
    for (const auto& endpoint : endpoints_) {
        has_ipv4 = has_ipv4 || endpoint.family == AF_INET;
        has_ipv6 = has_ipv6 || endpoint.family == AF_INET6;
    }
    if (has_ipv4 && has_ipv6 && !(enable_0rtt_ && tls_ctx_.has_early_resumption(origin_.host))) {
        if (run_handshake_race()) {
            /* Exactly one candidate owns the connection now.  Requests have
             * remained pending until this point, so this is safe for POST and
             * other non-idempotent methods. */
            int final_loop_result = event_loop();
            if (final_loop_result != 0 && !stop_.load(std::memory_order_acquire) &&
                terminal_error_ != KATHTTP3_ERR_NETWORK_LOST &&
                can_fail_over_before_request_commit()) {
                while (restart_precommit_fallback()) {
                    final_loop_result = event_loop();
                    if (final_loop_result == 0 || stop_.load(std::memory_order_acquire)) break;
                    if (!can_fail_over_before_request_commit()) break;
                }
            }
            if (final_loop_result != 0 && !stop_.load(std::memory_order_acquire) &&
                (terminal_error_ == KATHTTP3_ERR_NETWORK_LOST ||
                 !can_fail_over_before_request_commit())) {
                const int tls_error = tls_session_.lastFailure().code;
                fail_all_pending(tls_error != 0 ? tls_error : terminal_error_);
            }
            if (conn_) {
                ngtcp2_conn_del(conn_);
                conn_ = nullptr;
            }
            sock_.close();
            closed_.store(true);
            state_.store(ConnectionState::Closed);
            return;
        }
        /* A race failure may be address-specific.  Release its isolated
         * attempts and retain the old sequential path as a last-resort
         * fallback for additional resolver results. */
        handshake_candidates_.clear();
        if (terminal_error_ == KATHTTP3_ERR_NETWORK_LOST) {
            fail_all_pending(terminal_error_);
            closed_.store(true);
            state_.store(ConnectionState::Closed);
            return;
        }
    }

    bool connection_failed = false;
    while (endpoint_idx_ < endpoints_.size() && !stop_ && !handshake_confirmed_) {
        if (timeouts_.connect_ms != 0 &&
            deadline_elapsed_ns(now_ns(), connection_started_at_,
                                timeouts_.connect_ms * NGTCP2_MILLISECONDS)) {
            terminal_error_ = KATHTTP3_ERR_CONNECT_TIMEOUT;
            break;
        }
        tls_session_.resetFailure();
        if (!connect_to_endpoint() || !setup_connection()) {
            KATHTTP3_LOG_ERR("run: endpoint idx=%zu connect/setup failed\n", endpoint_idx_);
            endpoint_idx_++;
            continue;
        }
        handshake_started_at_ = now_ns();
        if (event_loop() != 0) {
            connection_failed = true;
            // handshake failure / fatal. A certificate / hostname / trust
            // failure is not endpoint-specific, so stop retrying (the
            // captured code is already the right one).
            int code = tls_session_.lastFailure().code;
            if (terminal_error_ == KATHTTP3_ERR_NETWORK_LOST) break;
            if (code == KATHTTP3_ERR_CERTIFICATE_VERIFY || code == KATHTTP3_ERR_HOSTNAME_MISMATCH ||
                code == KATHTTP3_ERR_NO_TRUST_PROVIDER) {
                break;
            }
            endpoint_idx_++;
            if (conn_) {
                ngtcp2_conn_del(conn_);
                conn_ = nullptr;
            }
            sock_.close();
            connection_failed = false;
            continue;
        }
        break;
    }
    if (connection_failed && handshake_confirmed_) {
        const int code = tls_session_.lastFailure().code;
        fail_all_pending(code != 0 ? code : terminal_error_);
    } else if (!handshake_confirmed_) {
        int code = tls_session_.lastFailure().code;
        fail_all_pending(code != 0 ? code : terminal_error_);
    }
    if (conn_) {
        ngtcp2_conn_del(conn_);
        conn_ = nullptr;
    }
    sock_.close();
    closed_.store(true);
    state_.store(ConnectionState::Closed);
}

int QuicClient::event_loop() {
    uint8_t pkt[NGTCP2_MAX_PKTLEN];
    uint8_t h3pkt[NGTCP2_MAX_PKTLEN];
    (void)h3pkt;
    last_active_ = now_ns();

    while (!stop_) {
        if (!process_network_change()) return -1;
        uint64_t now = now_ns();
        if (!handshake_confirmed_.load() && timeouts_.handshake_ms != 0 &&
            deadline_elapsed_ns(now, handshake_started_at_,
                                timeouts_.handshake_ms * NGTCP2_MILLISECONDS)) {
            terminal_error_ = KATHTTP3_ERR_HANDSHAKE_TIMEOUT;
            return -1;
        }
        int timeout_ms = compute_timeout(now);
        struct pollfd pfds[2];
        pfds[0].fd = sock_.fd();
        pfds[0].events = static_cast<short>(POLLIN | (sock_.wants_write() ? POLLOUT : 0));
        pfds[1].fd = wakeup_fd_;
        pfds[1].events = POLLIN;
        int nfd = wakeup_fd_ != -1 ? 2 : 1;
        int pr = poll(pfds, nfd, timeout_ms);
        if (pr < 0 && errno == EINTR) continue;
        if (pr < 0) {
            (void)record_socket_error(errno, "poll");
            return -1;
        }
        now = now_ns();

        if (pfds[0].revents & static_cast<short>(POLLERR | POLLHUP | POLLNVAL)) {
            terminal_error_ = KATHTTP3_ERR_NETWORK_LOST;
            KATHTTP3_LOG_WARN("UDP poll path failure connection=%llu revents=0x%x\n",
                              static_cast<unsigned long long>(connection_instance_id_),
                              static_cast<unsigned int>(pfds[0].revents));
            return -1;
        }
        if (pfds[0].revents & POLLIN) {
            for (int i = 0; i < 16; ++i) {
                UdpReceiveDatagram datagram{pkt, sizeof(pkt)};
                ssize_t n = sock_.recv(datagram);
                if (n < 0) {
                    const int error = errno;
                    if (error == EINTR) continue;
                    if (error == EAGAIN || error == EWOULDBLOCK) break;
                    (void)record_socket_error(error, "UDP receive");
                    return -1;
                }
                if (n == 0) break;
                ngtcp2_pkt_info pi{};
                pi.ecn = datagram.ecn;
                int rv = ngtcp2_conn_read_pkt_versioned(
                    conn_, const_cast<const ngtcp2_path*>(&path_), NGTCP2_PKT_INFO_VERSION, &pi,
                    pkt, static_cast<size_t>(n), now);
                if (rv != 0) {
                    KATHTTP3_LOG_ERR("ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
                    return -1;
                }
            }
        }
        if (pfds[0].revents & POLLOUT) {
            if (!sock_.flush_send_queue()) {
                (void)record_socket_error(errno, "UDP queue flush");
                return -1;
            }
        }
        // Migrate only after all events associated with the descriptor polled
        // above are consumed. Swapping the socket before this point could
        // interpret stale revents as belonging to the replacement fd.
        if (wakeup_fd_ != -1 && (pfds[1].revents & POLLIN)) {
            drain_wakeup();
            process_wakeup();
            if (!process_network_change()) return -1;
        }

        int rv = ngtcp2_conn_handle_expiry(conn_, now);
        if (rv != 0) {
            KATHTTP3_LOG_ERR("ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
            return -1;
        }

        // Packet callbacks above can record progress after the poll timestamp.
        // Refresh it so deadline arithmetic never compares against stale time.
        now = now_ns();
        expire_requests(now);
        try_submit_pending();
        update_keep_alive();
        write_pending();
        if (socket_failed_) return -1;

        // Keep the QUIC connection alive so it can be reused for more
        // requests within its idle timeout.  ngtcp2 ends the connection
        // (closing/draining period) once its own idle timeout elapses;
        // at that point we exit and let the Engine recreate on demand.
        if (ngtcp2_conn_in_closing_period2(conn_) || ngtcp2_conn_in_draining_period2(conn_)) {
            return 0;
        }
    }
    return 0;
}

void QuicClient::expire_requests(uint64_t now) {
    std::vector<std::pair<Job*, int>> expired;
    bool connection_timeout_triggered = false;
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        size_t connection_unconsumed = 0;
        for (const auto& job : active_jobs_) {
            if (job->streaming) {
                std::lock_guard<std::mutex> receive_lock(job->receive_credit_mutex);
                connection_unconsumed += job->delivered_unconsumed_bytes;
            }
        }
        auto collect_expired = [&](auto& jobs) {
            for (auto& job : jobs) {
                if (job->cancelled || job->submitted_at == 0) continue;
                if (connection_timeout_triggered) continue;
                int error = KATHTTP3_OK;
                std::lock_guard<std::mutex> receive_lock(job->receive_credit_mutex);
                const bool consumer_blocked =
                    job->streaming && receive_credit_blocked_by_consumer(
                                          job->delivered_unconsumed_bytes, connection_unconsumed);
                if (consumer_blocked) {
                    if (job->consumer_blocked_since == 0) job->consumer_blocked_since = now;
                    if (deadline_elapsed_ns(now, job->consumer_blocked_since,
                                            timeouts_.consumer_stall_ms * NGTCP2_MILLISECONDS)) {
                        error = KATHTTP3_ERR_CONSUMER_STALL;
                    }
                } else {
                    job->consumer_blocked_since = 0;
                }
                if (deadline_elapsed_ns(now, job->submitted_at,
                                        timeouts_.call_ms * NGTCP2_MILLISECONDS)) {
                    error = KATHTTP3_ERR_CALL_TIMEOUT;
                } else if (job->stream_id >= 0 && !job->saw_headers &&
                           timeouts_.response_headers_ms != 0 &&
                           deadline_elapsed_ns(
                               now, job->submitted_at,
                               timeouts_.response_headers_ms * NGTCP2_MILLISECONDS)) {
                    error = KATHTTP3_ERR_RESPONSE_HEADERS_TIMEOUT;
                } else if (error == KATHTTP3_OK && job->saw_headers &&
                           job->last_read_progress_at != 0 && timeouts_.read_ms != 0 &&
                           !consumer_blocked &&
                           deadline_elapsed_ns(now, job->last_read_progress_at,
                                               timeouts_.read_ms * NGTCP2_MILLISECONDS)) {
                    error = KATHTTP3_ERR_READ_TIMEOUT;
                } else if (job->request && job->body_sent < job->request->body.size() &&
                           job->last_write_progress_at != 0 && timeouts_.write_ms != 0 &&
                           deadline_elapsed_ns(now, job->last_write_progress_at,
                                               timeouts_.write_ms * NGTCP2_MILLISECONDS)) {
                    error = KATHTTP3_ERR_WRITE_TIMEOUT;
                }
                if (error != KATHTTP3_OK) {
                    job->cancelled = true;
                    if (error == KATHTTP3_ERR_RESPONSE_HEADERS_TIMEOUT ||
                        error == KATHTTP3_ERR_READ_TIMEOUT || error == KATHTTP3_ERR_WRITE_TIMEOUT) {
                        state_.store(ConnectionState::Draining);
                        connection_timeout_triggered = true;
                    }
                    uint64_t last_progress = job->submitted_at;
                    uint64_t configured_ms = timeouts_.call_ms;
                    if (error == KATHTTP3_ERR_CONSUMER_STALL) {
                        last_progress = job->consumer_blocked_since;
                        configured_ms = timeouts_.consumer_stall_ms;
                    } else if (error == KATHTTP3_ERR_RESPONSE_HEADERS_TIMEOUT) {
                        configured_ms = timeouts_.response_headers_ms;
                    } else if (error == KATHTTP3_ERR_READ_TIMEOUT) {
                        last_progress = job->last_read_progress_at;
                        configured_ms = timeouts_.read_ms;
                    } else if (error == KATHTTP3_ERR_WRITE_TIMEOUT) {
                        last_progress = job->last_write_progress_at;
                        configured_ms = timeouts_.write_ms;
                    }
                    const char* pending_reason =
                        job->stream_id < 0
                            ? (http3_ready_ ? "stream_not_open" : "connection_not_ready")
                            : "active_stream";
                    KATHTTP3_LOG_WARN(
                        "timeout connection=%llu request=%lld stream=%lld code=%d now_ns=%llu "
                        "last_progress_ns=%llu elapsed_ms=%llu configured_timeout_ms=%llu "
                        "connection_state=%s pending_reason=%s remote_address=%s "
                        "address_family=%s\n",
                        static_cast<unsigned long long>(connection_instance_id_),
                        static_cast<long long>(job->id), static_cast<long long>(job->stream_id),
                        error, static_cast<unsigned long long>(now),
                        static_cast<unsigned long long>(last_progress),
                        static_cast<unsigned long long>(elapsed_ns(now, last_progress) /
                                                        NGTCP2_MILLISECONDS),
                        static_cast<unsigned long long>(configured_ms),
                        connection_state_name(state_.load()), pending_reason,
                        peer_endpoint_.ip.empty() ? "-" : peer_endpoint_.ip.c_str(),
                        peer_endpoint_.family == AF_INET6
                            ? "IPv6"
                            : (peer_endpoint_.family == AF_INET ? "IPv4" : "unknown"));
                    expired.emplace_back(job.get(), error);
                }
            }
        };
        collect_expired(pending_jobs_);
        collect_expired(active_jobs_);
        if (connection_timeout_triggered) {
            auto fail_remaining = [&](auto& jobs) {
                for (auto& job : jobs) {
                    if (job->cancelled) continue;
                    job->cancelled = true;
                    KATHTTP3_LOG_WARN(
                        "timeout connection=%llu request=%lld stream=%lld code=%d now_ns=%llu "
                        "last_progress_ns=0 elapsed_ms=0 configured_timeout_ms=0 "
                        "connection_state=draining pending_reason=connection_timeout "
                        "remote_address=%s address_family=%s\n",
                        static_cast<unsigned long long>(connection_instance_id_),
                        static_cast<long long>(job->id), static_cast<long long>(job->stream_id),
                        KATHTTP3_ERR_QUIC, static_cast<unsigned long long>(now),
                        peer_endpoint_.ip.empty() ? "-" : peer_endpoint_.ip.c_str(),
                        peer_endpoint_.family == AF_INET6
                            ? "IPv6"
                            : (peer_endpoint_.family == AF_INET ? "IPv4" : "unknown"));
                    expired.emplace_back(job.get(), KATHTTP3_ERR_QUIC);
                }
            };
            fail_remaining(pending_jobs_);
            fail_remaining(active_jobs_);
        }
    }
    for (const auto& [job, error] : expired) notify_job_error(job, error);
    if (!expired.empty()) wakeup();
}

int QuicClient::compute_timeout(uint64_t now) {
    if (!conn_) return 1000;
    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry2(conn_);
    if (expiry <= now) return 0;
    uint64_t d = expiry - now;
    d /= NGTCP2_MILLISECONDS;
    if (d > 1000) d = 1000;
    return static_cast<int>(d);
}

void QuicClient::drain_wakeup() {
    uint64_t value;
    while (read(wakeup_fd_, &value, sizeof(value)) > 0) {
    }
}

void QuicClient::on_readable() {}

bool QuicClient::record_socket_error(int error, const char* operation) {
    if (udp_error_is_temporary(error)) return false;
    terminal_error_ =
        udp_error_is_network_lost(error) ? KATHTTP3_ERR_NETWORK_LOST : KATHTTP3_ERR_QUIC;
    socket_failed_ = true;
    KATHTTP3_LOG_WARN("%s failed connection=%llu errno=%d (%s)\n", operation,
                      static_cast<unsigned long long>(connection_instance_id_), error,
                      strerror(error));
    return true;
}

void QuicClient::send_packet(const uint8_t* data, size_t len) {
    const ssize_t sent = sock_.send({data, len, 0});
    if (sent != static_cast<ssize_t>(len)) {
        const int error = errno;
        (void)record_socket_error(error, "UDP send");
        return;
    }
    bytes_sent_in_quantum_ += len;
    sent_packet_in_quantum_ = true;
}

bool QuicClient::process_network_change() {
    const uint64_t generation = requested_network_generation_.load(std::memory_order_acquire);
    const uint64_t network_handle = requested_network_handle_.load(std::memory_order_acquire);
    const NetworkChangeRequest request{generation, NetworkHandle{network_handle}};
    const NetworkChangeAction action = network_change_action(
        request, applied_network_generation_, handshake_confirmed_.load(std::memory_order_acquire));
    if (action == NetworkChangeAction::None) return true;
    applied_network_generation_ = generation;
    if (action == NetworkChangeAction::Reconnect || !conn_ || peer_endpoint_.family == 0) {
        terminal_error_ = KATHTTP3_ERR_NETWORK_LOST;
        KATHTTP3_LOG_INFO("network generation=%llu requires reconnect connection=%llu\n",
                          static_cast<unsigned long long>(generation),
                          static_cast<unsigned long long>(connection_instance_id_));
        return false;
    }

    UdpSocket replacement;
    if (!replacement.open(peer_endpoint_.family, NetworkHandle{network_handle})) {
        terminal_error_ = KATHTTP3_ERR_NETWORK_LOST;
        return false;
    }
    replacement.set_nonblocking();
    if (!replacement.connect(peer_endpoint_)) {
        terminal_error_ = KATHTTP3_ERR_NETWORK_LOST;
        return false;
    }
    sockaddr_storage new_local{};
    sockaddr_storage new_remote{};
    socklen_t new_local_len = 0;
    socklen_t new_remote_len = 0;
    if (!replacement.local_address(new_local, new_local_len) ||
        !replacement.remote_address(new_remote, new_remote_len)) {
        terminal_error_ = KATHTTP3_ERR_NETWORK_LOST;
        return false;
    }

    const bool local_changed =
        path_.local.addrlen != new_local_len ||
        std::memcmp(&local_addr_, &new_local, static_cast<size_t>(new_local_len)) != 0;
    if (local_changed) {
        ngtcp2_path new_path{};
        new_path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&new_local);
        new_path.local.addrlen = new_local_len;
        new_path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&new_remote);
        new_path.remote.addrlen = new_remote_len;
        const int rv = ngtcp2_conn_initiate_immediate_migration(conn_, &new_path, now_ns());
        if (rv != 0) {
            KATHTTP3_LOG_WARN("ngtcp2 migration failed connection=%llu: %s\n",
                              static_cast<unsigned long long>(connection_instance_id_),
                              ngtcp2_strerror(rv));
            terminal_error_ = KATHTTP3_ERR_NETWORK_LOST;
            return false;
        }
        migration_in_progress_ = true;
    }

    sock_ = std::move(replacement);
    std::memcpy(&local_addr_, &new_local, static_cast<size_t>(new_local_len));
    std::memcpy(&remote_addr_, &new_remote, static_cast<size_t>(new_remote_len));
    path_.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&local_addr_);
    path_.local.addrlen = new_local_len;
    path_.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&remote_addr_);
    path_.remote.addrlen = new_remote_len;
    current_network_handle_ = network_handle;
    socket_failed_ = false;
    KATHTTP3_LOG_INFO("network migration started connection=%llu generation=%llu validation=%s\n",
                      static_cast<unsigned long long>(connection_instance_id_),
                      static_cast<unsigned long long>(generation),
                      local_changed ? "pending" : "rebinding");
    return true;
}

void QuicClient::begin_send_quantum() {
    bytes_sent_in_quantum_ = 0;
    sent_packet_in_quantum_ = false;
    send_quantum_bytes_ = std::max(kMinimumSendQuantum, ngtcp2_conn_get_send_quantum2(conn_));
}

bool QuicClient::send_quantum_exhausted() const {
    return bytes_sent_in_quantum_ >= send_quantum_bytes_ || sock_.wants_write();
}

void QuicClient::finish_send_quantum(ngtcp2_tstamp ts) {
    if (sent_packet_in_quantum_) ngtcp2_conn_update_pkt_tx_time(conn_, ts);
}

void QuicClient::write_pending() {
    uint64_t now = now_ns();
    begin_send_quantum();
    if (http3_ && http3_->ready()) {
        http3_->pump_write(now);
    }
    if (send_quantum_exhausted()) {
        finish_send_quantum(now);
        return;
    }
    uint8_t pkt[NGTCP2_MAX_PKTLEN];
    for (;;) {
        ngtcp2_pkt_info pi{};
        ngtcp2_ssize n = ngtcp2_conn_write_pkt_versioned(conn_, &path_, NGTCP2_PKT_INFO_VERSION,
                                                         &pi, pkt, sizeof(pkt), now);
        if (n == NGTCP2_ERR_WRITE_MORE) continue;
        if (n < 0) {
            KATHTTP3_LOG_ERR("ngtcp2_conn_write_pkt: %s\n", ngtcp2_strerror((int)n));
            return;
        }
        if (n == 0) break;
        const ssize_t sent = sock_.send({pkt, static_cast<size_t>(n), pi.ecn});
        if (sent != n) {
            (void)record_socket_error(errno, "UDP QUIC send");
            break;
        }
        bytes_sent_in_quantum_ += static_cast<size_t>(n);
        sent_packet_in_quantum_ = true;
        if (send_quantum_exhausted()) break;
    }
    finish_send_quantum(now);
}

void QuicClient::process_wakeup() {
    std::vector<int64_t> streams;
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        for (auto& job : active_jobs_)
            if (job->cancelled && job->stream_id >= 0) streams.push_back(job->stream_id);
    }
    if (http3_ && http3_->ready())
        for (int64_t id : streams) http3_->reset_stream(id);

    // Apply queued streaming receive-window extensions (backpressure ack).
    std::vector<std::pair<int64_t, size_t>> pending;
    {
        std::lock_guard<std::mutex> lk(consume_mutex_);
        pending.swap(pending_consumes_);
    }
    if (conn_ && !pending.empty()) {
        for (auto& kv : pending) {
            ngtcp2_conn_extend_max_stream_offset(conn_, kv.first, kv.second);
            ngtcp2_conn_extend_max_offset(conn_, kv.second);
        }
    }

    // A request-body producer may run on a Kotlin/Java worker thread. nghttp3
    // is not thread-safe, so resume streams only from this QUIC worker thread.
    std::vector<int64_t> body_resumes;
    {
        std::lock_guard<std::mutex> lk(request_body_resume_mutex_);
        body_resumes.swap(pending_request_body_resumes_);
    }
    if (http3_ && http3_->ready()) {
        for (int64_t stream_id : body_resumes) http3_->resume_stream(stream_id);
    }
}

int QuicClient::consume(int64_t request_id, size_t bytes) {
    if (bytes == 0) return KATHTTP3_OK;
    int64_t stream_id = -1;
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        for (auto& job : active_jobs_) {
            if (job->id == request_id) {
                std::lock_guard<std::mutex> receive_lock(job->receive_credit_mutex);
                if (job->cancelled || job->completed || bytes > job->delivered_unconsumed_bytes) {
                    return KATHTTP3_ERR_INVALID_ARG;
                }
                job->delivered_unconsumed_bytes -= bytes;
                job->consumed_body_bytes += bytes;
                stream_id = job->stream_id;
                job->pending_credit_bytes += bytes;
                bytes = job->pending_credit_bytes;
                job->pending_credit_bytes = 0;
                break;
            }
        }
    }
    if (stream_id < 0) return KATHTTP3_ERR_CLOSED;
    {
        std::lock_guard<std::mutex> lk(consume_mutex_);
        pending_consumes_.emplace_back(stream_id, bytes);
    }
    wakeup();
    return KATHTTP3_OK;
}

int QuicClient::append_request_body(int64_t request_id, const uint8_t* data, size_t len,
                                    bool finished) {
    int64_t stream_id = -1;
    {
        std::lock_guard<std::mutex> lock(job_mutex_);
        Job* target = nullptr;
        for (auto& job : pending_jobs_)
            if (job->id == request_id && !job->cancelled && !job->completed) target = job.get();
        for (auto& job : active_jobs_)
            if (job->id == request_id && !job->cancelled && !job->completed) target = job.get();
        if (!target) return KATHTTP3_ERR_CLOSED;
        std::lock_guard<std::mutex> body_lock(target->request_body_mutex);
        constexpr size_t kMaxBufferedRequestBodyBytes = 4 * 1024 * 1024;
        if (len > kMaxBufferedRequestBodyBytes - target->request_body_buffered_bytes)
            return KATHTTP3_ERR_NOMEM;
        if (target->request_body_finished) return KATHTTP3_ERR_INVALID_ARG;
        if (len) {
            target->request_body_chunks.emplace_back(data, data + len);
            target->request_body_buffered_bytes += len;
        }
        target->request_body_finished = finished;
        stream_id = target->stream_id;
    }
    if (stream_id >= 0) {
        std::lock_guard<std::mutex> lk(request_body_resume_mutex_);
        pending_request_body_resumes_.push_back(stream_id);
    }
    wakeup();
    return KATHTTP3_OK;
}

void QuicClient::note_write_progress(int64_t stream_id) {
    std::lock_guard<std::mutex> lk(job_mutex_);
    for (auto& job : active_jobs_) {
        if (job->stream_id == stream_id) {
            job->last_write_progress_at = now_ns();
            return;
        }
    }
}

void QuicClient::try_submit_pending() {
    if (is_draining()) return;
    if (!http3_ready_ || !http3_ || !http3_->ready()) return;
    // Engine callbacks may synchronously invoke cancel()/close().  Never call
    // them while job_mutex_ is held: that formerly made a failed body request
    // (notably PUT) re-enter this mutex and could leave the native worker stuck.
    std::vector<std::pair<std::unique_ptr<Job>, int>> failed;
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        for (auto it = pending_jobs_.begin(); it != pending_jobs_.end();) {
            Job* job = it->get();
            if (job->cancelled) {
                it = pending_jobs_.erase(it);
                continue;
            }
            if (early_data_enabled_ && !handshake_confirmed_.load() && !is_0rtt_replay_safe(*job)) {
                break;
            }
            int64_t stream_id;
            int rv = ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr);
            if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
                break;  // wait for extend_max_local_streams_bidi
            }
            if (rv != 0) {
                failed.emplace_back(std::move(*it), KATHTTP3_ERR_QUIC);
                it = pending_jobs_.erase(it);
                continue;
            }
            job->stream_id = stream_id;
            job->http3_ready = true;
            if (!http3_->submit_request(job)) {
                failed.emplace_back(std::move(*it), KATHTTP3_ERR_HTTP3);
                it = pending_jobs_.erase(it);
                continue;
            }
            job->native_request_committed = true;
            active_jobs_.push_back(std::move(*it));
            it = pending_jobs_.erase(it);
        }
    }
    for (auto& [job, error] : failed) notify_job_error(job.get(), error);
}

void QuicClient::on_handshake_confirmed() {
    handshake_confirmed_.store(true);
    last_active_ = now_ns();
    state_.store(ConnectionState::Active);
    if (precommit_failover_window_) {
        precommit_failover_window_ = false;
        precommit_fallback_endpoints_.clear();
        try_submit_pending();
    }
    KATHTTP3_LOG_INFO("handshake confirmed\n");
}

bool QuicClient::on_handshake_completed() {
    KATHTTP3_LOG_ERR("handshake completed\n");
    cache_0rtt_transport_params();
    if (!http3_ready_ && http3_) {
        if (http3_->setup_codec()) {
            http3_ready_ = true;
            if (!precommit_failover_window_) try_submit_pending();
            update_keep_alive();
        } else {
            return false;
        }
    }
    return true;
}

void QuicClient::setup_codec() {
    on_handshake_completed();
}

bool QuicClient::on_extend_max_stream_data(int64_t stream_id) {
    if (http3_) http3_->extend_max_stream_data(stream_id, 0);
    return true;
}

bool QuicClient::on_acked_stream_data(int64_t stream_id, uint64_t datalen) {
    return !http3_ || http3_->acked_stream_data_offset(stream_id, datalen);
}

bool QuicClient::on_recv_stream_data(uint32_t flags, int64_t stream_id, const uint8_t* data,
                                     size_t len) {
    last_active_ = now_ns();
    if (!http3_ || !http3_->ready()) return false;
    bool fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    int rv = http3_->recv_stream_data(flags, stream_id, data, len, fin, now_ns());
    return rv;
}

bool QuicClient::on_stream_close(int64_t stream_id, uint64_t app_error_code) {
    if (http3_) http3_->on_stream_close(stream_id, app_error_code);
    // Drop the Job from the active list. Its request object is owned by
    // the unique_ptr, so we must not touch it afterwards.
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        for (auto it = active_jobs_.begin(); it != active_jobs_.end(); ++it) {
            if ((*it)->stream_id == stream_id) {
                active_jobs_.erase(it);
                break;
            }
        }
        if (is_draining() && active_jobs_.empty()) stop_.store(true);
    }
    // update_keep_alive takes job_mutex_; call it only after the stream has
    // been removed so an idle reusable connection stops emitting probes.
    update_keep_alive();
    return true;
}

void QuicClient::on_goaway(int64_t stream_id) {
    state_.store(ConnectionState::Draining);
    std::vector<Job*> rejected;
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        for (auto& job : active_jobs_) {
            if (stream_id != NGHTTP3_SHUTDOWN_NOTICE_STREAM_ID && job->stream_id >= stream_id) {
                job->cancelled = true;
                rejected.push_back(job.get());
            }
        }
    }
    for (auto* job : rejected) notify_job_error(job, KATHTTP3_ERR_HTTP3);
    wakeup();
}

void QuicClient::on_path_validation(ngtcp2_path_validation_result result) {
    if (!migration_in_progress_) return;
    migration_in_progress_ = false;
    if (result == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS) {
        KATHTTP3_LOG_INFO("network migration validated connection=%llu generation=%llu\n",
                          static_cast<unsigned long long>(connection_instance_id_),
                          static_cast<unsigned long long>(applied_network_generation_));
        return;
    }
    terminal_error_ = KATHTTP3_ERR_NETWORK_LOST;
    socket_failed_ = true;
    KATHTTP3_LOG_WARN("network migration validation failed connection=%llu result=%d\n",
                      static_cast<unsigned long long>(connection_instance_id_),
                      static_cast<int>(result));
}

bool QuicClient::on_stream_reset(int64_t stream_id, uint64_t app_error_code) {
    if (http3_) http3_->on_stream_reset(stream_id);
    return true;
}

bool QuicClient::on_stream_stop_sending(int64_t stream_id, uint64_t app_error_code) {
    if (http3_) http3_->on_stream_stop_sending(stream_id);
    return true;
}

void QuicClient::on_early_data_rejected() {
    if (!early_data_enabled_) return;
    early_data_enabled_ = false;
    // ngtcp2 discards early streams and stream-ID allocations. Recreate the
    // HTTP/3 control/QPACK state and replay only requests that have not
    // produced an application-visible response.
    {
        std::lock_guard<std::mutex> lock(job_mutex_);
        for (auto it = active_jobs_.begin(); it != active_jobs_.end();) {
            (*it)->stream_id = -1;
            (*it)->http3_ready = false;
            pending_jobs_.push_back(std::move(*it));
            it = active_jobs_.erase(it);
        }
    }
    http3_ = std::make_unique<Http3Session>(this, conn_);
    http3_ready_ = false;
}

void QuicClient::notify_job_headers(Job* job, int status, const HeaderList& headers) {
    engine_->on_job_headers(job, status, headers);
}

void QuicClient::notify_job_body(Job* job, const uint8_t* data, size_t len) {
    engine_->on_job_body(job, data, len);
}

void QuicClient::notify_job_complete(Job* job) {
    engine_->on_job_complete(job);
}

void QuicClient::notify_job_error(Job* job, int err) {
    engine_->on_job_error(job, err, "request failed");
}

void QuicClient::fail_all_pending(int err) {
    std::vector<Job*> jobs;
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        for (auto& j : pending_jobs_) jobs.push_back(j.get());
        for (auto& j : active_jobs_) jobs.push_back(j.get());
    }
    // Invoke the engine WITHOUT holding job_mutex_ (a callback may call
    // cancel_job(), which would otherwise deadlock).
    for (auto* j : jobs) {
        engine_->on_job_error(j, err, "connection setup failed");
    }
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        pending_jobs_.clear();
        active_jobs_.clear();
    }
}

}  // namespace kathttp3

// QuicClient relies on a self-pipe / eventfd for wakeups in the real
// build; for the host build we use a pipe created by the engine before
// starting the client. The default-constructed wakeup_fd_ == -1 means
// the poll loop relies on timeouts (still correct, just slightly less
// responsive to cancellation).  The Android build wires an eventfd here.
namespace kathttp3 {
void QuicClient::set_wakeup_fd(int fd) {
    wakeup_fd_ = fd;
}
}  // namespace kathttp3
