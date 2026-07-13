#include "quic_client.h"

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>

#include "engine.h"
#include "http3_session.h"
#include "log.h"
#include "request.h"
#include "time_util.h"

#ifndef NGTCP2_MAX_PKTLEN
#define NGTCP2_MAX_PKTLEN 2048
#endif
#ifndef NGTCP2_WRITE_STREAM_FLAG_FIN
#define NGTCP2_WRITE_STREAM_FLAG_FIN 0x1
#endif

namespace kathttp {

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
        KATHTTP_LOG_ERR("recv_crypto_data_cb: level=%d rv=%d ngtcp2=%s ssl='%s'\n", level, rv,
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
                       ngtcp2_path_validation_result, void* user_data) {
    (void)user_data;
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

}  // namespace

QuicClient::QuicClient(Engine* engine, TlsClientContext& tls_ctx, const Url& origin,
                       std::shared_ptr<Resolver> resolver, bool enable_0rtt,
                       uint64_t connect_timeout_ms, uint64_t request_timeout_ms,
                       uint64_t idle_timeout_ms, uint64_t dns_timeout_ms,
                       uint64_t handshake_timeout_ms, uint64_t response_headers_timeout_ms,
                       uint64_t read_timeout_ms, uint64_t write_timeout_ms,
                       uint64_t call_timeout_ms, uint32_t quic_version)
    : engine_(engine),
      tls_ctx_(tls_ctx),
      origin_(origin),
      resolver_(std::move(resolver)),
      enable_0rtt_(enable_0rtt),
      connect_timeout_ms_(connect_timeout_ms),
      request_timeout_ms_(request_timeout_ms),
      idle_timeout_ms_(idle_timeout_ms),
      dns_timeout_ms_(dns_timeout_ms ? dns_timeout_ms : connect_timeout_ms),
      handshake_timeout_ms_(handshake_timeout_ms ? handshake_timeout_ms : connect_timeout_ms),
      response_headers_timeout_ms_(response_headers_timeout_ms ? response_headers_timeout_ms
                                                                : request_timeout_ms),
      read_timeout_ms_(read_timeout_ms ? read_timeout_ms : idle_timeout_ms),
      write_timeout_ms_(write_timeout_ms ? write_timeout_ms : idle_timeout_ms),
      call_timeout_ms_(call_timeout_ms ? call_timeout_ms : request_timeout_ms),
      quic_version_(quic_version) {
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
    if (wakeup_fd_ != -1) ::close(wakeup_fd_);
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
    std::lock_guard<std::mutex> lk(job_mutex_);
    if (pending_jobs_.empty()) return false;
    const uint64_t started = now_ns();
    const auto* req = pending_jobs_.front()->request;
    if (!req->addresses.empty()) {
        for (const auto& a : req->addresses) {
            int family = a.first.find(':') == std::string::npos ? AF_INET : AF_INET6;
            endpoints_.push_back({a.first, a.second, family});
        }
    } else {
        endpoints_ = resolver_->resolve(
            origin_.host, origin_.port ? origin_.port : default_port(origin_.scheme), &stop_);
    }
    if (dns_timeout_ms_ != 0 && now_ns() - started >= dns_timeout_ms_ * NGTCP2_MILLISECONDS) {
        endpoints_.clear();
        terminal_error_ = KATHTTP_ERR_DNS_TIMEOUT;
    }
    return !endpoints_.empty();
}

bool QuicClient::connect_to_endpoint() {
    const auto& ep = endpoints_[endpoint_idx_];
    if (!sock_.open(ep.family)) return false;
    sock_.set_nonblocking();
    if (!sock_.connect(ep)) {
        sock_.close();
        return false;
    }
    return true;
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
    settings.handshake_timeout = handshake_timeout_ms_ * NGTCP2_MILLISECONDS;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_data = 16 * 1024 * 1024;
    params.initial_max_streams_bidi = 16;
    params.initial_max_streams_uni = 3;
    params.max_idle_timeout = idle_timeout_ms_ * NGTCP2_MILLISECONDS;
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
        KATHTTP_LOG_ERR("ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
        return false;
    }

    if (!tls_session_.init(tls_ctx_, origin_.host, enable_0rtt_, &conn_ref_)) {
        return false;
    }
    ngtcp2_conn_set_tls_native_handle(conn_, tls_session_.native());

    path_ = path;
    http3_ = std::make_unique<Http3Session>(this, conn_);
    handshake_confirmed_.store(false);
    return true;
}

void QuicClient::run() {
    connection_started_at_ = now_ns();
    if (!prepare_endpoints()) {
        KATHTTP_LOG_ERR("run: prepare_endpoints failed -> DNS err\n");
        fail_all_pending(terminal_error_ == KATHTTP_ERR_QUIC ? KATHTTP_ERR_DNS : terminal_error_);
        return;
    }
    while (endpoint_idx_ < endpoints_.size() && !stop_ && !handshake_confirmed_) {
        if (connect_timeout_ms_ != 0 &&
            now_ns() - connection_started_at_ >= connect_timeout_ms_ * NGTCP2_MILLISECONDS) {
            terminal_error_ = KATHTTP_ERR_CONNECT_TIMEOUT;
            break;
        }
        tls_session_.resetFailure();
        if (!connect_to_endpoint() || !setup_connection()) {
            KATHTTP_LOG_ERR("run: endpoint idx=%zu connect/setup failed\n", endpoint_idx_);
            endpoint_idx_++;
            continue;
        }
        handshake_started_at_ = now_ns();
        if (event_loop() != 0) {
            // handshake failure / fatal. A certificate / hostname / trust
            // failure is not endpoint-specific, so stop retrying (the
            // captured code is already the right one).
            int code = tls_session_.lastFailure().code;
            if (code == KATHTTP_ERR_CERTIFICATE_VERIFY || code == KATHTTP_ERR_HOSTNAME_MISMATCH ||
                code == KATHTTP_ERR_NO_TRUST_PROVIDER) {
                break;
            }
            endpoint_idx_++;
            if (conn_) {
                ngtcp2_conn_del(conn_);
                conn_ = nullptr;
            }
            sock_.close();
            continue;
        }
        break;
    }
    if (!handshake_confirmed_) {
        int code = tls_session_.lastFailure().code;
        fail_all_pending(code != 0 ? code : terminal_error_);
    }
    if (conn_) {
        ngtcp2_conn_del(conn_);
        conn_ = nullptr;
    }
    sock_.close();
    closed_.store(true);
}

int QuicClient::event_loop() {
    uint8_t pkt[NGTCP2_MAX_PKTLEN];
    uint8_t h3pkt[NGTCP2_MAX_PKTLEN];
    (void)h3pkt;
    sockaddr_storage from{};
    socklen_t fromlen = sizeof(from);
    unsigned int ecn = 0;
    last_active_ = now_ns();

    while (!stop_) {
        uint64_t now = now_ns();
        if (!handshake_confirmed_.load() && handshake_timeout_ms_ != 0 &&
            now - handshake_started_at_ >= handshake_timeout_ms_ * NGTCP2_MILLISECONDS) {
            terminal_error_ = KATHTTP_ERR_HANDSHAKE_TIMEOUT;
            return -1;
        }
        int timeout_ms = compute_timeout(now);
        struct pollfd pfds[2];
        pfds[0].fd = sock_.fd();
        pfds[0].events = POLLIN;
        pfds[1].fd = wakeup_fd_;
        pfds[1].events = POLLIN;
        int nfd = wakeup_fd_ != -1 ? 2 : 1;
        int pr = poll(pfds, nfd, timeout_ms);
        if (pr < 0 && errno != EINTR) {
            return -1;
        }
        now = now_ns();

        if (wakeup_fd_ != -1 && (pfds[1].revents & POLLIN)) {
            drain_wakeup();
            process_wakeup();
        }
        if (pfds[0].revents & POLLIN) {
            for (int i = 0; i < 16; ++i) {
                ssize_t n = sock_.recv(pkt, sizeof(pkt), from, fromlen, ecn);
                if (n <= 0) break;
                ngtcp2_pkt_info pi{};
                pi.ecn = ecn;
                int rv = ngtcp2_conn_read_pkt_versioned(
                    conn_, const_cast<const ngtcp2_path*>(&path_), NGTCP2_PKT_INFO_VERSION, &pi,
                    pkt, static_cast<size_t>(n), now);
                if (rv != 0) {
                    KATHTTP_LOG_ERR("ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
                    return -1;
                }
            }
        }

        int rv = ngtcp2_conn_handle_expiry(conn_, now);
        if (rv != 0) {
            KATHTTP_LOG_ERR("ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
            return -1;
        }

        expire_requests(now);
        try_submit_pending();
        write_pending();

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
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        auto collect_expired = [&](auto& jobs) {
            for (auto& job : jobs) {
                if (job->cancelled || job->submitted_at == 0) continue;
                int error = KATHTTP_OK;
                if (call_timeout_ms_ != 0 &&
                    now - job->submitted_at >= call_timeout_ms_ * NGTCP2_MILLISECONDS) {
                    error = KATHTTP_ERR_CALL_TIMEOUT;
                } else if (job->stream_id >= 0 && !job->saw_headers &&
                           response_headers_timeout_ms_ != 0 &&
                           now - job->submitted_at >=
                               response_headers_timeout_ms_ * NGTCP2_MILLISECONDS) {
                    error = KATHTTP_ERR_RESPONSE_HEADERS_TIMEOUT;
                } else if (job->saw_headers && job->last_read_progress_at != 0 &&
                           read_timeout_ms_ != 0 &&
                           now - job->last_read_progress_at >=
                               read_timeout_ms_ * NGTCP2_MILLISECONDS) {
                    error = KATHTTP_ERR_READ_TIMEOUT;
                } else if (job->request && job->body_sent < job->request->body.size() &&
                           job->last_write_progress_at != 0 && write_timeout_ms_ != 0 &&
                           now - job->last_write_progress_at >=
                               write_timeout_ms_ * NGTCP2_MILLISECONDS) {
                    error = KATHTTP_ERR_WRITE_TIMEOUT;
                }
                if (error != KATHTTP_OK) {
                    job->cancelled = true;
                    expired.emplace_back(job.get(), error);
                }
            }
        };
        collect_expired(pending_jobs_);
        collect_expired(active_jobs_);
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

void QuicClient::write_pending() {
    uint64_t now = now_ns();
    if (http3_ && http3_->ready()) {
        http3_->pump_write(now);
    }
    uint8_t pkt[NGTCP2_MAX_PKTLEN];
    for (;;) {
        ngtcp2_pkt_info pi{};
        ngtcp2_ssize n = ngtcp2_conn_write_pkt_versioned(conn_, &path_, NGTCP2_PKT_INFO_VERSION,
                                                         &pi, pkt, sizeof(pkt), now);
        if (n == NGTCP2_ERR_WRITE_MORE) continue;
        if (n < 0) {
            KATHTTP_LOG_ERR("ngtcp2_conn_write_pkt: %s\n", ngtcp2_strerror((int)n));
            return;
        }
        if (n == 0) break;
        sock_.send(pkt, static_cast<size_t>(n), pi.ecn);
    }
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
}

int QuicClient::consume(int64_t request_id, size_t bytes) {
    if (bytes == 0) return KATHTTP_OK;
    int64_t stream_id = -1;
    {
        std::lock_guard<std::mutex> lk(job_mutex_);
        for (auto& job : active_jobs_) {
            if (job->id == request_id) {
                if (job->cancelled || job->completed || bytes > job->delivered_unconsumed_bytes) {
                    return KATHTTP_ERR_INVALID_ARG;
                }
                job->delivered_unconsumed_bytes -= bytes;
                job->consumed_body_bytes += bytes;
                stream_id = job->stream_id;
                break;
            }
        }
    }
    if (stream_id < 0) return KATHTTP_ERR_CLOSED;
    {
        std::lock_guard<std::mutex> lk(consume_mutex_);
        pending_consumes_.emplace_back(stream_id, bytes);
    }
    wakeup();
    return KATHTTP_OK;
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
            int64_t stream_id;
            int rv = ngtcp2_conn_open_bidi_stream(conn_, &stream_id, nullptr);
            if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
                break;  // wait for extend_max_local_streams_bidi
            }
            if (rv != 0) {
                failed.emplace_back(std::move(*it), KATHTTP_ERR_QUIC);
                it = pending_jobs_.erase(it);
                continue;
            }
            job->stream_id = stream_id;
            job->http3_ready = true;
            if (!http3_->submit_request(job)) {
                failed.emplace_back(std::move(*it), KATHTTP_ERR_HTTP3);
                it = pending_jobs_.erase(it);
                continue;
            }
            active_jobs_.push_back(std::move(*it));
            it = pending_jobs_.erase(it);
        }
    }
    for (auto& [job, error] : failed) notify_job_error(job.get(), error);
}

void QuicClient::on_handshake_confirmed() {
    handshake_confirmed_.store(true);
    last_active_ = now_ns();
    KATHTTP_LOG_ERR("handshake confirmed\n");
}

bool QuicClient::on_handshake_completed() {
    KATHTTP_LOG_ERR("handshake completed\n");
    if (!http3_ready_ && http3_) {
        if (http3_->setup_codec()) {
            http3_ready_ = true;
            try_submit_pending();
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
    std::lock_guard<std::mutex> lk(job_mutex_);
    for (auto it = active_jobs_.begin(); it != active_jobs_.end(); ++it) {
        if ((*it)->stream_id == stream_id) {
            active_jobs_.erase(it);
            break;
        }
    }
    return true;
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
    if (http3_) http3_->early_data_rejected();
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

}  // namespace kathttp

// QuicClient relies on a self-pipe / eventfd for wakeups in the real
// build; for the host build we use a pipe created by the engine before
// starting the client. The default-constructed wakeup_fd_ == -1 means
// the poll loop relies on timeouts (still correct, just slightly less
// responsive to cancellation).  The Android build wires an eventfd here.
namespace kathttp {
void QuicClient::set_wakeup_fd(int fd) {
    wakeup_fd_ = fd;
}
}  // namespace kathttp
