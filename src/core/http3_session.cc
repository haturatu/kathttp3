#include "http3_session.h"

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#include <cstdlib>
#include <cstring>

#include "kathttp.h"
#include "log.h"
#include "request.h"
#include "url.h"

namespace kathttp {

#ifndef NGTCP2_MAX_PKTLEN
#define NGTCP2_MAX_PKTLEN 2048
#endif

namespace {

int begin_headers_cb(nghttp3_conn *, int64_t stream_id, void *conn_user_data,
                      void * /*stream_user_data*/) {
  auto *c = static_cast<Http3Session *>(conn_user_data);
  auto *job = c->find_job(stream_id);
  if (job) job->response.headers.clear();
  return 0;
}

int recv_header_cb(nghttp3_conn *, int64_t stream_id, int32_t token,
                    nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t,
                    void *conn_user_data, void * /*stream_user_data*/) {
  (void)token;
  auto *c = static_cast<Http3Session *>(conn_user_data);
  auto *job = c->find_job(stream_id);
  if (!job) return 0;
  nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
  if (n.len == 7 && std::memcmp(n.base, ":status", 7) == 0) {
    job->response.status_code =
        static_cast<int>(strtol(reinterpret_cast<const char *>(v.base), nullptr, 10));
  } else {
    job->response.headers.add(
        std::string(reinterpret_cast<const char *>(n.base), n.len),
        std::string(reinterpret_cast<const char *>(v.base), v.len));
  }
  return 0;
}

int end_headers_cb(nghttp3_conn *, int64_t stream_id, int /*fin*/,
                    void *conn_user_data, void * /*stream_user_data*/) {
  auto *c = static_cast<Http3Session *>(conn_user_data);
  auto *job = c->find_job(stream_id);
  if (job)
    c->client()->notify_job_headers(job, job->response.status_code,
                                    job->response.headers);
  return 0;
}

int recv_data_cb(nghttp3_conn *, int64_t stream_id, const uint8_t *data,
                  size_t len, void *conn_user_data, void * /*stream_user_data*/) {
  auto *c = static_cast<Http3Session *>(conn_user_data);
  auto *job = c->find_job(stream_id);
  if (job) c->client()->notify_job_body(job, data, len);
  ngtcp2_conn_extend_max_stream_offset(c->client()->conn(), stream_id, len);
  ngtcp2_conn_extend_max_offset(c->client()->conn(), len);
  return 0;
}

int end_stream_cb(nghttp3_conn *, int64_t stream_id, void *conn_user_data,
                   void * /*stream_user_data*/) {
  auto *c = static_cast<Http3Session *>(conn_user_data);
  auto *job = c->find_job(stream_id);
  if (job) {
    job->completed = true;
    c->client()->notify_job_complete(job);
  }
  return 0;
}

int stream_close_cb(nghttp3_conn *, int64_t stream_id, uint64_t app_error_code,
                      void *conn_user_data, void * /*stream_user_data*/) {
  auto *c = static_cast<Http3Session *>(conn_user_data);
  auto *job = c->find_job(stream_id);
  if (job && !job->completed) {
    c->client()->notify_job_error(job, KATHTTP_ERR_HTTP3);
  }
  c->unmap_stream(stream_id);
  return 0;
}

int reset_stream_cb(nghttp3_conn *, int64_t stream_id, uint64_t app_error_code,
                      void *conn_user_data, void * /*stream_user_data*/) {
  auto *c = static_cast<Http3Session *>(conn_user_data);
  ngtcp2_conn_shutdown_stream_write(c->client()->conn(), 0, stream_id,
                                     app_error_code);
  return 0;
}

int stop_sending_cb(nghttp3_conn *, int64_t stream_id, uint64_t app_error_code,
                       void *conn_user_data, void * /*stream_user_data*/) {
  auto *c = static_cast<Http3Session *>(conn_user_data);
  ngtcp2_conn_shutdown_stream_read(c->client()->conn(), 0, stream_id,
                                    app_error_code);
  return 0;
}

int acked_stream_data_cb(nghttp3_conn *, int64_t, uint64_t, void *,
                           void *) {
  return 0;
}

int extend_max_stream_data_cb(nghttp3_conn *, int64_t, uint64_t, void *,
                               void *) {
  return 0;
}

int recv_settings_cb(nghttp3_conn *, const nghttp3_settings *,
                      void *conn_user_data) {
  (void)conn_user_data;
  return 0;
}

nghttp3_ssize data_read_cb(nghttp3_conn *, int64_t stream_id, nghttp3_vec *vec,
                           size_t veccnt, uint32_t *pflags,
                           void *stream_user_data, void *conn_user_data) {
  (void)conn_user_data;
  (void)veccnt;
  auto *job = static_cast<Job *>(stream_user_data);
  auto *req = job->request;
  vec[0].base = nullptr;
  vec[0].len = 0;
  if (job->body_sent < req->body.size()) {
    vec[0].base = req->body.data() + job->body_sent;
    vec[0].len = req->body.size() - job->body_sent;
    job->body_sent += vec[0].len;
    *pflags = 0;
    return 1;
  }
  *pflags = NGHTTP3_DATA_FLAG_EOF;
  return 0;
}

constexpr nghttp3_callbacks kH3Callbacks = {
    .acked_stream_data = acked_stream_data_cb,
    .stream_close = stream_close_cb,
    .recv_data = recv_data_cb,
    .deferred_consume = nullptr,
    .begin_headers = begin_headers_cb,
    .recv_header = recv_header_cb,
    .end_headers = end_headers_cb,
    .begin_trailers = nullptr,
    .recv_trailer = nullptr,
    .end_trailers = nullptr,
    .stop_sending = stop_sending_cb,
    .end_stream = end_stream_cb,
    .reset_stream = reset_stream_cb,
    .shutdown = nullptr,
    .recv_settings = recv_settings_cb,
    .recv_origin = nullptr,
    .end_origin = nullptr,
    .rand = nullptr,
    .recv_settings2 = nullptr,
};

}  // namespace

Http3Session::Http3Session(QuicClient *client, ngtcp2_conn *conn)
    : client_(client), conn_(conn) {}

Http3Session::~Http3Session() {
  if (httpconn_) nghttp3_conn_del(httpconn_);
}

Job *Http3Session::find_job(int64_t stream_id) {
  auto it = streams_.find(stream_id);
  if (it == streams_.end()) return nullptr;
  return it->second;
}

void Http3Session::map_stream(int64_t stream_id, Job *job) {
  streams_[stream_id] = job;
}

void Http3Session::unmap_stream(int64_t stream_id) {
  streams_.erase(stream_id);
}

bool Http3Session::setup_codec() {
  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  nghttp3_conn *conn = nullptr;
  int rv = nghttp3_conn_client_new_versioned(
      &conn, NGHTTP3_CALLBACKS_VERSION, &kH3Callbacks,
      NGHTTP3_SETTINGS_VERSION, &settings, nullptr, this);
  if (rv != 0) {
    KATHTTP_LOG_ERR("nghttp3_conn_client_new: %s\n",
                     nghttp3_strerror(rv));
    return false;
  }
  httpconn_ = conn;
  int64_t control_id, encoder_id, decoder_id;
  if (ngtcp2_conn_open_uni_stream(conn_, &control_id, nullptr) != 0 ||
      ngtcp2_conn_open_uni_stream(conn_, &encoder_id, nullptr) != 0 ||
      ngtcp2_conn_open_uni_stream(conn_, &decoder_id, nullptr) != 0 ||
      nghttp3_conn_bind_control_stream(httpconn_, control_id) != 0 ||
      nghttp3_conn_bind_qpack_streams(httpconn_, encoder_id, decoder_id) != 0) {
    KATHTTP_LOG_ERR("failed to bind HTTP/3 critical streams\n");
    nghttp3_conn_del(httpconn_);
    httpconn_ = nullptr;
    return false;
  }
  return true;
}

bool Http3Session::submit_request(Job *job) {
  std::vector<nghttp3_nv> nva;
  auto &url = job->url;
  const auto &req = *job->request;

  auto add_nv = [&](const char *name, size_t nlen, const std::string &val) {
    nva.push_back({reinterpret_cast<const uint8_t *>(name),
                   reinterpret_cast<const uint8_t *>(val.data()), nlen,
                   val.size(), NGHTTP3_NV_FLAG_NONE});
  };
  add_nv(":method", 7, req.method);
  add_nv(":scheme", 7, url.scheme);
  std::string authority = url.host;
  if (!((url.scheme == "https" && url.port == 443) ||
         (url.scheme == "http" && url.port == 80))) {
    authority += ":";
    authority += std::to_string(url.port);
  }
  add_nv(":authority", 10, authority);
  std::string path = url.path.empty() ? "/" : url.path;
  if (!url.query.empty()) {
    path += "?";
    path += url.query;
  }
  add_nv(":path", 5, path);

  for (const auto &h : req.headers.list()) {
    nva.push_back({reinterpret_cast<const uint8_t *>(h.name.data()),
                   reinterpret_cast<const uint8_t *>(h.value.data()),
                   h.name.size(), h.value.size(), NGHTTP3_NV_FLAG_NONE});
  }

  nghttp3_data_reader dr{data_read_cb};
  const nghttp3_data_reader *drp = nullptr;
  if (!req.body.empty()) {
    // Ensure a Content-Length is present so servers parse the body.
    bool has_cl = false;
    for (const auto &h : req.headers.list()) {
      if (strcasecmp(h.name.c_str(), "content-length") == 0) {
        has_cl = true;
        break;
      }
    }
    if (!has_cl) {
      std::string cl = std::to_string(req.body.size());
      nva.push_back(
          {reinterpret_cast<const uint8_t *>("content-length"),
           reinterpret_cast<const uint8_t *>(cl.data()), 14, cl.size(),
           NGHTTP3_NV_FLAG_NONE});
    }
    drp = &dr;
  }

  int rv = nghttp3_conn_submit_request(httpconn_, job->stream_id, nva.data(),
                                       nva.size(), drp, job);
  if (rv != 0) {
    KATHTTP_LOG_ERR("nghttp3_conn_submit_request: %s\n",
                     nghttp3_strerror(rv));
    return false;
  }
  map_stream(job->stream_id, job);
  return true;
}

void Http3Session::pump_write(ngtcp2_tstamp ts) {
  if (!httpconn_) return;
  uint8_t h3buf[NGTCP2_MAX_PKTLEN];
  uint8_t pkt[NGTCP2_MAX_PKTLEN];
  for (;;) {
    int64_t stream_id = -1;
    int fin = 0;
    nghttp3_vec vec;
    vec.base = h3buf;
    vec.len = sizeof(h3buf);
    nghttp3_ssize n =
        nghttp3_conn_writev_stream(httpconn_, &stream_id, &fin, &vec, 1);
    if (n < 0) {
      KATHTTP_LOG_ERR("nghttp3_conn_writev_stream: %s\n",
                       nghttp3_strerror((int)n));
      return;
    }
    if (n == 0 && stream_id == -1) return;
    ngtcp2_vec nv;
    nv.base = n > 0 ? const_cast<uint8_t *>(vec.base) : nullptr;
    nv.len = n > 0 ? vec.len : 0;
    ngtcp2_pkt_info pi{};
    ngtcp2_ssize ndatalen = -1;
    ngtcp2_ssize w = ngtcp2_conn_writev_stream(
        client_->conn(), &client_->path(), &pi, pkt, sizeof(pkt), &ndatalen,
        fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0, stream_id,
        n > 0 ? &nv : nullptr, n > 0 ? 1 : 0, ts);
    if (w == NGTCP2_ERR_WRITE_MORE) {
      if (ndatalen >= 0) nghttp3_conn_add_write_offset(httpconn_, stream_id, static_cast<size_t>(ndatalen));
      continue;
    }
    if (w < 0) {
      KATHTTP_LOG_ERR("ngtcp2_conn_writev_stream: %s\n",
                       ngtcp2_strerror((int)w));
      return;
    }
    if (ndatalen >= 0) nghttp3_conn_add_write_offset(httpconn_, stream_id, static_cast<size_t>(ndatalen));
    if (w == 0) return;
    if (w > 0) client_->send_packet(pkt, static_cast<size_t>(w));
  }
}

bool Http3Session::recv_stream_data(uint32_t, int64_t stream_id,
                                      const uint8_t *data, size_t len, bool fin,
                                      ngtcp2_tstamp ts) {
  if (!httpconn_) return false;
  int rv = nghttp3_conn_read_stream(httpconn_, stream_id, data, len,
                                    fin ? 1 : 0);
  if (rv < 0) {
    KATHTTP_LOG_ERR("nghttp3_conn_read_stream: %s\n",
                     nghttp3_strerror(rv));
    return false;
  }
  ngtcp2_conn_extend_max_stream_offset(client_->conn(), stream_id,
                                       static_cast<uint64_t>(rv));
  ngtcp2_conn_extend_max_offset(client_->conn(), static_cast<uint64_t>(rv));
  return true;
}

bool Http3Session::acked_stream_data_offset(int64_t stream_id, uint64_t n) {
  return !httpconn_ || nghttp3_conn_add_ack_offset(httpconn_, stream_id, n) == 0;
}

bool Http3Session::extend_max_stream_data(int64_t, uint64_t) { return true; }

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

}  // namespace kathttp
