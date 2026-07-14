#ifndef KATHTTP3_PRECOMMIT_FAILOVER_H
#define KATHTTP3_PRECOMMIT_FAILOVER_H

namespace kathttp3 {

/* A connection may be replaced only before a request is committed to
 * nghttp3.  This is intentionally stricter than observing packet output:
 * once nghttp3 owns request HEADERS, retries cannot prove non-delivery. */
inline bool can_fail_over_before_request_commit(bool failover_window_open, bool stopping,
                                                bool request_committed,
                                                bool has_live_pending_request = true) {
    return failover_window_open && !stopping && !request_committed && has_live_pending_request;
}

}  // namespace kathttp3

#endif  // KATHTTP3_PRECOMMIT_FAILOVER_H
