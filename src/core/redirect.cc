#include "redirect.h"

#include "log.h"

namespace kathttp {

static bool is_redirect_status(int s) {
  return s == 301 || s == 302 || s == 303 || s == 307 || s == 308;
}

RedirectDecision RedirectPolicy::evaluate(const std::string &method,
                                          const Url &from, const Response &resp,
                                          bool auto_redirect,
                                          unsigned remaining) const {
  RedirectDecision d{false, "", method};
  if (!auto_redirect) return d;
  if (!is_redirect_status(resp.status_code)) return d;
  if (remaining == 0) {
    KATHTTP_LOG_WARN("redirect budget exhausted for %s\n", from.host.c_str());
    return d;
  }

  std::string location(resp.headers.get("location"));
  if (location.empty()) return d;

  // Resolve relative references against `from`.
  Url to;
  if (location.find("://") != std::string::npos) {
    parse_url(location, to);
  } else {
    to.scheme = from.scheme;
    to.host = from.host;
    to.port = from.port;
    if (!location.empty() && location.front() == '/') {
      to.path = location;
    } else {
      // relative path: replace the last segment of `from.path`
      auto slash = from.path.find_last_of('/');
      std::string base = slash == std::string::npos ? "/" : from.path.substr(0, slash + 1);
      to.path = base + location;
    }
    auto q = to.path.find('?');
    if (q != std::string::npos) {
      to.query = to.path.substr(q + 1);
      to.path = to.path.substr(0, q);
    }
  }
  if (!to.valid()) return d;

  // 303 => GET. 307/308 keep the method. 301/302 keep the method per spec
  // (browsers historically switch to GET, but we follow the strict reading).
  if (resp.status_code == 303) {
    d.new_method = "GET";
  } else {
    d.new_method = method;
  }

  d.new_url = to.scheme + "://" + to.authority() + to.request_target();
  // Re-parse to populate the full Url for the caller if needed.
  d.follow = true;
  return d;
}

} /* namespace kathttp */
