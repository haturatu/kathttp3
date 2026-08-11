#ifndef KATHTTP3_REDIRECT_H
#define KATHTTP3_REDIRECT_H

#include <optional>
#include <string>

#include "response.h"
#include "url.h"

namespace kathttp3 {

struct RedirectDecision {
    bool follow = false;
    bool cross_origin = false;
    bool drop_body = false;
    std::string new_url;
    std::string new_method;
};

/* Decides whether (and how) to follow a redirect. Honors:
 *  - 301/302/303/307/308
 *  - the Location header (absolute or relative)
 *  - the remaining redirect budget
 *  - auto-redirect setting on the request
 * 301/302 may rewrite POST to GET, 303 switches non-HEAD methods to GET, and
 * 307/308 preserve the method. */
class RedirectPolicy {
   public:
    RedirectDecision evaluate(const std::string& method, const Url& from, const Response& resp,
                              bool auto_redirect, unsigned remaining) const;
};

} /* namespace kathttp3 */

#endif /* KATHTTP3_REDIRECT_H */
