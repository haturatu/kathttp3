#ifndef KATHTTP_REDIRECT_H
#define KATHTTP_REDIRECT_H

#include <optional>
#include <string>

#include "response.h"
#include "url.h"

namespace kathttp {

struct RedirectDecision {
    bool follow = false;
    bool cross_origin = false;
    std::string new_url;
    std::string new_method; /* 303 downgrades to GET; 307/308 keep method */
};

/* Decides whether (and how) to follow a redirect. Honors:
 *  - 301/302/303/307/308
 *  - the Location header (absolute or relative)
 *  - the remaining redirect budget
 *  - auto-redirect setting on the request
 * 303 always switches to GET; 307/308 preserve the method. */
class RedirectPolicy {
   public:
    RedirectDecision evaluate(const std::string& method, const Url& from, const Response& resp,
                              bool auto_redirect, unsigned remaining) const;
};

} /* namespace kathttp */

#endif /* KATHTTP_REDIRECT_H */
