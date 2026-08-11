#include "redirect.h"

#include "log.h"

namespace kathttp3 {

namespace {

bool is_redirect_status(int s) {
    return s == 301 || s == 302 || s == 303 || s == 307 || s == 308;
}

bool ascii_alpha(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool ascii_alnum(char c) {
    return ascii_alpha(c) || (c >= '0' && c <= '9');
}

void remove_last_segment(std::string& output) {
    const auto slash = output.find_last_of('/');
    if (slash == std::string::npos) {
        output.clear();
    } else {
        output.erase(slash);
    }
}

std::string remove_dot_segments(std::string input) {
    std::string output;
    while (!input.empty()) {
        if (input.starts_with("../")) {
            input.erase(0, 3);
        } else if (input.starts_with("./")) {
            input.erase(0, 2);
        } else if (input.starts_with("/./")) {
            input.erase(0, 2);
        } else if (input == "/.") {
            input = "/";
        } else if (input.starts_with("/../")) {
            input.erase(0, 3);
            remove_last_segment(output);
        } else if (input == "/..") {
            input = "/";
            remove_last_segment(output);
        } else if (input == "." || input == "..") {
            input.clear();
        } else {
            const size_t segment_end = input.front() == '/' ? input.find('/', 1) : input.find('/');
            if (segment_end == std::string::npos) {
                output += input;
                input.clear();
            } else {
                output.append(input, 0, segment_end);
                input.erase(0, segment_end);
            }
        }
    }
    return output;
}

bool has_valid_scheme(std::string_view ref, bool& has_scheme) {
    has_scheme = false;
    const auto colon = ref.find(':');
    const auto delimiter = ref.find_first_of("/?#");
    if (colon == std::string_view::npos ||
        (delimiter != std::string_view::npos && colon > delimiter)) {
        return true;
    }
    if (colon == 0 || !ascii_alpha(ref.front())) return false;
    for (size_t i = 1; i < colon; ++i) {
        const char c = ref[i];
        if (!ascii_alnum(c) && c != '+' && c != '-' && c != '.') return false;
    }
    has_scheme = true;
    return true;
}

bool resolve_reference(const Url& base, std::string_view reference, Url& target) {
    const auto fragment = reference.find('#');
    if (fragment != std::string_view::npos) reference = reference.substr(0, fragment);

    bool absolute = false;
    if (!has_valid_scheme(reference, absolute)) return false;
    if (absolute) return parse_url(reference, target);
    if (reference.starts_with("//")) {
        return parse_url(base.scheme + ":" + std::string(reference), target);
    }

    target = Url{};
    target.scheme = base.scheme;
    target.host = base.host;
    target.port = base.port;

    const auto question = reference.find('?');
    const std::string_view reference_path = reference.substr(0, question);
    const bool has_query = question != std::string_view::npos;
    const std::string_view reference_query =
        has_query ? reference.substr(question + 1) : std::string_view{};

    if (reference_path.empty()) {
        target.path = base.path;
        if (has_query) {
            target.query = std::string(reference_query);
            target.query_present = true;
        } else {
            target.query = base.query;
            target.query_present = base.query_present;
        }
        return target.valid();
    }

    if (reference_path.front() == '/') {
        target.path = remove_dot_segments(std::string(reference_path));
    } else {
        const auto slash = base.path.find_last_of('/');
        const std::string prefix =
            slash == std::string::npos ? std::string{} : base.path.substr(0, slash + 1);
        target.path = remove_dot_segments(prefix + std::string(reference_path));
    }
    target.query = std::string(reference_query);
    target.query_present = has_query;
    return target.valid();
}

}  // namespace

RedirectDecision RedirectPolicy::evaluate(const std::string& method, const Url& from,
                                          const Response& resp, bool auto_redirect,
                                          unsigned remaining) const {
    RedirectDecision d;
    d.new_method = method;
    if (!auto_redirect) return d;
    if (!is_redirect_status(resp.status_code)) return d;
    if (remaining == 0) {
        KATHTTP3_LOG_WARN("redirect budget exhausted for %s\n", from.host.c_str());
        return d;
    }

    std::string location(resp.headers.get("location"));
    if (location.empty()) return d;

    Url to;
    if (!resolve_reference(from, location, to)) return d;
    // Refuse downgrades to plaintext (KatHttp3 is HTTPS-only).
    if (to.scheme != "https") return d;
    if (!to.valid()) return d;

    // A user agent may rewrite POST to GET for 301/302.  Other methods are
    // preserved.  A 303 rewrites every method except HEAD to GET.
    if ((resp.status_code == 303 && method != "HEAD") ||
        ((resp.status_code == 301 || resp.status_code == 302) && method == "POST")) {
        d.new_method = "GET";
        d.drop_body = true;
    } else {
        d.new_method = method;
        d.drop_body = resp.status_code == 303;
    }

    d.new_url = to.to_string();
    d.cross_origin = from.scheme != to.scheme || from.host != to.host ||
                     (from.port ? from.port : default_port(from.scheme)) !=
                         (to.port ? to.port : default_port(to.scheme));
    d.follow = true;
    return d;
}

} /* namespace kathttp3 */
