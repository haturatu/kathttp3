#include "cache_control.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace kathttp3 {

namespace {

std::string_view trim_ows(std::string_view value) {
    const size_t begin = value.find_first_not_of(" \t");
    if (begin == std::string_view::npos) return {};
    const size_t end = value.find_last_not_of(" \t");
    return value.substr(begin, end - begin + 1);
}

bool ascii_iequals(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        unsigned char a = static_cast<unsigned char>(lhs[i]);
        unsigned char b = static_cast<unsigned char>(rhs[i]);
        if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + ('a' - 'A'));
        if (a != b) return false;
    }
    return true;
}

std::vector<std::string_view> split_directives(std::string_view field) {
    std::vector<std::string_view> directives;
    size_t begin = 0;
    bool quoted = false;
    bool escaped = false;
    for (size_t i = 0; i < field.size(); ++i) {
        const char ch = field[i];
        if (quoted) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                quoted = false;
            }
        } else if (ch == '"') {
            quoted = true;
        } else if (ch == ',') {
            directives.push_back(field.substr(begin, i - begin));
            begin = i + 1;
        }
    }
    directives.push_back(field.substr(begin));
    return directives;
}

struct ParsedDirective {
    std::string_view name;
    std::string value;
    bool has_value = false;
    bool value_valid = true;
};

ParsedDirective parse_directive(std::string_view raw) {
    raw = trim_ows(raw);
    const size_t equals = raw.find('=');
    ParsedDirective out;
    out.name = trim_ows(equals == std::string_view::npos ? raw : raw.substr(0, equals));
    if (equals == std::string_view::npos) return out;

    out.has_value = true;
    std::string_view value = trim_ows(raw.substr(equals + 1));
    if (value.empty()) {
        out.value_valid = false;
        return out;
    }
    if (value.front() != '"') {
        out.value = std::string(value);
        return out;
    }

    if (value.size() < 2 || value.back() != '"') {
        out.value_valid = false;
        return out;
    }
    out.value.reserve(value.size() - 2);
    bool escaped = false;
    for (size_t i = 1; i + 1 < value.size(); ++i) {
        const unsigned char ch = static_cast<unsigned char>(value[i]);
        if (escaped) {
            out.value.push_back(static_cast<char>(ch));
            escaped = false;
        } else if (ch == '\\') {
            escaped = true;
        } else {
            if (ch < 0x20 || ch == 0x7f) {
                out.value_valid = false;
                return out;
            }
            out.value.push_back(static_cast<char>(ch));
        }
    }
    if (escaped) out.value_valid = false;
    return out;
}

void parse_numeric_directive(std::optional<uint64_t>& destination, bool& seen, bool& conflict,
                             bool& invalid, const ParsedDirective& directive) {
    if (!directive.has_value || !directive.value_valid) {
        invalid = true;
        return;
    }
    const auto parsed = parse_delta_seconds(directive.value);
    if (!parsed) {
        invalid = true;
        return;
    }
    if (seen) {
        if (!destination || *destination != *parsed) conflict = true;
        return;
    }
    destination = *parsed;
    seen = true;
}

}  // namespace

std::optional<uint64_t> parse_delta_seconds(std::string_view value) {
    value = trim_ows(value);
    if (value.empty()) return std::nullopt;

    uint64_t result = 0;
    bool saturated = false;
    constexpr uint64_t kMax = std::numeric_limits<uint64_t>::max();
    for (const char raw : value) {
        if (raw < '0' || raw > '9') return std::nullopt;
        if (saturated) continue;
        const uint64_t digit = static_cast<uint64_t>(raw - '0');
        if (result > (kMax - digit) / 10) {
            result = kMax;
            saturated = true;
        } else {
            result = result * 10 + digit;
        }
    }
    return result;
}

CacheControl parse_cache_control(const HeaderList& headers) {
    CacheControl out;
    bool max_age_seen = false;
    bool stale_if_error_seen = false;
    for (const std::string_view field : headers.get_all("cache-control")) {
        for (const std::string_view raw : split_directives(field)) {
            const ParsedDirective directive = parse_directive(raw);
            if (directive.name.empty()) continue;
            if (ascii_iequals(directive.name, "no-store")) {
                out.no_store = true;
            } else if (ascii_iequals(directive.name, "no-cache")) {
                out.no_cache = true;
            } else if (ascii_iequals(directive.name, "must-revalidate")) {
                out.must_revalidate = true;
            } else if (ascii_iequals(directive.name, "private")) {
                out.is_private = true;
            } else if (ascii_iequals(directive.name, "max-age")) {
                parse_numeric_directive(out.max_age, max_age_seen, out.conflicting_max_age,
                                        out.invalid, directive);
            } else if (ascii_iequals(directive.name, "stale-if-error")) {
                bool ignored_conflict = false;
                parse_numeric_directive(out.stale_if_error, stale_if_error_seen, ignored_conflict,
                                        out.invalid, directive);
            }
        }
    }
    return out;
}

} /* namespace kathttp3 */
