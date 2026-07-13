#include "header_list.h"

#include <algorithm>

namespace kathttp3 {

static bool ieq(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

std::string_view HeaderList::get(std::string_view name) const {
    for (const auto& h : headers_) {
        if (ieq(h.name, name)) return h.value;
    }
    return "";
}

std::vector<std::string_view> HeaderList::get_all(std::string_view name) const {
    std::vector<std::string_view> out;
    for (const auto& h : headers_) {
        if (ieq(h.name, name)) out.push_back(h.value);
    }
    return out;
}

std::vector<const char*> HeaderList::name_pointers() const {
    std::vector<const char*> out;
    out.reserve(headers_.size());
    for (const auto& h : headers_) out.push_back(h.name.c_str());
    return out;
}

std::vector<const char*> HeaderList::value_pointers() const {
    std::vector<const char*> out;
    out.reserve(headers_.size());
    for (const auto& h : headers_) out.push_back(h.value.c_str());
    return out;
}

} /* namespace kathttp3 */
