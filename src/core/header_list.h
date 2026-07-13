#ifndef KATHTTP3_HEADER_LIST_H
#define KATHTTP3_HEADER_LIST_H

#include <string>
#include <vector>

namespace kathttp3 {

/* Preserves order and allows duplicate header names (e.g. set-cookie). */
struct Header {
    std::string name;
    std::string value;
};

class HeaderList {
   public:
    void add(std::string name, std::string value) {
        headers_.emplace_back(Header{std::move(name), std::move(value)});
    }

    const std::vector<Header>& all() const {
        return headers_;
    }
    const std::vector<Header>& list() const {
        return headers_;
    }
    size_t size() const {
        return headers_.size();
    }

    void clear() {
        headers_.clear();
    }

    /* First value whose name matches (case-insensitive), or "" if absent. */
    std::string_view get(std::string_view name) const;

    /* All values for a name. */
    std::vector<std::string_view> get_all(std::string_view name) const;

    std::vector<const char*> name_pointers() const;
    std::vector<const char*> value_pointers() const;

   private:
    std::vector<Header> headers_;
};

} /* namespace kathttp3 */

#endif /* KATHTTP3_HEADER_LIST_H */
