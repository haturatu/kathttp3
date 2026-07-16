#ifndef KATHTTP3_NETWORK_CHANGE_H
#define KATHTTP3_NETWORK_CHANGE_H

#include <cstdint>

namespace kathttp3 {

enum class NetworkChangeAction { None = 0, Reconnect, Migrate };

struct NetworkHandle {
    uint64_t value = 0;
};

struct NetworkChangeRequest {
    uint64_t generation = 0;
    NetworkHandle network;
};

inline NetworkChangeAction network_change_action(NetworkChangeRequest requested,
                                                 uint64_t applied_generation,
                                                 bool handshake_confirmed) {
    if (requested.generation <= applied_generation) return NetworkChangeAction::None;
    if (requested.network.value == 0 || !handshake_confirmed) return NetworkChangeAction::Reconnect;
    return NetworkChangeAction::Migrate;
}

}  // namespace kathttp3

#endif
