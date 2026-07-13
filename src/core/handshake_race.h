#ifndef KATHTTP3_HANDSHAKE_RACE_H
#define KATHTTP3_HANDSHAKE_RACE_H

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace kathttp3 {

constexpr size_t kNoHandshakeRaceWinner = std::numeric_limits<size_t>::max();

/* Returns the candidate whose 1-RTT receive key became available first.
 * A value of zero represents a candidate that has not reached that state.
 * Ties are resolved by the stable candidate index only; the event-loop's
 * polling/callback order never changes an already-recorded timestamp. */
inline size_t select_earliest_1rtt_candidate(const std::vector<uint64_t>& ready_at_ns) {
    size_t winner = kNoHandshakeRaceWinner;
    uint64_t earliest = 0;
    for (size_t i = 0; i < ready_at_ns.size(); ++i) {
        const uint64_t ready_at = ready_at_ns[i];
        if (ready_at == 0) continue;
        if (winner == kNoHandshakeRaceWinner || ready_at < earliest) {
            winner = i;
            earliest = ready_at;
        }
    }
    return winner;
}

}  // namespace kathttp3

#endif  // KATHTTP3_HANDSHAKE_RACE_H
