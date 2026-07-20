#pragma once

#include <condition_variable>
#include <mutex>
#include <vector>

#include "dns.h"

namespace kathttp3 {

struct DnsWaitState {
    std::mutex mutex;
    std::condition_variable changed;
    bool complete = false;
    std::vector<ResolvedEndpoint> endpoints;
};

}  // namespace kathttp3
