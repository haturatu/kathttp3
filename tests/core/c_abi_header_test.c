#include "kathttp3.h"

static void qlog_sink(void* userdata, uint32_t flags, const uint8_t* data, size_t len) {
    (void)userdata;
    (void)flags;
    (void)data;
    (void)len;
}

int main(void) {
    if (KATHTTP3_EVENT_NONE != 0) return 1;
    kathttp3_client_config config;
    kathttp3_client_config_init(&config);
    config.qlog_sink_cb = qlog_sink;
    return config.struct_size >= sizeof(config) && config.enable_http_cache == 0 &&
                   config.http_cache_max_entries == 128 &&
                   config.http_cache_max_bytes == 32u * 1024u * 1024u &&
                   config.http_cache_max_entry_bytes == 4u * 1024u * 1024u &&
                   config.abi_version == KATHTTP3_ABI_VERSION_CURRENT
               ? 0
               : 1;
}
