#include <stddef.h>
#include <string.h>

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
    kathttp3_client_config_init_size(&config, sizeof(config));
    config.qlog_sink_cb = qlog_sink;
    if (config.struct_size != sizeof(config) || config.enable_http_cache != 0 ||
        config.http_cache_max_entries != 128 ||
        config.http_cache_max_bytes != 32u * 1024u * 1024u ||
        config.http_cache_max_entry_bytes != 4u * 1024u * 1024u ||
        config.abi_version != KATHTTP3_ABI_VERSION_CURRENT)
        return 1;

    union {
        max_align_t alignment;
        unsigned char bytes[KATHTTP3_CLIENT_OPTIONS_LEGACY_SIZE + 16];
    } legacy_storage;
    memset(legacy_storage.bytes, 0xa5, sizeof(legacy_storage.bytes));
    kathttp3_client_options_init((kathttp3_client_options*)legacy_storage.bytes);
    for (size_t i = KATHTTP3_CLIENT_OPTIONS_LEGACY_SIZE; i < sizeof(legacy_storage.bytes); ++i)
        if (legacy_storage.bytes[i] != 0xa5) return 1;

    return 0;
}
