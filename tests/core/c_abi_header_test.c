#include "kathttp3.h"

int main(void) {
    if (KATHTTP3_EVENT_NONE != 0) return 1;
    kathttp3_client_config config;
    kathttp3_client_config_init(&config);
    return config.struct_size >= sizeof(config) &&
                   config.abi_version == KATHTTP3_ABI_VERSION_CURRENT
               ? 0
               : 1;
}
