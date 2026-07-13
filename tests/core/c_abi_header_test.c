#include "kathttp.h"

int main(void) {
    kathttp_client_config config;
    kathttp_client_config_init(&config);
    return config.struct_size >= sizeof(config) && config.abi_version == KATHTTP_ABI_VERSION_CURRENT
               ? 0
               : 1;
}
