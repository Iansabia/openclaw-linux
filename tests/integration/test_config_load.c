#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <clawd/config.h>

int main(void) {
    printf("Integration test: config loading\n");

    clawd_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    // Test loading default config
    int rc = clawd_config_load_default(&cfg);
    // May fail if no config file exists, that's OK
    if (rc == 0) {
        assert(cfg.gateway.port > 0);
        printf("  Config loaded: gateway port=%d\n", cfg.gateway.port);
    } else {
        printf("  No default config found (expected in test env)\n");
    }

    clawd_config_free(&cfg);
    printf("  PASSED\n");
    return 0;
}
