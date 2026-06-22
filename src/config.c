#include <stdlib.h>
#include <string.h>
#include "config.h"

static char *get_env_or_default(const char *env_name, const char *default_val) {
    char *val = getenv(env_name);
    if (val && strlen(val) > 0) {
        return strdup(val);
    }
    return strdup(default_val);
}

int load_env_config(Config *config) {
    config->ldap_uri = get_env_or_default(ENV_LDAP_URI, DEFAULT_LDAP_URI);
    config->bind_dn  = get_env_or_default(ENV_BIND_DN, DEFAULT_BIND_DN);
    config->bind_pw  = get_env_or_default(ENV_BIND_PW, DEFAULT_BIND_PW);
    config->base_dn  = get_env_or_default(ENV_BASE_DN, DEFAULT_BASE_DN);

    return 0;
}

void Config_free(Config *config) {
    free(config->ldap_uri);
    free(config->bind_dn);
    free(config->bind_pw);
    free(config->base_dn);
    config->ldap_uri = NULL;
    config->bind_dn = NULL;
    config->bind_pw = NULL;
    config->base_dn = NULL;
}