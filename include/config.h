#ifndef CONFIG_H
#define CONFIG_H

// Configuration structure for LDAP connection
typedef struct {
    char *ldap_uri;  // LDAP server URI
    char *bind_dn;   // Bind DN for authentication
    char *bind_pw;   // Bind password
    char *base_dn;   // Base DN for searches
} Config;

// Environment variable names
#define ENV_LDAP_URI "ACLGUARD_LDAP_URI"
#define ENV_BIND_DN  "ACLGUARD_BIND_DN"
#define ENV_BIND_PW  "ACLGUARD_BIND_PW"
#define ENV_BASE_DN  "ACLGUARD_BASE_DN"

// Default values
#define DEFAULT_LDAP_URI ""
#define DEFAULT_BIND_DN  ""
#define DEFAULT_BIND_PW  ""
#define DEFAULT_BASE_DN  ""

// Function declarations
int load_env_config(Config *config);

#endif // CONFIG_H
