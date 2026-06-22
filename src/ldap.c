#include "aclguard_ldap.h"
#include "error_handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldap.h>

// Function to analyze user permissions based on group memberships
void analyze_user_permissions(ADUser *user) {
    // Initialize all permissions to 0
    user->perms.isAdmin = 0;
    user->perms.canResetPasswords = 0;
    user->perms.canModifyACLs = 0;
    user->perms.canDelegateAuth = 0;
    user->perms.hasServiceAcct = 0;
    user->perms.isPrivileged = 0;
    user->perms.canReadSecrets = 0;
    user->perms.canWriteSecrets = 0;
    user->risk = 0;
    
    if (!user->memberOf) return;
    
    char *groups = strdup(user->memberOf);
    char *group = strtok(groups, ",");
    
    while (group != NULL) {
        // Remove leading/trailing whitespace
        while (*group == ' ' || *group == '\t') group++;
        char *end = group + strlen(group) - 1;
        while (end > group && (*end == ' ' || *end == '\t')) end--;
        *(end + 1) = '\0';
        
        // Check for high-risk group memberships
        if (strstr(group, "Domain Admins") || 
            strstr(group, "Enterprise Admins") ||
            strstr(group, "Schema Admins") ||
            strstr(group, "Administrators") ||
            strstr(group, "Group Policy Creator Owners") ||
            strstr(group, "Domain Controllers") ||
            strstr(group, "Administrator")) {
            user->perms.isAdmin = 1;
            user->perms.isPrivileged = 1;
            user->risk += 40; // High risk for admin groups
        }
        
        if (strstr(group, "Account Operators") ||
            strstr(group, "Help Desk") ||
            strstr(group, "Password Reset")) {
            user->perms.canResetPasswords = 1;
            user->perms.isPrivileged = 1;
            user->risk += 25; // Medium-high risk for password reset
        }
        
        if (strstr(group, "Backup Operators") ||
            strstr(group, "Server Operators") ||
            strstr(group, "Print Operators") ||
            strstr(group, "Remote Desktop Users") ||
            strstr(group, "Power Users")) {
            user->perms.canModifyACLs = 1;
            user->perms.isPrivileged = 1;
            user->risk += 20; // Medium risk for ACL modification
        }
        
        if (strstr(group, "Service") ||
            strstr(group, "SQL") ||
            strstr(group, "IIS") ||
            strstr(group, "Exchange")) {
            user->perms.hasServiceAcct = 1;
            user->risk += 15; // Medium risk for service accounts
        }
        
        if (strstr(group, "Delegation") ||
            strstr(group, "Trusted")) {
            user->perms.canDelegateAuth = 1;
            user->risk += 30; // High risk for delegation
        }
        
        if (strstr(group, "Read") && strstr(group, "Secret")) {
            user->perms.canReadSecrets = 1;
            user->risk += 20; // Medium risk for reading secrets
        }
        
        if (strstr(group, "Write") && strstr(group, "Secret")) {
            user->perms.canWriteSecrets = 1;
            user->risk += 35; // High risk for writing secrets
        }
        
        group = strtok(NULL, ",");
    }
    
    free(groups);
    
    // Cap risk score at 100
    if (user->risk > 100) user->risk = 100;

    // Map highest-risk permission to MITRE ATT&CK technique
    user->mitre_attack = NULL;
    user->mitre_name = NULL;
    if (user->perms.isAdmin) {
        user->mitre_attack = "T1078.002";
        user->mitre_name = "Valid Accounts: Domain Accounts";
    } else if (user->perms.canWriteSecrets) {
        user->mitre_attack = "T1098";
        user->mitre_name = "Account Manipulation";
    } else if (user->perms.canDelegateAuth) {
        user->mitre_attack = "T1484.001";
        user->mitre_name = "Group Policy Modification";
    } else if (user->perms.canResetPasswords) {
        user->mitre_attack = "T1098";
        user->mitre_name = "Account Manipulation";
    } else if (user->perms.canReadSecrets) {
        user->mitre_attack = "T1552";
        user->mitre_name = "Unsecured Credentials";
    } else if (user->perms.canModifyACLs) {
        user->mitre_attack = "T1484";
        user->mitre_name = "Domain Policy Modification";
    } else if (user->perms.hasServiceAcct) {
        user->mitre_attack = "T1558.003";
        user->mitre_name = "Kerberoasting";
    } else if (user->perms.isPrivileged) {
        user->mitre_attack = "T1078.002";
        user->mitre_name = "Valid Accounts: Domain Accounts";
    }
}

ADUser *fetch_real_users(const Config *config, int *count_out) {
    LDAP *ld = NULL;
    LDAPMessage *result = NULL, *entry = NULL;
    char *attrs[] = {"cn", "mail", "sAMAccountName", "uid", "memberOf", NULL};
    int rc;

    *count_out = 0;

    // 1. Initialize connection
    rc = ldap_initialize(&ld, config->ldap_uri);
    if (rc != LDAP_SUCCESS) {
        log_error("LDAP initialization failed: %s", ldap_err2string(rc));
        return NULL;
    }

    // 2. Prepare credentials
    struct berval cred;
    cred.bv_val = config->bind_pw;
    cred.bv_len = strlen(config->bind_pw);

    // 3. Simple bind (via SASL API)
    rc = ldap_sasl_bind_s(ld,
                          config->bind_dn,
                          LDAP_SASL_SIMPLE,
                          &cred,
                          NULL,
                          NULL,
                          NULL);
    if (rc != LDAP_SUCCESS) {
        log_error("LDAP bind failed: %s", ldap_err2string(rc));
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }

    // 4. Perform search - try multiple approaches for compatibility
    // First try: Search for users with person objectClass (OpenLDAP)
    rc = ldap_search_ext_s(ld,
                           config->base_dn,
                           LDAP_SCOPE_SUBTREE,
                           "(objectClass=person)",
                           attrs,
                           0,
                           NULL,
                           NULL,
                           NULL,
                           LDAP_NO_LIMIT,
                           &result);
    
    if (rc != LDAP_SUCCESS) {
        // Fallback 1: Retry same base DN with user objectClass (AD-style)
        rc = ldap_search_ext_s(ld,
                               config->base_dn,
                               LDAP_SCOPE_SUBTREE,
                               "(objectClass=user)",
                               attrs,
                               0,
                               NULL,
                               NULL,
                               NULL,
                               LDAP_NO_LIMIT,
                               &result);
        
        if (rc != LDAP_SUCCESS) {
            // Fallback 2: Try base DN with BASE scope
            rc = ldap_search_ext_s(ld,
                                   config->base_dn,
                                   LDAP_SCOPE_BASE,
                                   "(objectClass=*)",
                                   attrs,
                                   0,
                                   NULL,
                                   NULL,
                                   NULL,
                                   LDAP_NO_LIMIT,
                                   &result);
            
            if (rc != LDAP_SUCCESS) {
                log_error("LDAP search failed: %s", ldap_err2string(rc));
                ldap_unbind_ext_s(ld, NULL, NULL);
                return NULL;
            }
        }
    }

    // 5. Count results
    int num_entries = ldap_count_entries(ld, result);
    if (num_entries <= 0) {
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }

    ADUser *users = calloc(num_entries, sizeof(ADUser));
    if (!users) {
        log_error("Memory allocation failed for ADUser list.");
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, NULL, NULL);
        return NULL;
    }

    // 6. Extract CN and mail attributes
    int i = 0;
    for (entry = ldap_first_entry(ld, result);
         entry != NULL && i < num_entries;
         entry = ldap_next_entry(ld, entry), i++) {

        char *dn = ldap_get_dn(ld, entry);
        if (dn) {
            users[i].dn = strdup(dn);
            ldap_memfree(dn);
        }

        BerElement *ber = NULL;
        char *attr;
        struct berval **vals;

        for (attr = ldap_first_attribute(ld, entry, &ber);
             attr != NULL;
             attr = ldap_next_attribute(ld, entry, ber)) {

            vals = ldap_get_values_len(ld, entry, attr);
            if (vals && vals[0]) {
                if (strcmp(attr, "cn") == 0) {
                    users[i].cn = strndup(vals[0]->bv_val, vals[0]->bv_len);
                } else if (strcmp(attr, "mail") == 0) {
                    users[i].mail = strndup(vals[0]->bv_val, vals[0]->bv_len);
                } else if (strcmp(attr, "sAMAccountName") == 0 || strcmp(attr, "uid") == 0) {
                    // Use sAMAccountName for AD or uid for OpenLDAP
                    if (!users[i].username) {  // Only set if not already set
                        users[i].username = strndup(vals[0]->bv_val, vals[0]->bv_len);
                    }
                } else if (strcmp(attr, "memberOf") == 0) {
                    // Handle multiple group memberships
                    if (!users[i].memberOf) {
                        users[i].memberOf = strndup(vals[0]->bv_val, vals[0]->bv_len);
                    } else {
                        // Append additional groups
                        char *temp = malloc(strlen(users[i].memberOf) + vals[0]->bv_len + 2);
                        sprintf(temp, "%s,%s", users[i].memberOf, vals[0]->bv_val);
                        free(users[i].memberOf);
                        users[i].memberOf = temp;
                    }
                }
            }
            if (vals) {
                ldap_value_free_len(vals);
            }
            ldap_memfree(attr);
        }

        if (ber) {
            ber_free(ber, 0);
        }
        
        // Analyze user permissions based on group memberships
        analyze_user_permissions(&users[i]);
    }

    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, NULL, NULL);

    *count_out = num_entries;
    return users;
}