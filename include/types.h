// include/types.h
#ifndef TYPES_H
#define TYPES_H

// Active Directory / LDAP User representation
typedef struct {
    char *username;   // sAMAccountName or uid
    char *cn;         // Common Name
    char *dn;         // Distinguished Name
    char *mail;       // Email address
    char *memberOf;   // Group memberships (comma-separated)
    
    // Permission flags (1 = has permission, 0 = no permission)
    struct {
        int isAdmin;           // Domain Admin, Enterprise Admin, etc.
        int canResetPasswords; // Reset password permission
        int canModifyACLs;     // WriteDACL permission
        int canDelegateAuth;   // Can delegate authentication
        int hasServiceAcct;    // Service account privileges
        int isPrivileged;      // Any privileged group membership
        int canReadSecrets;    // Can read sensitive attributes
        int canWriteSecrets;   // Can write sensitive attributes
    } perms;
    
    int risk;              // Risk score (0-100)
    char *mitre_attack;    // Primary MITRE ATT&CK technique ID
    char *mitre_name;      // Human-readable MITRE technique name
} ADUser;

// Free a single ADUser's dynamically allocated fields
void ADUser_free(ADUser *user);

// Free an array of ADUser structs and the array itself
void ADUser_list_free(ADUser *users, int count);

#endif