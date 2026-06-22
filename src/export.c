#include "export.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

// Helper to safely return a string or "N/A"
static const char* safe_str(const char* s) {
    return (s && strlen(s) > 0) ? s : "N/A";
}

void export_to_csv(const char *filename, ADUser *users, int count) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("[ERROR] fopen failed");
        return;
    }

    fprintf(fp, "Username,CN,Email,Groups,IsAdmin,CanResetPass,CanModifyACL,CanDelegate,HasServiceAcct,CanReadSecrets,CanWriteSecrets,Risk,MITRE_Attack_ID,MITRE_Attack_Name\n");
    for (int i = 0; i < count; i++) {
        fprintf(fp, "%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s\n",
                safe_str(users[i].username),
                safe_str(users[i].cn),
                safe_str(users[i].mail),
                safe_str(users[i].memberOf),
                users[i].perms.isAdmin,
                users[i].perms.canResetPasswords,
                users[i].perms.canModifyACLs,
                users[i].perms.canDelegateAuth,
                users[i].perms.hasServiceAcct,
                users[i].perms.canReadSecrets,
                users[i].perms.canWriteSecrets,
                users[i].risk,
                safe_str(users[i].mitre_attack),
                safe_str(users[i].mitre_name));
    }

    fclose(fp);
    printf("[INFO] Exported %d users to %s (CSV)\n", count, filename);
}

void export_to_json(const char *filename, ADUser *users, int count) {
    struct json_object *jarray = json_object_new_array();

    for (int i = 0; i < count; i++) {
        struct json_object *juser = json_object_new_object();

        json_object_object_add(juser, "username", json_object_new_string(safe_str(users[i].username)));
        json_object_object_add(juser, "cn", json_object_new_string(safe_str(users[i].cn)));
        json_object_object_add(juser, "email", json_object_new_string(safe_str(users[i].mail)));
        json_object_object_add(juser, "groups", json_object_new_string(safe_str(users[i].memberOf)));
        json_object_object_add(juser, "isAdmin", json_object_new_int(users[i].perms.isAdmin));
        json_object_object_add(juser, "canResetPasswords", json_object_new_int(users[i].perms.canResetPasswords));
        json_object_object_add(juser, "canModifyACLs", json_object_new_int(users[i].perms.canModifyACLs));
        json_object_object_add(juser, "canDelegateAuth", json_object_new_int(users[i].perms.canDelegateAuth));
        json_object_object_add(juser, "hasServiceAcct", json_object_new_int(users[i].perms.hasServiceAcct));
        json_object_object_add(juser, "canReadSecrets", json_object_new_int(users[i].perms.canReadSecrets));
        json_object_object_add(juser, "mitre_attack_id", json_object_new_string(safe_str(users[i].mitre_attack)));
        json_object_object_add(juser, "mitre_attack_name", json_object_new_string(safe_str(users[i].mitre_name)));
        json_object_object_add(juser, "canWriteSecrets", json_object_new_int(users[i].perms.canWriteSecrets));
        json_object_object_add(juser, "risk", json_object_new_int(users[i].risk));

        json_object_array_add(jarray, juser);
    }

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("[ERROR] fopen failed");
        json_object_put(jarray);
        return;
    }

    fprintf(fp, "%s\n", json_object_to_json_string_ext(jarray, JSON_C_TO_STRING_PRETTY));
    fclose(fp);

    json_object_put(jarray);

    printf("[INFO] Exported %d users to %s (JSON)\n", count, filename);
}