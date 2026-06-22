// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "config.h"
#include "aclguard_ldap.h"
#include "export.h"
#include "mock.h"
#include "ldap_insights.h"

// Banner function
void print_banner(void) {
    printf("\n");
    printf("                █████╗  ██████╗██╗     \n");
    printf("               ██╔══██╗██╔════╝██║     \n");
    printf("               ███████║██║     ██║     \n");
    printf("               ██╔══██║██║     ██║     \n");
    printf("               ██║  ██║╚██████╗███████╗\n");
    printf("               ╚═╝  ╚═╝ ╚═════╝╚══════╝\n");
    printf("                       ForeverLX\n");
    printf("              Access Control List Guard\n");
    printf("              v%s \"%s\"\n\n", ACLGUARD_VERSION, ACLGUARD_CODENAME);
}

// Function to get risk level description
const char* get_risk_level(int risk) {
    if (risk >= 80) return "🔴 CRITICAL";
    if (risk >= 60) return "🟠 HIGH";
    if (risk >= 40) return "🟡 MEDIUM";
    if (risk >= 20) return "🔵 LOW";
    return "🟢 MINIMAL";
}

// Function to display user permissions
void display_user_permissions(ADUser *user) {
    printf("    Permissions: ");
    int perm_count = 0;
    
    if (user->perms.isAdmin) {
        printf("Admin ");
        perm_count++;
    }
    if (user->perms.canResetPasswords) {
        printf("ResetPass ");
        perm_count++;
    }
    if (user->perms.canModifyACLs) {
        printf("ModifyACL ");
        perm_count++;
    }
    if (user->perms.canDelegateAuth) {
        printf("Delegate ");
        perm_count++;
    }
    if (user->perms.hasServiceAcct) {
        printf("ServiceAcct ");
        perm_count++;
    }
    if (user->perms.canReadSecrets) {
        printf("ReadSecrets ");
        perm_count++;
    }
    if (user->perms.canWriteSecrets) {
        printf("WriteSecrets ");
        perm_count++;
    }
    
    if (perm_count == 0) {
        printf("None");
    }
    printf("\n");
    if (user->mitre_attack) {
        printf("    MITRE ATT&CK: %s — %s\n", user->mitre_attack, user->mitre_name);
    }
}

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s status [--json]\n", prog);
    printf("  %s alerts --recent [--json]\n", prog);
    printf("  %s correlate --attack <name> [--json]\n", prog);
    printf("  %s analyze --incident <latest|id> [--json]\n", prog);
    printf("  %s metrics --throughput|--accuracy|--scale [--json]\n", prog);
    printf("  %s --mock status [--json]\n", prog);
    printf("  %s --mock alerts --recent [--json]\n", prog);
    printf("  %s --mock correlate --attack <name> [--json]\n", prog);
    printf("  %s --mock analyze --incident <latest|id> [--json]\n", prog);
    printf("  %s --mock metrics --throughput|--accuracy|--scale [--json]\n", prog);
    printf("\nLegacy (deprecated):\n");
    printf("  %s [--export-csv [filename]] [--export-json [filename]]\n", prog);
}

static int load_ldap_users(ADUser **users_out, int *count_out, double *scan_seconds_out) {
    Config config = {0};
    if (load_env_config(&config) != 0) {
        fprintf(stderr, "Failed to load configuration from environment.\n");
        Config_free(&config);
        return 1;
    }

    if (!config.ldap_uri || !config.bind_dn || !config.bind_pw || !config.base_dn ||
        strlen(config.ldap_uri) == 0 || strlen(config.bind_dn) == 0 ||
        strlen(config.bind_pw) == 0 || strlen(config.base_dn) == 0) {
        fprintf(stderr, "LDAP configuration missing. Set ACLGUARD_LDAP_URI, ACLGUARD_BIND_DN, ACLGUARD_BIND_PW, ACLGUARD_BASE_DN.\n");
        Config_free(&config);
        return 1;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    ADUser *users = fetch_real_users(&config, count_out);
    clock_gettime(CLOCK_MONOTONIC, &end);
    Config_free(&config);

    if (!users || *count_out == 0) {
        fprintf(stderr, "LDAP connection failed or no users fetched.\n");
        return 1;
    }

    if (scan_seconds_out) {
        double seconds = (double)(end.tv_sec - start.tv_sec);
        seconds += (double)(end.tv_nsec - start.tv_nsec) / 1e9;
        if (seconds < 0.0) seconds = 0.0;
        *scan_seconds_out = seconds;
    }

    *users_out = users;
    return 0;
}

static int handle_legacy(int argc, char *argv[]) {
    print_banner();

    int export_csv = 0;
    int export_json = 0;
    char *csv_filename = "aclguard_users.csv";
    char *json_filename = "aclguard_users.json";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--export-csv") == 0) {
            export_csv = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                csv_filename = argv[++i];
            }
        } else if (strcmp(argv[i], "--export-json") == 0) {
            export_json = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                json_filename = argv[++i];
            }
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    if (export_csv || export_json) {
        fprintf(stderr, "[WARN] Legacy export flags are deprecated and will be removed in a future release.\n");
    }

    int user_count = 0;
    ADUser *users = NULL;
    if (load_ldap_users(&users, &user_count, NULL) != 0) return 1;

    const char *ldap_uri = getenv("ACLGUARD_LDAP_URI");
    printf("Successfully connected to LDAP server: %s\n",
           ldap_uri ? ldap_uri : "(unknown)");
    printf("Users retrieved: %d\n\n", user_count);


    for (int i = 0; i < user_count; i++) {
        printf("═══════════════════════════════════════════════════════════════════════════════════\n");
        printf("User: %s (%s)\n",
               users[i].username ? users[i].username : "N/A",
               users[i].cn ? users[i].cn : "N/A");

        if (users[i].mail) {
            printf("Email: %s\n", users[i].mail);
        }

        if (users[i].memberOf) {
            printf("Groups: %s\n", users[i].memberOf);
        }

        display_user_permissions(&users[i]);
        printf("Risk Score: %d/100 %s\n", users[i].risk, get_risk_level(users[i].risk));
        printf("\n");
    }

    int high_risk_count = 0;
    int admin_count = 0;
    int privileged_count = 0;

    for (int i = 0; i < user_count; i++) {
        if (users[i].risk >= 60) high_risk_count++;
        if (users[i].perms.isAdmin) admin_count++;
        if (users[i].perms.isPrivileged) privileged_count++;
    }

    printf("═══════════════════════════════════════════════════════════════════════════════════\n");
    printf("SECURITY SUMMARY\n");
    printf("═══════════════════════════════════════════════════════════════════════════════════\n");
    printf("Total Users: %d\n", user_count);
    printf("High Risk Users (>=60): %d\n", high_risk_count);
    printf("Admin Users: %d\n", admin_count);
    printf("Privileged Users: %d\n", privileged_count);
    printf("═══════════════════════════════════════════════════════════════════════════════════\n");

    if (export_csv) {
        export_to_csv(csv_filename, users, user_count);
    }

    if (export_json) {
        export_to_json(json_filename, users, user_count);
    }
    ADUser_list_free(users, user_count);
    return 0;
}

int main(int argc, char *argv[]) {
    int mock_mode = 0;
    int json_output = 0;
    int show_help = 0;

    int show_version = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mock") == 0) {
            mock_mode = 1;
        } else if (strcmp(argv[i], "--json") == 0) {
            json_output = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            show_help = 1;
        } else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            show_version = 1;
        }
    }

    int subcmd_index = -1;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            subcmd_index = i;
            break;
        }
    }

    if (show_version) {
        printf("ACLGuard v%s \"%s\"\n", ACLGUARD_VERSION, ACLGUARD_CODENAME);
        return 0;
    }

    if (show_help) {
        print_usage(argv[0]);
        return 0;
    }

    if (subcmd_index == -1) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--export-csv") == 0 || strcmp(argv[i], "--export-json") == 0) {
                return handle_legacy(argc, argv);
            }
        }
        print_usage(argv[0]);
        return 1;
    }

    const char *subcmd = argv[subcmd_index];

    if (strcmp(subcmd, "status") == 0) {
        if (mock_mode) {
            return mock_status(json_output);
        }
        ADUser *users = NULL;
        int count = 0;
        double scan_seconds = 0.0;
        if (load_ldap_users(&users, &count, &scan_seconds) != 0) return 1;
        int rc = ldap_status_output(users, count, json_output);
        ADUser_list_free(users, count);
        return rc;
    }

    if (strcmp(subcmd, "alerts") == 0) {
        int recent = 0;
        for (int i = subcmd_index + 1; i < argc; i++) {
            if (strcmp(argv[i], "--recent") == 0) {
                recent = 1;
            }
        }
        if (!recent) {
            fprintf(stderr, "alerts requires --recent.\n");
            return 1;
        }
        if (mock_mode) return mock_alerts_recent(json_output);
        ADUser *users = NULL;
        int count = 0;
        double scan_seconds = 0.0;
        if (load_ldap_users(&users, &count, &scan_seconds) != 0) return 1;
        int rc = ldap_alerts_recent_output(users, count, json_output);
        ADUser_list_free(users, count);
        return rc;
    }

    if (strcmp(subcmd, "correlate") == 0) {
        const char *attack = NULL;
        for (int i = subcmd_index + 1; i < argc; i++) {
            if (strcmp(argv[i], "--attack") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "correlate requires --attack <name>.\n");
                    return 1;
                }
                attack = argv[i + 1];
                break;
            }
        }
        if (!attack) {
            fprintf(stderr, "correlate requires --attack <name>.\n");
            return 1;
        }
        if (mock_mode) return mock_correlate_attack(attack, json_output);
        ADUser *users = NULL;
        int count = 0;
        double scan_seconds = 0.0;
        if (load_ldap_users(&users, &count, &scan_seconds) != 0) return 1;
        int rc = ldap_correlate_attack_output(users, count, attack, json_output);
        ADUser_list_free(users, count);
        return rc;
    }

    if (strcmp(subcmd, "analyze") == 0) {
        const char *incident = NULL;
        for (int i = subcmd_index + 1; i < argc; i++) {
            if (strcmp(argv[i], "--incident") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "analyze requires --incident <latest|id>.\n");
                    return 1;
                }
                incident = argv[i + 1];
                break;
            }
        }
        if (!incident) {
            fprintf(stderr, "analyze requires --incident <latest|id>.\n");
            return 1;
        }
        if (mock_mode) return mock_analyze_incident(incident, json_output);
        ADUser *users = NULL;
        int count = 0;
        double scan_seconds = 0.0;
        if (load_ldap_users(&users, &count, &scan_seconds) != 0) return 1;
        int rc = ldap_analyze_incident_output(users, count, incident, json_output);
        ADUser_list_free(users, count);
        return rc;
    }

    if (strcmp(subcmd, "metrics") == 0) {
        const char *metric = NULL;
        for (int i = subcmd_index + 1; i < argc; i++) {
            if (strcmp(argv[i], "--throughput") == 0) {
                metric = "throughput";
            } else if (strcmp(argv[i], "--accuracy") == 0) {
                metric = "accuracy";
            } else if (strcmp(argv[i], "--scale") == 0) {
                metric = "scale";
            }
        }
        if (!metric) {
            fprintf(stderr, "metrics requires one of --throughput, --accuracy, or --scale.\n");
            return 1;
        }
        if (mock_mode) return mock_metrics(metric, json_output);
        ADUser *users = NULL;
        int count = 0;
        double scan_seconds = 0.0;
        if (load_ldap_users(&users, &count, &scan_seconds) != 0) return 1;
        int rc = ldap_metrics_output(users, count, scan_seconds, metric, json_output);
        ADUser_list_free(users, count);
        return rc;
    }

    fprintf(stderr, "Unknown command: %s\n", subcmd);
    print_usage(argv[0]);
    return 1;
}
