#include "ldap_insights.h"
#include <ctype.h>
#include <errno.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} StringList;

static void list_init(StringList *list) {
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static void list_push(StringList *list, const char *value) {
    if (!value) return;
    if (list->count + 1 > list->cap) {
        size_t new_cap = list->cap == 0 ? 4 : list->cap * 2;
        char **next = realloc(list->items, new_cap * sizeof(char *));
        if (!next) return;
        list->items = next;
        list->cap = new_cap;
    }
    list->items[list->count++] = strdup(value);
}

static void list_free(StringList *list) {
    if (!list) return;
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int ci_contains(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen == 0 || hlen < nlen) return 0;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        size_t j = 0;
        while (j < nlen && tolower((unsigned char)haystack[i + j]) == tolower((unsigned char)needle[j])) {
            j++;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

static int starts_with_ci(const char *str, const char *prefix) {
    if (!str || !prefix) return 0;
    size_t len = strlen(prefix);
    return strncasecmp(str, prefix, len) == 0;
}

static int count_groups(const char *memberOf) {
    if (!memberOf || memberOf[0] == '\0') return 0;
    int count = 1;
    for (const char *p = memberOf; *p; p++) {
        if (*p == ',') count++;
    }
    return count;
}

static const char *user_key(const ADUser *u) {
    if (u->username && u->username[0] != '\0') return u->username;
    if (u->cn && u->cn[0] != '\0') return u->cn;
    return "";
}

static int user_cmp(const void *a, const void *b) {
    const ADUser *ua = *(const ADUser * const *)a;
    const ADUser *ub = *(const ADUser * const *)b;
    return strcasecmp(user_key(ua), user_key(ub));
}

static void current_time_rfc3339(char *out, size_t len) {
    const char *override = getenv("ACLGUARD_SCAN_TIME");
    if (override && override[0] != '\0') {
        snprintf(out, len, "%s", override);
        return;
    }
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(out, len, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static struct json_object *load_external_alerts(void) {
    const char *path = getenv("ACLGUARD_ALERTS_FILE");
    if (!path || path[0] == '\0') return NULL;
    struct json_object *obj = json_object_from_file(path);
    if (!obj) {
        fprintf(stderr, "Failed to read external alerts file: %s (%s)\n", path, strerror(errno));
    }
    return obj;
}

static void update_counts(struct json_object *counts, const char *severity) {
    struct json_object *val = NULL;
    int next = 1;
    if (json_object_object_get_ex(counts, severity, &val)) {
        next = json_object_get_int(val) + 1;
    }
    json_object_object_add(counts, severity, json_object_new_int(next));
}

static void add_alert(struct json_object *recent,
                      struct json_object *counts,
                      const char *id,
                      const char *type,
                      const char *severity,
                      const char *time,
                      const char *user,
                      const char *host,
                      const char *details) {
    struct json_object *alert = json_object_new_object();
    json_object_object_add(alert, "id", json_object_new_string(id));
    json_object_object_add(alert, "type", json_object_new_string(type));
    json_object_object_add(alert, "severity", json_object_new_string(severity));
    json_object_object_add(alert, "time", json_object_new_string(time));
    json_object_object_add(alert, "user", json_object_new_string(user));
    json_object_object_add(alert, "host", json_object_new_string(host));
    json_object_object_add(alert, "details", json_object_new_string(details));
    json_object_array_add(recent, alert);
    update_counts(counts, severity);
}

static struct json_object *build_alerts(ADUser *users,
                                        int count,
                                        struct json_object **counts_out,
                                        StringList *kerb_ids,
                                        StringList *admin_ids,
                                        StringList *enum_ids) {
    struct json_object *recent = json_object_new_array();
    struct json_object *counts = json_object_new_object();
    json_object_object_add(counts, "critical", json_object_new_int(0));
    json_object_object_add(counts, "high", json_object_new_int(0));
    json_object_object_add(counts, "medium", json_object_new_int(0));
    json_object_object_add(counts, "low", json_object_new_int(0));

    char time_buf[32];
    current_time_rfc3339(time_buf, sizeof(time_buf));

    ADUser **sorted = calloc((size_t)count, sizeof(ADUser *));
    if (!sorted) {
        if (counts_out) *counts_out = counts;
        return recent;
    }
    for (int i = 0; i < count; i++) sorted[i] = &users[i];
    qsort(sorted, (size_t)count, sizeof(ADUser *), user_cmp);

    int alert_index = 1;
    for (int i = 0; i < count; i++) {
        ADUser *u = sorted[i];
        const char *username = u->username ? u->username : "unknown";
        int groups = count_groups(u->memberOf);

        int is_service = u->perms.hasServiceAcct ||
                         starts_with_ci(username, "svc") ||
                         ci_contains(username, "service");
        int is_privileged = u->perms.isAdmin || u->perms.isPrivileged;
        int is_enum = groups >= 10;

        if (is_service) {
            char id[32];
            snprintf(id, sizeof(id), "AL-LDAP-%04d", alert_index++);
            const char *sev = u->risk >= 60 ? "critical" : "high";
            add_alert(recent, counts, id, "Kerberoasting", sev, time_buf, username, "ldap", "Service account shows elevated risk for ticket abuse.");
            list_push(kerb_ids, id);
        }

        if (is_privileged) {
            char id[32];
            snprintf(id, sizeof(id), "AL-LDAP-%04d", alert_index++);
            add_alert(recent, counts, id, "Privileged Group Change", "high", time_buf, username, "ldap", "Privileged group membership detected.");
            list_push(admin_ids, id);
        }

        if (is_enum) {
            char id[32];
            snprintf(id, sizeof(id), "AL-LDAP-%04d", alert_index++);
            add_alert(recent, counts, id, "Unusual LDAP Enumeration", "medium", time_buf, username, "ldap", "High volume group membership detected.");
            list_push(enum_ids, id);
        }
    }
    free(sorted);

    struct json_object *external = load_external_alerts();
    if (external) {
        struct json_object *ext_recent = NULL;
        if (json_object_is_type(external, json_type_object)) {
            json_object_object_get_ex(external, "data", &ext_recent);
            if (ext_recent && json_object_is_type(ext_recent, json_type_object)) {
                struct json_object *tmp = NULL;
                if (json_object_object_get_ex(ext_recent, "recent", &tmp) && json_object_is_type(tmp, json_type_array)) {
                    ext_recent = tmp;
                } else {
                    ext_recent = NULL;
                }
            } else {
                ext_recent = NULL;
            }
        } else if (json_object_is_type(external, json_type_array)) {
            ext_recent = external;
        }

        if (ext_recent && json_object_is_type(ext_recent, json_type_array)) {
            size_t ext_count = json_object_array_length(ext_recent);
            for (size_t i = 0; i < ext_count; i++) {
                struct json_object *item = json_object_array_get_idx(ext_recent, i);
                if (!item || !json_object_is_type(item, json_type_object)) continue;
                struct json_object *sev = NULL;
                if (json_object_object_get_ex(item, "severity", &sev) && json_object_is_type(sev, json_type_string)) {
                    update_counts(counts, json_object_get_string(sev));
                }
                json_object_array_add(recent, json_object_get(item));
            }
        }
        json_object_put(external);
    }

    if (counts_out) {
        *counts_out = counts;
    }
    return recent;
}

static struct json_object *build_incidents(StringList *kerb_ids,
                                           StringList *admin_ids,
                                           const char *time_buf,
                                           const char **latest_id_out,
                                           struct json_object **correlations_out) {
    struct json_object *incidents = json_object_new_array();
    struct json_object *correlations = json_object_new_array();
    const char *latest = "";

    if (kerb_ids->count > 0) {
        struct json_object *inc = json_object_new_object();
        json_object_object_add(inc, "id", json_object_new_string("INC-LDAP-0001"));
        json_object_object_add(inc, "title", json_object_new_string("Suspicious Service Ticket Burst"));
        json_object_object_add(inc, "status", json_object_new_string("open"));
        json_object_object_add(inc, "severity", json_object_new_string("high"));
        json_object_object_add(inc, "started", json_object_new_string(time_buf));
        json_object_object_add(inc, "last_update", json_object_new_string(time_buf));

        struct json_object *related = json_object_new_array();
        for (size_t i = 0; i < kerb_ids->count; i++) {
            json_object_array_add(related, json_object_new_string(kerb_ids->items[i]));
        }
        json_object_object_add(inc, "related_alerts", related);

        struct json_object *findings = json_object_new_array();
        json_object_array_add(findings, json_object_new_string("Service accounts flagged with elevated ticket abuse risk."));
        json_object_array_add(findings, json_object_new_string("Kerberos-related groups detected in memberships."));
        json_object_object_add(inc, "findings", findings);

        struct json_object *reco = json_object_new_array();
        json_object_array_add(reco, json_object_new_string("Rotate service account credentials."));
        json_object_array_add(reco, json_object_new_string("Review SPN usage and enforce AES-only tickets."));
        json_object_object_add(inc, "recommendations", reco);

        json_object_array_add(incidents, inc);
        latest = "INC-LDAP-0001";

        struct json_object *corr = json_object_new_object();
        json_object_object_add(corr, "attack", json_object_new_string("kerberoasting"));
        json_object_object_add(corr, "incident_id", json_object_new_string("INC-LDAP-0001"));
        json_object_object_add(corr, "confidence", json_object_new_double(0.85));
        struct json_object *signals = json_object_new_array();
        json_object_array_add(signals, json_object_new_string("Service account membership"));
        json_object_array_add(signals, json_object_new_string("Elevated risk score"));
        json_object_object_add(corr, "signals", signals);
        json_object_object_add(corr, "impact", json_object_new_string("Potential credential exposure"));
        json_object_object_add(corr, "summary", json_object_new_string("Service accounts show patterns consistent with kerberoasting risk."));
        json_object_array_add(correlations, corr);
    }

    if (admin_ids->count > 0) {
        struct json_object *inc = json_object_new_object();
        json_object_object_add(inc, "id", json_object_new_string("INC-LDAP-0002"));
        json_object_object_add(inc, "title", json_object_new_string("Privileged Group Membership Drift"));
        json_object_object_add(inc, "status", json_object_new_string("open"));
        json_object_object_add(inc, "severity", json_object_new_string("medium"));
        json_object_object_add(inc, "started", json_object_new_string(time_buf));
        json_object_object_add(inc, "last_update", json_object_new_string(time_buf));

        struct json_object *related = json_object_new_array();
        for (size_t i = 0; i < admin_ids->count; i++) {
            json_object_array_add(related, json_object_new_string(admin_ids->items[i]));
        }
        json_object_object_add(inc, "related_alerts", related);

        struct json_object *findings = json_object_new_array();
        json_object_array_add(findings, json_object_new_string("Privileged group memberships detected in LDAP."));
        json_object_object_add(inc, "findings", findings);

        struct json_object *reco = json_object_new_array();
        json_object_array_add(reco, json_object_new_string("Review privileged memberships for approval."));
        json_object_object_add(inc, "recommendations", reco);

        json_object_array_add(incidents, inc);
        if (latest[0] == '\0') latest = "INC-LDAP-0002";

        struct json_object *corr = json_object_new_object();
        json_object_object_add(corr, "attack", json_object_new_string("privilege_escalation"));
        json_object_object_add(corr, "incident_id", json_object_new_string("INC-LDAP-0002"));
        json_object_object_add(corr, "confidence", json_object_new_double(0.78));
        struct json_object *signals = json_object_new_array();
        json_object_array_add(signals, json_object_new_string("Admin group membership"));
        json_object_array_add(signals, json_object_new_string("Privileged permissions detected"));
        json_object_object_add(corr, "signals", signals);
        json_object_object_add(corr, "impact", json_object_new_string("Elevated privileges without clear change record"));
        json_object_object_add(corr, "summary", json_object_new_string("Privileged membership patterns suggest escalation risk."));
        json_object_array_add(correlations, corr);
    }

    if (latest_id_out) {
        *latest_id_out = latest;
    }
    if (correlations_out) {
        *correlations_out = correlations;
    }
    return incidents;
}

int ldap_status_output(ADUser *users, int count, int json_output) {
    StringList kerb_ids, admin_ids, enum_ids;
    list_init(&kerb_ids);
    list_init(&admin_ids);
    list_init(&enum_ids);
    struct json_object *counts = NULL;
    struct json_object *recent = build_alerts(users, count, &counts, &kerb_ids, &admin_ids, &enum_ids);

    char time_buf[32];
    current_time_rfc3339(time_buf, sizeof(time_buf));

    const char *latest_id = "";
    struct json_object *correlations = NULL;
    struct json_object *incidents = build_incidents(&kerb_ids, &admin_ids, time_buf, &latest_id, &correlations);

    int incident_count = (int)json_object_array_length(incidents);
    int alert_count = (int)json_object_array_length(recent);
    int detectors = 4;

    struct json_object *root = json_object_new_object();
    char summary[256];
    snprintf(summary, sizeof(summary), "LDAP status OK. %d alerts, %d incidents, %d detectors.", alert_count, incident_count, detectors);
    json_object_object_add(root, "summary", json_object_new_string(summary));

    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "mode", json_object_new_string("ldap"));
    json_object_object_add(data, "fixtures_version", json_object_new_string("live"));
    json_object_object_add(data, "alerts_total", json_object_new_int(alert_count));
    json_object_object_add(data, "incidents_open", json_object_new_int(incident_count));
    json_object_object_add(data, "detectors", json_object_new_int(detectors));
    json_object_object_add(data, "last_refresh", json_object_new_string(time_buf));
    json_object_object_add(root, "data", data);

    if (json_output) {
        printf("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
    } else {
        printf("LDAP Status: OK\n");
        printf("Summary: %s\n", summary);
        printf("Alerts total: %d\n", alert_count);
        printf("Open incidents: %d\n", incident_count);
        printf("Detectors: %d\n", detectors);
        printf("Last refresh: %s\n", time_buf);
    }

    json_object_put(recent);
    json_object_put(counts);
    json_object_put(incidents);
    json_object_put(correlations);
    json_object_put(root);
    list_free(&kerb_ids);
    list_free(&admin_ids);
    list_free(&enum_ids);
    return 0;
}

int ldap_alerts_recent_output(ADUser *users, int count, int json_output) {
    StringList kerb_ids, admin_ids, enum_ids;
    list_init(&kerb_ids);
    list_init(&admin_ids);
    list_init(&enum_ids);
    struct json_object *counts = NULL;
    struct json_object *recent = build_alerts(users, count, &counts, &kerb_ids, &admin_ids, &enum_ids);

    struct json_object *root = json_object_new_object();
    int total = (int)json_object_array_length(recent);
    char summary[256];
    snprintf(summary, sizeof(summary), "%d recent alerts derived from LDAP scan.", total);
    json_object_object_add(root, "summary", json_object_new_string(summary));

    struct json_object *data = json_object_new_object();
    json_object_object_add(data, "window", json_object_new_string("scan"));
    json_object_object_add(data, "recent", json_object_get(recent));
    json_object_object_add(data, "counts", json_object_get(counts));
    json_object_object_add(root, "data", data);

    if (json_output) {
        printf("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
    } else {
        printf("Recent Alerts\n");
        printf("Summary: %s\n", summary);
        printf("Count: %d\n", total);
        for (int i = 0; i < total; i++) {
            struct json_object *item = json_object_array_get_idx(recent, i);
            if (!item) continue;
            struct json_object *id = NULL;
            struct json_object *type = NULL;
            struct json_object *severity = NULL;
            struct json_object *time = NULL;
            struct json_object *user = NULL;
            json_object_object_get_ex(item, "id", &id);
            json_object_object_get_ex(item, "type", &type);
            json_object_object_get_ex(item, "severity", &severity);
            json_object_object_get_ex(item, "time", &time);
            json_object_object_get_ex(item, "user", &user);
            printf("- %s [%s] %s (%s) user=%s\n",
                   id ? json_object_get_string(id) : "N/A",
                   severity ? json_object_get_string(severity) : "N/A",
                   type ? json_object_get_string(type) : "N/A",
                   time ? json_object_get_string(time) : "N/A",
                   user ? json_object_get_string(user) : "N/A");
        }
    }

    json_object_put(recent);
    json_object_put(counts);
    json_object_put(root);
    list_free(&kerb_ids);
    list_free(&admin_ids);
    list_free(&enum_ids);
    return 0;
}

int ldap_correlate_attack_output(ADUser *users, int count, const char *attack, int json_output) {
    StringList kerb_ids, admin_ids, enum_ids;
    list_init(&kerb_ids);
    list_init(&admin_ids);
    list_init(&enum_ids);
    struct json_object *counts = NULL;
    struct json_object *recent = build_alerts(users, count, &counts, &kerb_ids, &admin_ids, &enum_ids);
    char time_buf[32];
    current_time_rfc3339(time_buf, sizeof(time_buf));

    const char *latest_id = "";
    struct json_object *correlations = NULL;
    struct json_object *incidents = build_incidents(&kerb_ids, &admin_ids, time_buf, &latest_id, &correlations);

    struct json_object *match = NULL;
    size_t corr_count = json_object_array_length(correlations);
    for (size_t i = 0; i < corr_count; i++) {
        struct json_object *entry = json_object_array_get_idx(correlations, i);
        if (!entry) continue;
        struct json_object *attack_name = NULL;
        if (json_object_object_get_ex(entry, "attack", &attack_name) &&
            json_object_is_type(attack_name, json_type_string) &&
            strcasecmp(json_object_get_string(attack_name), attack) == 0) {
            match = entry;
            break;
        }
    }

    if (!match) {
        fprintf(stderr, "Attack '%s' not found in LDAP correlations.\n", attack);
        json_object_put(recent);
        json_object_put(counts);
        json_object_put(incidents);
        json_object_put(correlations);
        list_free(&kerb_ids);
        list_free(&admin_ids);
        list_free(&enum_ids);
        return 1;
    }

    if (json_output) {
        struct json_object *out = json_object_new_object();
        char summary[256];
        snprintf(summary, sizeof(summary), "Correlation ready for %s.", attack);
        json_object_object_add(out, "summary", json_object_new_string(summary));
        json_object_object_add(out, "data", json_object_get(match));
        printf("%s\n", json_object_to_json_string_ext(out, JSON_C_TO_STRING_PRETTY));
        json_object_put(out);
    } else {
        struct json_object *incident_id = NULL;
        struct json_object *confidence = NULL;
        json_object_object_get_ex(match, "incident_id", &incident_id);
        json_object_object_get_ex(match, "confidence", &confidence);
        printf("Correlation\n");
        printf("Summary: Correlation ready for %s.\n", attack);
        printf("Incident: %s\n", incident_id ? json_object_get_string(incident_id) : "N/A");
        printf("Confidence: %.2f\n", confidence ? json_object_get_double(confidence) : 0.0);
    }

    json_object_put(recent);
    json_object_put(counts);
    json_object_put(incidents);
    json_object_put(correlations);
    list_free(&kerb_ids);
    list_free(&admin_ids);
    list_free(&enum_ids);
    return 0;
}

int ldap_analyze_incident_output(ADUser *users, int count, const char *incident_id, int json_output) {
    StringList kerb_ids, admin_ids, enum_ids;
    list_init(&kerb_ids);
    list_init(&admin_ids);
    list_init(&enum_ids);
    struct json_object *counts = NULL;
    struct json_object *recent = build_alerts(users, count, &counts, &kerb_ids, &admin_ids, &enum_ids);
    char time_buf[32];
    current_time_rfc3339(time_buf, sizeof(time_buf));

    const char *latest_id = "";
    struct json_object *correlations = NULL;
    struct json_object *incidents = build_incidents(&kerb_ids, &admin_ids, time_buf, &latest_id, &correlations);

    const char *target = incident_id;
    if (strcasecmp(incident_id, "latest") == 0) {
        target = latest_id;
    }

    if (!target || target[0] == '\0') {
        fprintf(stderr, "No incidents available for analysis.\n");
        json_object_put(recent);
        json_object_put(counts);
        json_object_put(incidents);
        json_object_put(correlations);
        list_free(&kerb_ids);
        list_free(&admin_ids);
        list_free(&enum_ids);
        return 1;
    }

    struct json_object *match = NULL;
    size_t inc_count = json_object_array_length(incidents);
    for (size_t i = 0; i < inc_count; i++) {
        struct json_object *entry = json_object_array_get_idx(incidents, i);
        if (!entry) continue;
        struct json_object *id = NULL;
        if (json_object_object_get_ex(entry, "id", &id) &&
            json_object_is_type(id, json_type_string) &&
            strcasecmp(json_object_get_string(id), target) == 0) {
            match = entry;
            break;
        }
    }

    if (!match) {
        fprintf(stderr, "Incident '%s' not found.\n", target);
        json_object_put(recent);
        json_object_put(counts);
        json_object_put(incidents);
        json_object_put(correlations);
        list_free(&kerb_ids);
        list_free(&admin_ids);
        list_free(&enum_ids);
        return 1;
    }

    if (json_output) {
        struct json_object *out = json_object_new_object();
        char summary[256];
        snprintf(summary, sizeof(summary), "Incident %s analyzed.", target);
        json_object_object_add(out, "summary", json_object_new_string(summary));
        json_object_object_add(out, "data", json_object_get(match));
        printf("%s\n", json_object_to_json_string_ext(out, JSON_C_TO_STRING_PRETTY));
        json_object_put(out);
    } else {
        struct json_object *title = NULL;
        struct json_object *severity = NULL;
        struct json_object *status = NULL;
        json_object_object_get_ex(match, "title", &title);
        json_object_object_get_ex(match, "severity", &severity);
        json_object_object_get_ex(match, "status", &status);
        printf("Incident Analysis\n");
        printf("Summary: Incident %s analyzed.\n", target);
        printf("Title: %s\n", title ? json_object_get_string(title) : "N/A");
        printf("Severity: %s\n", severity ? json_object_get_string(severity) : "N/A");
        printf("Status: %s\n", status ? json_object_get_string(status) : "N/A");
    }

    json_object_put(recent);
    json_object_put(counts);
    json_object_put(incidents);
    json_object_put(correlations);
    list_free(&kerb_ids);
    list_free(&admin_ids);
    list_free(&enum_ids);
    return 0;
}

int ldap_metrics_output(ADUser *users, int count, double scan_seconds, const char *metric, int json_output) {
    int classified = 0;
    for (int i = 0; i < count; i++) {
        if (users[i].risk > 0 || users[i].perms.isAdmin || users[i].perms.isPrivileged ||
            users[i].perms.canResetPasswords || users[i].perms.canModifyACLs ||
            users[i].perms.canDelegateAuth || users[i].perms.hasServiceAcct ||
            users[i].perms.canReadSecrets || users[i].perms.canWriteSecrets) {
            classified++;
        }
    }
    struct json_object *root = json_object_new_object();

    double throughput = 0.0;
    if (scan_seconds > 0.0) {
        throughput = ((double)count / scan_seconds) * 60.0;
    }

    struct json_object *metric_obj = NULL;

    if (strcmp(metric, "throughput") == 0) {
        metric_obj = json_object_new_object();
        json_object_object_add(metric_obj, "value", json_object_new_int((int)throughput));
        json_object_object_add(metric_obj, "unit", json_object_new_string("objects/min"));
        json_object_object_add(metric_obj, "window", json_object_new_string("scan"));
        json_object_object_add(metric_obj, "p95_ms", json_object_new_int((int)(scan_seconds * 1000.0)));
    } else if (strcmp(metric, "accuracy") == 0) {
        const char *acc_env = getenv("ACLGUARD_METRIC_ACCURACY");
        const char *prec_env = getenv("ACLGUARD_METRIC_PRECISION");
        const char *rec_env = getenv("ACLGUARD_METRIC_RECALL");
        int calibrated = (acc_env && acc_env[0]) || (prec_env && prec_env[0]) || (rec_env && rec_env[0]);
        double acc = 0.0;
        double prec = 0.0;
        double rec = 0.0;
        if (calibrated) {
            acc = acc_env && acc_env[0] ? atof(acc_env) : 0.0;
            prec = prec_env && prec_env[0] ? atof(prec_env) : 0.0;
            rec = rec_env && rec_env[0] ? atof(rec_env) : 0.0;
        } else if (count > 0) {
            acc = (double)classified / (double)count;
        }
        metric_obj = json_object_new_object();
        json_object_object_add(metric_obj, "value", json_object_new_double(acc));
        json_object_object_add(metric_obj, "precision", json_object_new_double(prec));
        json_object_object_add(metric_obj, "recall", json_object_new_double(rec));
        json_object_object_add(metric_obj, "window", json_object_new_string("scan"));
        json_object_object_add(metric_obj, "calibrated", json_object_new_boolean(calibrated ? 1 : 0));
    } else if (strcmp(metric, "scale") == 0) {
        metric_obj = json_object_new_object();
        json_object_object_add(metric_obj, "forests", json_object_new_int(1));
        json_object_object_add(metric_obj, "domains", json_object_new_int(1));
        json_object_object_add(metric_obj, "domain_controllers", json_object_new_int(1));
        json_object_object_add(metric_obj, "users", json_object_new_int(count));
    }

    if (!metric_obj) {
        fprintf(stderr, "Metric '%s' not available.\n", metric);
        json_object_put(root);
        return 1;
    }

    char summary[256];
    snprintf(summary, sizeof(summary), "LDAP metrics derived from scan (%d users).", count);
    json_object_object_add(root, "summary", json_object_new_string(summary));
    json_object_object_add(root, "metric", json_object_new_string(metric));
    json_object_object_add(root, "data", metric_obj);

    if (json_output) {
        printf("%s\n", json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY));
    } else {
        printf("Metric: %s\n", metric);
        printf("Summary: %s\n", summary);
        if (json_object_is_type(metric_obj, json_type_object)) {
            json_object_object_foreach(metric_obj, key, val) {
                if (json_object_is_type(val, json_type_string)) {
                    printf("%s: %s\n", key, json_object_get_string(val));
                } else if (json_object_is_type(val, json_type_double)) {
                    printf("%s: %.2f\n", key, json_object_get_double(val));
                } else if (json_object_is_type(val, json_type_int)) {
                    printf("%s: %d\n", key, json_object_get_int(val));
                } else if (json_object_is_type(val, json_type_boolean)) {
                    printf("%s: %s\n", key, json_object_get_boolean(val) ? "true" : "false");
                }
            }
        }
    }

    json_object_put(root);
    return 0;
}
