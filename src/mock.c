#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <json-c/json.h>
#include "mock.h"

static struct json_object *load_fixture(const char *filename) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "data/mock/%s", filename);
    struct json_object *obj = json_object_from_file(path);
    if (!obj) {
        fprintf(stderr, "Failed to read mock fixture: %s (%s)\n", path, strerror(errno));
        return NULL;
    }
    return obj;
}

static int output_json(struct json_object *obj) {
    const char *payload = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
    printf("%s\n", payload);
    return 0;
}

static const char *get_string_field(struct json_object *obj, const char *key, const char *fallback) {
    struct json_object *val = NULL;
    if (json_object_object_get_ex(obj, key, &val) && json_object_is_type(val, json_type_string)) {
        return json_object_get_string(val);
    }
    return fallback;
}

static struct json_object *get_object_field(struct json_object *obj, const char *key) {
    struct json_object *val = NULL;
    if (json_object_object_get_ex(obj, key, &val) && json_object_is_type(val, json_type_object)) {
        return val;
    }
    return NULL;
}

static struct json_object *get_array_field(struct json_object *obj, const char *key) {
    struct json_object *val = NULL;
    if (json_object_object_get_ex(obj, key, &val) && json_object_is_type(val, json_type_array)) {
        return val;
    }
    return NULL;
}

int mock_status(int json_output) {
    struct json_object *root = load_fixture("status.json");
    if (!root) return 1;

    if (json_output) {
        int rc = output_json(root);
        json_object_put(root);
        return rc;
    }

    struct json_object *data = get_object_field(root, "data");
    printf("Mock Status: OK\n");
    printf("Summary: %s\n", get_string_field(root, "summary", "Mock status ready."));
    if (data) {
        struct json_object *alerts = NULL;
        struct json_object *incidents = NULL;
        struct json_object *detectors = NULL;
        struct json_object *last_refresh = NULL;
        if (json_object_object_get_ex(data, "alerts_total", &alerts)) {
            printf("Alerts total: %d\n", json_object_get_int(alerts));
        }
        if (json_object_object_get_ex(data, "incidents_open", &incidents)) {
            printf("Open incidents: %d\n", json_object_get_int(incidents));
        }
        if (json_object_object_get_ex(data, "detectors", &detectors)) {
            printf("Detectors: %d\n", json_object_get_int(detectors));
        }
        if (json_object_object_get_ex(data, "last_refresh", &last_refresh)) {
            printf("Last refresh: %s\n", json_object_get_string(last_refresh));
        }
    }

    json_object_put(root);
    return 0;
}

int mock_alerts_recent(int json_output) {
    struct json_object *root = load_fixture("alerts.json");
    if (!root) return 1;

    if (json_output) {
        int rc = output_json(root);
        json_object_put(root);
        return rc;
    }

    struct json_object *data = get_object_field(root, "data");
    printf("Recent Alerts\n");
    printf("Summary: %s\n", get_string_field(root, "summary", "Recent alerts ready."));
    if (data) {
        const char *window = get_string_field(data, "window", "24h");
        printf("Window: %s\n", window);
        struct json_object *recent = get_array_field(data, "recent");
        if (recent) {
            size_t count = json_object_array_length(recent);
            printf("Count: %zu\n", count);
            for (size_t i = 0; i < count; i++) {
                struct json_object *item = json_object_array_get_idx(recent, i);
                if (!item) continue;
                const char *id = get_string_field(item, "id", "N/A");
                const char *type = get_string_field(item, "type", "N/A");
                const char *severity = get_string_field(item, "severity", "N/A");
                const char *time = get_string_field(item, "time", "N/A");
                const char *user = get_string_field(item, "user", "N/A");
                printf("- %s [%s] %s (%s) user=%s\n", id, severity, type, time, user);
            }
        }
    }

    json_object_put(root);
    return 0;
}

int mock_correlate_attack(const char *attack, int json_output) {
    struct json_object *root = load_fixture("incidents.json");
    if (!root) return 1;

    struct json_object *data = get_object_field(root, "data");
    struct json_object *correlations = data ? get_array_field(data, "correlations") : NULL;
    if (!correlations) {
        fprintf(stderr, "Mock correlations data missing.\n");
        json_object_put(root);
        return 1;
    }

    struct json_object *match = NULL;
    size_t count = json_object_array_length(correlations);
    for (size_t i = 0; i < count; i++) {
        struct json_object *entry = json_object_array_get_idx(correlations, i);
        if (!entry) continue;
        const char *entry_attack = get_string_field(entry, "attack", "");
        if (strcasecmp(entry_attack, attack) == 0) {
            match = entry;
            break;
        }
    }

    if (!match) {
        fprintf(stderr, "Attack '%s' not found in mock correlations.\n", attack);
        json_object_put(root);
        return 1;
    }

    if (json_output) {
        struct json_object *out = json_object_new_object();
        char summary[256];
        snprintf(summary, sizeof(summary), "Correlation ready for %s.", attack);
        json_object_object_add(out, "summary", json_object_new_string(summary));
        json_object_object_add(out, "data", json_object_get(match));
        int rc = output_json(out);
        json_object_put(out);
        json_object_put(root);
        return rc;
    }

    printf("Correlation\n");
    printf("Summary: Correlation ready for %s.\n", attack);
    printf("Incident: %s\n", get_string_field(match, "incident_id", "N/A"));
    struct json_object *confidence = NULL;
    double confidence_val = 0.0;
    if (json_object_object_get_ex(match, "confidence", &confidence)) {
        confidence_val = json_object_get_double(confidence);
    }
    printf("Confidence: %.2f\n", confidence_val);

    struct json_object *signals = get_array_field(match, "signals");
    if (signals) {
        size_t sig_count = json_object_array_length(signals);
        printf("Signals:\n");
        for (size_t i = 0; i < sig_count; i++) {
            struct json_object *sig = json_object_array_get_idx(signals, i);
            if (sig) printf("- %s\n", json_object_get_string(sig));
        }
    }

    printf("Impact: %s\n", get_string_field(match, "impact", "N/A"));
    printf("Notes: %s\n", get_string_field(match, "summary", "N/A"));

    json_object_put(root);
    return 0;
}

int mock_analyze_incident(const char *incident_id, int json_output) {
    struct json_object *root = load_fixture("incidents.json");
    if (!root) return 1;

    struct json_object *data = get_object_field(root, "data");
    struct json_object *incidents = data ? get_array_field(data, "incidents") : NULL;
    if (!incidents) {
        fprintf(stderr, "Mock incidents data missing.\n");
        json_object_put(root);
        return 1;
    }

    const char *target_id = incident_id;
    if (strcasecmp(incident_id, "latest") == 0) {
        target_id = get_string_field(root, "latest_incident_id", "");
        if (target_id[0] == '\0') {
            fprintf(stderr, "Mock latest incident not set.\n");
            json_object_put(root);
            return 1;
        }
    }

    struct json_object *match = NULL;
    size_t count = json_object_array_length(incidents);
    for (size_t i = 0; i < count; i++) {
        struct json_object *entry = json_object_array_get_idx(incidents, i);
        if (!entry) continue;
        const char *entry_id = get_string_field(entry, "id", "");
        if (strcasecmp(entry_id, target_id) == 0) {
            match = entry;
            break;
        }
    }

    if (!match) {
        fprintf(stderr, "Incident '%s' not found in mock incidents.\n", target_id);
        json_object_put(root);
        return 1;
    }

    if (json_output) {
        struct json_object *out = json_object_new_object();
        char summary[256];
        snprintf(summary, sizeof(summary), "Incident %s analyzed.", target_id);
        json_object_object_add(out, "summary", json_object_new_string(summary));
        json_object_object_add(out, "data", json_object_get(match));
        int rc = output_json(out);
        json_object_put(out);
        json_object_put(root);
        return rc;
    }

    printf("Incident Analysis\n");
    printf("Summary: Incident %s analyzed.\n", target_id);
    printf("Title: %s\n", get_string_field(match, "title", "N/A"));
    printf("Severity: %s\n", get_string_field(match, "severity", "N/A"));
    printf("Status: %s\n", get_string_field(match, "status", "N/A"));
    printf("Started: %s\n", get_string_field(match, "started", "N/A"));
    printf("Last update: %s\n", get_string_field(match, "last_update", "N/A"));

    struct json_object *findings = get_array_field(match, "findings");
    if (findings) {
        size_t fcount = json_object_array_length(findings);
        printf("Findings:\n");
        for (size_t i = 0; i < fcount; i++) {
            struct json_object *finding = json_object_array_get_idx(findings, i);
            if (finding) printf("- %s\n", json_object_get_string(finding));
        }
    }

    struct json_object *actions = get_array_field(match, "recommendations");
    if (actions) {
        size_t acount = json_object_array_length(actions);
        printf("Recommendations:\n");
        for (size_t i = 0; i < acount; i++) {
            struct json_object *action = json_object_array_get_idx(actions, i);
            if (action) printf("- %s\n", json_object_get_string(action));
        }
    }

    json_object_put(root);
    return 0;
}

int mock_metrics(const char *metric, int json_output) {
    struct json_object *root = load_fixture("metrics.json");
    if (!root) return 1;

    struct json_object *data = get_object_field(root, "data");
    if (!data) {
        fprintf(stderr, "Mock metrics data missing.\n");
        json_object_put(root);
        return 1;
    }

    struct json_object *metric_obj = NULL;
    if (!json_object_object_get_ex(data, metric, &metric_obj)) {
        fprintf(stderr, "Metric '%s' not found in mock metrics.\n", metric);
        json_object_put(root);
        return 1;
    }

    if (json_output) {
        struct json_object *out = json_object_new_object();
        json_object_object_add(out, "summary", json_object_new_string(get_string_field(root, "summary", "Mock metrics ready.")));
        json_object_object_add(out, "metric", json_object_new_string(metric));
        json_object_object_add(out, "data", json_object_get(metric_obj));
        int rc = output_json(out);
        json_object_put(out);
        json_object_put(root);
        return rc;
    }

    printf("Metric: %s\n", metric);
    printf("Summary: %s\n", get_string_field(root, "summary", "Mock metrics ready."));
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

    json_object_put(root);
    return 0;
}
