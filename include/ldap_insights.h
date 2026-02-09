#ifndef LDAP_INSIGHTS_H
#define LDAP_INSIGHTS_H

#include "types.h"

int ldap_status_output(ADUser *users, int count, int json_output);
int ldap_alerts_recent_output(ADUser *users, int count, int json_output);
int ldap_correlate_attack_output(ADUser *users, int count, const char *attack, int json_output);
int ldap_analyze_incident_output(ADUser *users, int count, const char *incident_id, int json_output);
int ldap_metrics_output(ADUser *users, int count, double scan_seconds, const char *metric, int json_output);

#endif
