#ifndef MOCK_H
#define MOCK_H

int mock_status(int json_output);
int mock_alerts_recent(int json_output);
int mock_correlate_attack(const char *attack, int json_output);
int mock_analyze_incident(const char *incident_id, int json_output);
int mock_metrics(const char *metric, int json_output);

#endif
