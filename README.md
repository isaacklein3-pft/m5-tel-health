# m5-tel-health
M5 Validator Telemetry and Health Scoring Framework
# M5 Superstructure Validator Telemetry and Health Scoring

Post Fiat Network — Superstructure Validator Platform, M5 Live Validator Operations

## What this repo contains

Two artifacts from the M5 Telemetry and Health Scoring workstream:

1. `index.html` — The M5 Telemetry and Health Scoring Framework specification. Defines all required telemetry channels, collection intervals, staleness thresholds, health scoring logic, tier classifications, and OCP action triggers for a live institutional validator fleet.

2. `telemetry_gap_analysis.py` — A Python audit engine that programmatically checks a running validator fleet against the M5 spec. Identifies missing, stale, and malformed telemetry channels and outputs a structured JSON remediation report per validator. Scored 10,000 PFT exceptional on the Post Fiat Task Node.

## Architecture decisions worth reading

**Why 90 seconds is the staleness threshold for NODE_HEARTBEAT.** The spec defines 30-second heartbeat emission intervals. Three missed cycles at 90 seconds is the gap detection trigger because it separates a transient network blip from a genuine connectivity failure without triggering false-positive failover. This threshold is consistent with M3 CRS failover logic rather than an invented value.

**Why NODE_INTEGRITY failures floor the composite score to zero immediately.** An integrity check failure is not a degradation event. It is a security event. Leaving a node with a failed binary integrity check in the routing pool while applying a score penalty is a design error. The override is pass/fail, not weighted, because the failure modes are categorically different from performance degradation.

**Why the audit engine was built against real M5 signal IDs.** A prior submission built against invented interfaces scored 63/100. This module uses the actual signal identifiers from the spec: NODE_HEARTBEAT, NODE_LATENCY_P95, NODE_CEREMONY_SUCCESS, NODE_SLOT_PARTICIPATION, NODE_RESOURCE, NODE_INTEGRITY, NODE_FRESHNESS, OP_FLEET_UPTIME, OP_CEREMONY_THROUGHPUT, OP_INCIDENT_RATE with their spec-defined staleness thresholds of 90s, 120s, and 360s.

## Running the tests
```bash
pytest telemetry_gap_analysis.py -v
```

13 tests, all passing. Covers all channels healthy, single channel missing, multiple channels stale, malformed payload, empty fleet, mixed fleet, severity classification at exact spec thresholds, and remediation report schema validation.

## Signal IDs and thresholds from the M5 spec

| Signal | Layer | Interval | Staleness Threshold |
| ------ | ----- | -------- | ------------------- |
| NODE_HEARTBEAT | node | 30s | 90s |
| NODE_LATENCY_P95 | node | 60s | 120s |
| NODE_CEREMONY_SUCCESS | node | 60s | 120s |
| NODE_SLOT_PARTICIPATION | node | 60s | 120s |
| NODE_RESOURCE | node | 60s | 120s |
| NODE_INTEGRITY | node | 300s | 360s |
| NODE_FRESHNESS | node | 60s | 90s |
| OP_FLEET_UPTIME | operator | 60s | 120s |
| OP_CEREMONY_THROUGHPUT | operator | 60s | 120s |
| OP_INCIDENT_RATE | operator | 60s | 120s |
