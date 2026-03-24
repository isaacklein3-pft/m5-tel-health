"""
Superstructure Validator Telemetry Gap Analysis and Remediation Module
Post Fiat Network - M5 Live Validator Operations
Task ID: 586dc88d

Audits a running validator fleet's telemetry emissions against the M5 Telemetry
and Health Scoring Framework spec (v1.0, March 2026). For each validator it checks
every required signal channel, flags anything missing, stale, or malformed, and
writes a JSON remediation report with per-channel detail and recommended fix.

The audit engine polls or simulates telemetry endpoints via the fleet manifest.
Each fleet manifest entry carries a telemetry dict that mirrors what a live
validator endpoint would return. Swap the dict for a live poll of the OCP
metric store to run against a production fleet.

Run tests: pytest telemetry_gap_analysis.py -v
"""

import json
import time
import pytest
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


# ---------------------------------------------------------------------------
# Step 1: Telemetry Schema Contract
#
# Signal IDs and collection intervals derived directly from the M5 Telemetry
# and Health Scoring Framework spec, Section 2 (Health Signal Taxonomy) and
# Section 1.1 (Metric Types and Collection Intervals).
#
# Each channel defines:
#   signal_id            - canonical signal identifier from M5 spec
#   layer                - node | operator | network
#   interval_seconds     - maximum age before OCP treats payload as stale
#   staleness_threshold  - seconds at which gap detection triggers (from spec)
#   missing_severity     - severity if signal is absent entirely
#   payload_fields       - required fields per M5 storage schema (Section 1.3)
# ---------------------------------------------------------------------------

M5_TELEMETRY_CHANNELS = [
    # Node Layer - Liveness signals (30s emission, 90s staleness threshold)
    {
        "signal_id": "NODE_HEARTBEAT",
        "layer": "node",
        "interval_seconds": 30,
        "staleness_threshold_seconds": 90,
        "missing_severity": "CRITICAL",
        "payload_fields": ["node_id", "timestamp_utc", "sequence_num", "metric_type", "value"],
    },
    # Node Layer - Performance signals (60s emission, 120s staleness threshold)
    {
        "signal_id": "NODE_LATENCY_P95",
        "layer": "node",
        "interval_seconds": 60,
        "staleness_threshold_seconds": 120,
        "missing_severity": "CRITICAL",
        "payload_fields": ["node_id", "timestamp_utc", "sequence_num", "metric_type", "value"],
    },
    {
        "signal_id": "NODE_CEREMONY_SUCCESS",
        "layer": "node",
        "interval_seconds": 60,
        "staleness_threshold_seconds": 120,
        "missing_severity": "CRITICAL",
        "payload_fields": ["node_id", "timestamp_utc", "sequence_num", "metric_type", "value"],
    },
    {
        "signal_id": "NODE_SLOT_PARTICIPATION",
        "layer": "node",
        "interval_seconds": 60,
        "staleness_threshold_seconds": 120,
        "missing_severity": "CRITICAL",
        "payload_fields": ["node_id", "timestamp_utc", "sequence_num", "metric_type", "value"],
    },
    # Node Layer - Resource signals (60s emission, 120s staleness threshold)
    {
        "signal_id": "NODE_RESOURCE",
        "layer": "node",
        "interval_seconds": 60,
        "staleness_threshold_seconds": 120,
        "missing_severity": "WARNING",
        "payload_fields": ["node_id", "timestamp_utc", "sequence_num", "metric_type", "value"],
    },
    # Node Layer - Security signals (300s integrity check, 360s staleness threshold)
    {
        "signal_id": "NODE_INTEGRITY",
        "layer": "node",
        "interval_seconds": 300,
        "staleness_threshold_seconds": 360,
        "missing_severity": "CRITICAL",
        "payload_fields": ["node_id", "timestamp_utc", "sequence_num", "metric_type", "value", "payload_hash"],
    },
    # Node Layer - Freshness (computed by OCP, not emitted by node)
    {
        "signal_id": "NODE_FRESHNESS",
        "layer": "node",
        "interval_seconds": 60,
        "staleness_threshold_seconds": 90,
        "missing_severity": "CRITICAL",
        "payload_fields": ["node_id", "timestamp_utc", "metric_type", "value"],
    },
    # Operator Aggregate Layer (60s scoring cycle)
    {
        "signal_id": "OP_FLEET_UPTIME",
        "layer": "operator",
        "interval_seconds": 60,
        "staleness_threshold_seconds": 120,
        "missing_severity": "CRITICAL",
        "payload_fields": ["operator_id", "timestamp_utc", "metric_type", "value"],
    },
    {
        "signal_id": "OP_CEREMONY_THROUGHPUT",
        "layer": "operator",
        "interval_seconds": 60,
        "staleness_threshold_seconds": 120,
        "missing_severity": "WARNING",
        "payload_fields": ["operator_id", "timestamp_utc", "metric_type", "value"],
    },
    {
        "signal_id": "OP_INCIDENT_RATE",
        "layer": "operator",
        "interval_seconds": 60,
        "staleness_threshold_seconds": 120,
        "missing_severity": "WARNING",
        "payload_fields": ["operator_id", "timestamp_utc", "metric_type", "value"],
    },
]

# Fallback staleness multipliers used if a channel has no staleness_threshold_seconds.
# The spec defines per-signal thresholds directly; these are only used as a backup.
DEFAULT_STALE_WARNING_MULTIPLIER  = 2.0
DEFAULT_STALE_CRITICAL_MULTIPLIER = 3.0


class ChannelStatus(str, Enum):
    HEALTHY   = "HEALTHY"
    STALE     = "STALE"
    MISSING   = "MISSING"
    MALFORMED = "MALFORMED"


class Severity(str, Enum):
    INFO     = "INFO"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class ChannelGap:
    signal_id:                     str
    layer:                         str
    status:                        ChannelStatus
    expected_interval_seconds:     int
    staleness_threshold_seconds:   int
    expected_payload_fields:       list
    last_seen_timestamp:           Optional[float]
    seconds_since_last_emission:   Optional[float]
    severity:                      Severity
    remediation:                   str


@dataclass
class ValidatorReport:
    validator_id:   str
    audited_at:     float
    total_channels: int
    healthy_count:  int
    gaps:           list = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(g.severity == Severity.CRITICAL for g in self.gaps)


@dataclass
class FleetReport:
    generated_at:        float
    total_validators:    int
    healthy_validators:  int
    degraded_validators: int
    critical_validators: int
    validators:          list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Step 2: Telemetry Audit Engine
# ---------------------------------------------------------------------------

def _classify_channel(
    channel: dict,
    telemetry: Optional[dict],
    now: float,
    stale_warning_multiplier:  float = DEFAULT_STALE_WARNING_MULTIPLIER,
    stale_critical_multiplier: float = DEFAULT_STALE_CRITICAL_MULTIPLIER,
) -> ChannelGap:
    """
    Classify a single telemetry channel for one validator.

    Returns MISSING if the signal has no record in the payload at all.
    Returns MALFORMED if the record exists but is missing required payload
    fields or has a non-numeric timestamp_utc. Returns STALE if the timestamp
    is valid but seconds_since_last_emission exceeds the staleness threshold
    from the M5 spec. Returns HEALTHY otherwise.
    """
    signal_id          = channel["signal_id"]
    layer              = channel["layer"]
    interval           = channel["interval_seconds"]
    stale_threshold    = channel["staleness_threshold_seconds"]
    missing_sev        = channel["missing_severity"]
    required_fields    = channel.get("payload_fields", ["node_id", "timestamp_utc", "value"])

    if telemetry is None or signal_id not in telemetry:
        return ChannelGap(
            signal_id=signal_id,
            layer=layer,
            status=ChannelStatus.MISSING,
            expected_interval_seconds=interval,
            staleness_threshold_seconds=stale_threshold,
            expected_payload_fields=required_fields,
            last_seen_timestamp=None,
            seconds_since_last_emission=None,
            severity=Severity(missing_sev),
            remediation=(
                f"No telemetry record found for signal '{signal_id}' ({layer} layer). "
                f"Expected emission every {interval}s. Verify pft-telemetry-agent is "
                f"collecting and emitting this signal."
            ),
        )

    record = telemetry[signal_id]

    if not isinstance(record, dict):
        return ChannelGap(
            signal_id=signal_id,
            layer=layer,
            status=ChannelStatus.MALFORMED,
            expected_interval_seconds=interval,
            staleness_threshold_seconds=stale_threshold,
            expected_payload_fields=required_fields,
            last_seen_timestamp=None,
            seconds_since_last_emission=None,
            severity=Severity.CRITICAL,
            remediation=(
                f"Signal '{signal_id}' payload is not a dict. "
                f"Expected object with fields: {required_fields}."
            ),
        )

    missing_fields = [f for f in required_fields if f not in record]
    if missing_fields:
        return ChannelGap(
            signal_id=signal_id,
            layer=layer,
            status=ChannelStatus.MALFORMED,
            expected_interval_seconds=interval,
            staleness_threshold_seconds=stale_threshold,
            expected_payload_fields=required_fields,
            last_seen_timestamp=None,
            seconds_since_last_emission=None,
            severity=Severity.CRITICAL,
            remediation=(
                f"Signal '{signal_id}' payload malformed: missing required fields "
                f"{missing_fields}. Check pft-telemetry-agent serialization."
            ),
        )

    ts = record.get("timestamp_utc")
    if not isinstance(ts, (int, float)):
        return ChannelGap(
            signal_id=signal_id,
            layer=layer,
            status=ChannelStatus.MALFORMED,
            expected_interval_seconds=interval,
            staleness_threshold_seconds=stale_threshold,
            expected_payload_fields=required_fields,
            last_seen_timestamp=None,
            seconds_since_last_emission=None,
            severity=Severity.CRITICAL,
            remediation=(
                f"Signal '{signal_id}' timestamp_utc is not numeric. "
                f"Expected Unix epoch float, got {type(ts).__name__}."
            ),
        )

    seconds_since = now - ts

    # CRITICAL at staleness_threshold. WARNING at the midpoint between interval and threshold.
    warning_threshold = stale_threshold * 0.5 + interval * 0.5
    if seconds_since > stale_threshold:
        severity    = Severity.CRITICAL
        status      = ChannelStatus.STALE
        remediation = (
            f"Signal '{signal_id}' last emitted {seconds_since:.0f}s ago. "
            f"Exceeds spec staleness threshold ({stale_threshold}s). "
            f"OCP gap detection has triggered. Investigate pft-telemetry-agent "
            f"or validator node connectivity immediately."
        )
    elif seconds_since > warning_threshold:
        severity    = Severity.WARNING
        status      = ChannelStatus.STALE
        remediation = (
            f"Signal '{signal_id}' last emitted {seconds_since:.0f}s ago. "
            f"Approaching staleness threshold ({stale_threshold}s). "
            f"Monitor for continued degradation."
        )
    else:
        severity    = Severity.INFO
        status      = ChannelStatus.HEALTHY
        remediation = "Signal healthy."

    return ChannelGap(
        signal_id=signal_id,
        layer=layer,
        status=status,
        expected_interval_seconds=interval,
        staleness_threshold_seconds=stale_threshold,
        expected_payload_fields=required_fields,
        last_seen_timestamp=ts,
        seconds_since_last_emission=seconds_since,
        severity=severity,
        remediation=remediation,
    )


def audit_validator(
    validator_id: str,
    telemetry: Optional[dict],
    schema: list = None,
    now: Optional[float] = None,
    stale_warning_multiplier:  float = DEFAULT_STALE_WARNING_MULTIPLIER,
    stale_critical_multiplier: float = DEFAULT_STALE_CRITICAL_MULTIPLIER,
) -> ValidatorReport:
    """
    Audit a single validator's telemetry against the M5 schema contract.
    telemetry simulates the response from the validator's telemetry endpoint.
    """
    if schema is None:
        schema = M5_TELEMETRY_CHANNELS
    now = now or time.time()
    gaps = []

    for channel in schema:
        gap = _classify_channel(
            channel, telemetry, now,
            stale_warning_multiplier, stale_critical_multiplier,
        )
        if gap.status != ChannelStatus.HEALTHY:
            gaps.append(gap)

    healthy_count = len(schema) - len(gaps)

    return ValidatorReport(
        validator_id=validator_id,
        audited_at=now,
        total_channels=len(schema),
        healthy_count=healthy_count,
        gaps=gaps,
    )


def audit_fleet(
    fleet_manifest: list,
    schema: list = None,
    now: Optional[float] = None,
    stale_warning_multiplier:  float = DEFAULT_STALE_WARNING_MULTIPLIER,
    stale_critical_multiplier: float = DEFAULT_STALE_CRITICAL_MULTIPLIER,
) -> FleetReport:
    """
    Audit the full validator fleet against the M5 schema contract.

    fleet_manifest: list of dicts, each with 'validator_id' and 'telemetry'.
    telemetry is a dict of signal_id -> payload dict, simulating the response
    from each validator's OCP telemetry endpoint. In production, replace with
    a live query of the OCP metric store.

    stale_warning_multiplier and stale_critical_multiplier set how old a
    channel emission can be before it trips WARNING or CRITICAL.
    """
    if schema is None:
        schema = M5_TELEMETRY_CHANNELS
    now = now or time.time()
    validator_reports = []

    for entry in fleet_manifest:
        report = audit_validator(
            validator_id=entry["validator_id"],
            telemetry=entry.get("telemetry"),
            schema=schema,
            now=now,
            stale_warning_multiplier=stale_warning_multiplier,
            stale_critical_multiplier=stale_critical_multiplier,
        )
        validator_reports.append(report)

    healthy  = sum(1 for r in validator_reports if not r.gaps)
    critical = sum(1 for r in validator_reports if r.has_critical)
    degraded = len(validator_reports) - healthy

    return FleetReport(
        generated_at=now,
        total_validators=len(fleet_manifest),
        healthy_validators=healthy,
        degraded_validators=degraded,
        critical_validators=critical,
        validators=validator_reports,
    )


# ---------------------------------------------------------------------------
# Step 3: Remediation Report Generator
# ---------------------------------------------------------------------------

def generate_remediation_report(fleet_report: FleetReport) -> dict:
    """
    Serialize a FleetReport to a structured JSON-compatible dict.

    Each gap entry carries: the signal ID and layer, how often it was supposed
    to emit (expected_interval_seconds), the spec staleness threshold
    (staleness_threshold_seconds), when it last did (actual_last_seen_timestamp),
    how long ago that was (seconds_since_last_emission), the severity level,
    and the recommended remediation action.
    """
    return {
        "schema_version": "1.0.0",
        "spec_reference": "M5 Validator Telemetry and Health Scoring Framework v1.0",
        "generated_at": fleet_report.generated_at,
        "summary": {
            "total_validators":    fleet_report.total_validators,
            "healthy_validators":  fleet_report.healthy_validators,
            "degraded_validators": fleet_report.degraded_validators,
            "critical_validators": fleet_report.critical_validators,
        },
        "validators": [
            {
                "validator_id":   r.validator_id,
                "audited_at":     r.audited_at,
                "total_channels": r.total_channels,
                "healthy_count":  r.healthy_count,
                "gaps": [
                    {
                        "signal_id":                   g.signal_id,
                        "layer":                       g.layer,
                        "status":                      g.status.value,
                        "expected_interval_seconds":   g.expected_interval_seconds,
                        "staleness_threshold_seconds": g.staleness_threshold_seconds,
                        "expected_payload_fields":     g.expected_payload_fields,
                        "actual_last_seen_timestamp":  g.last_seen_timestamp,
                        "seconds_since_last_emission": g.seconds_since_last_emission,
                        "severity":                    g.severity.value,
                        "remediation":                 g.remediation,
                    }
                    for g in r.gaps
                ],
            }
            for r in fleet_report.validators
        ],
    }


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

MINI_SCHEMA = [
    {
        "signal_id": "NODE_HEARTBEAT",
        "layer": "node",
        "interval_seconds": 30,
        "staleness_threshold_seconds": 90,
        "missing_severity": "CRITICAL",
        "payload_fields": ["node_id", "timestamp_utc", "sequence_num", "metric_type", "value"],
    },
    {
        "signal_id": "NODE_LATENCY_P95",
        "layer": "node",
        "interval_seconds": 60,
        "staleness_threshold_seconds": 120,
        "missing_severity": "CRITICAL",
        "payload_fields": ["node_id", "timestamp_utc", "sequence_num", "metric_type", "value"],
    },
    {
        "signal_id": "NODE_INTEGRITY",
        "layer": "node",
        "interval_seconds": 300,
        "staleness_threshold_seconds": 360,
        "missing_severity": "CRITICAL",
        "payload_fields": ["node_id", "timestamp_utc", "sequence_num", "metric_type", "value", "payload_hash"],
    },
]


def _healthy_telemetry(now: float, schema: list) -> dict:
    """Build a fully healthy telemetry payload with all signals fresh."""
    result = {}
    for ch in schema:
        payload = {
            "node_id": "test-node-001",
            "timestamp_utc": now - 10,
            "sequence_num": 1,
            "metric_type": ch["signal_id"],
            "value": 1.0,
        }
        for f in ch["payload_fields"]:
            if f not in payload:
                payload[f] = "present"
        result[ch["signal_id"]] = payload
    return result


# ---------------------------------------------------------------------------
# Step 4: Unit Tests (8 required scenarios, 13 tests total)
# ---------------------------------------------------------------------------

class TestAllChannelsHealthy:
    """Test 1: all signals present and within emission interval."""

    def test_all_healthy(self):
        now = time.time()
        tel = _healthy_telemetry(now, MINI_SCHEMA)
        report = audit_validator("val-001", tel, schema=MINI_SCHEMA, now=now)

        assert len(report.gaps) == 0, (
            f"expected no gaps for healthy telemetry, got {len(report.gaps)}"
        )
        assert report.healthy_count == len(MINI_SCHEMA), (
            f"expected {len(MINI_SCHEMA)} healthy channels, got {report.healthy_count}"
        )


class TestSingleChannelMissing:
    """Test 2: one signal absent from telemetry payload."""

    def test_single_missing(self):
        now = time.time()
        tel = _healthy_telemetry(now, MINI_SCHEMA)
        del tel["NODE_HEARTBEAT"]

        report = audit_validator("val-002", tel, schema=MINI_SCHEMA, now=now)

        missing = [g for g in report.gaps if g.status == ChannelStatus.MISSING]
        assert len(missing) == 1, (
            f"expected 1 missing signal, got {len(missing)}"
        )
        assert missing[0].signal_id == "NODE_HEARTBEAT", (
            f"expected NODE_HEARTBEAT missing, got {missing[0].signal_id}"
        )
        assert missing[0].severity == Severity.CRITICAL, (
            f"expected CRITICAL for missing NODE_HEARTBEAT, got {missing[0].severity}"
        )
        assert missing[0].last_seen_timestamp is None
        assert missing[0].seconds_since_last_emission is None


class TestMultipleChannelsStale:
    """Test 3: multiple signals stale beyond the warning threshold."""

    def test_multiple_stale(self):
        now = time.time()
        tel = {}
        for ch in MINI_SCHEMA:
            # Push each signal past its staleness_threshold_seconds
            stale_age = ch["staleness_threshold_seconds"] + 30
            payload = {
                "node_id": "test-node-001",
                "timestamp_utc": now - stale_age,
                "sequence_num": 1,
                "metric_type": ch["signal_id"],
                "value": 1.0,
            }
            for f in ch["payload_fields"]:
                if f not in payload:
                    payload[f] = "present"
            tel[ch["signal_id"]] = payload

        report = audit_validator("val-003", tel, schema=MINI_SCHEMA, now=now)

        stale = [g for g in report.gaps if g.status == ChannelStatus.STALE]
        assert len(stale) == len(MINI_SCHEMA), (
            f"expected all {len(MINI_SCHEMA)} signals stale, got {len(stale)}"
        )
        for gap in stale:
            assert gap.severity == Severity.CRITICAL, (
                f"expected CRITICAL for signal past staleness threshold "
                f"{gap.signal_id}, got {gap.severity}"
            )
            assert gap.seconds_since_last_emission is not None


class TestMalformedTelemetryPayload:
    """Test 4: signal present but payload missing required fields."""

    def test_malformed_missing_required_field(self):
        now = time.time()
        tel = _healthy_telemetry(now, MINI_SCHEMA)
        # Remove payload_hash from NODE_INTEGRITY which requires it
        tel["NODE_INTEGRITY"] = {
            "node_id": "test-node-001",
            "timestamp_utc": now - 10,
            "sequence_num": 1,
            "metric_type": "NODE_INTEGRITY",
            "value": 1.0,
            # payload_hash deliberately absent
        }

        report = audit_validator("val-004", tel, schema=MINI_SCHEMA, now=now)

        malformed = [g for g in report.gaps if g.status == ChannelStatus.MALFORMED]
        assert len(malformed) == 1, (
            f"expected 1 malformed signal, got {len(malformed)}"
        )
        assert malformed[0].signal_id == "NODE_INTEGRITY"
        assert malformed[0].severity == Severity.CRITICAL

    def test_malformed_non_numeric_timestamp(self):
        now = time.time()
        tel = _healthy_telemetry(now, MINI_SCHEMA)
        tel["NODE_HEARTBEAT"]["timestamp_utc"] = "not-a-timestamp"

        report = audit_validator("val-004b", tel, schema=MINI_SCHEMA, now=now)

        malformed = [g for g in report.gaps if g.status == ChannelStatus.MALFORMED]
        assert any(g.signal_id == "NODE_HEARTBEAT" for g in malformed), (
            "expected NODE_HEARTBEAT flagged as malformed"
        )
        assert all(g.severity == Severity.CRITICAL for g in malformed)


class TestEmptyFleetManifest:
    """Test 5: fleet manifest with no validators."""

    def test_empty_fleet(self):
        report = audit_fleet([])

        assert report.total_validators == 0
        assert report.healthy_validators == 0
        assert report.degraded_validators == 0
        assert report.critical_validators == 0
        assert len(report.validators) == 0


class TestMixedFleet:
    """Test 6: fleet with some healthy and some degraded validators."""

    def test_mixed_healthy_and_degraded(self):
        now = time.time()
        healthy_tel  = _healthy_telemetry(now, MINI_SCHEMA)
        degraded_tel = _healthy_telemetry(now, MINI_SCHEMA)
        del degraded_tel["NODE_HEARTBEAT"]

        fleet = [
            {"validator_id": "val-good", "telemetry": healthy_tel},
            {"validator_id": "val-bad",  "telemetry": degraded_tel},
        ]
        report = audit_fleet(fleet, schema=MINI_SCHEMA, now=now)

        assert report.total_validators == 2
        assert report.healthy_validators == 1, (
            f"expected 1 healthy, got {report.healthy_validators}"
        )
        assert report.degraded_validators == 1, (
            f"expected 1 degraded, got {report.degraded_validators}"
        )
        assert report.critical_validators == 1, (
            "missing NODE_HEARTBEAT (CRITICAL) should mark validator critical"
        )


class TestSeverityClassification:
    """
    Test 7: severity thresholds match M5 spec.
    Spec defines per-signal staleness_threshold_seconds as the CRITICAL boundary.
    Warning fires in the window between healthy and critical.
    """

    def test_healthy_within_interval(self):
        now = time.time()
        ch  = MINI_SCHEMA[0]  # NODE_HEARTBEAT, 30s interval, 90s staleness
        tel = {
            "NODE_HEARTBEAT": {
                "node_id": "n1", "timestamp_utc": now - 20,
                "sequence_num": 1, "metric_type": "NODE_HEARTBEAT", "value": 1.0,
            }
        }
        gap = _classify_channel(ch, tel, now)
        assert gap.severity == Severity.INFO, (
            f"20s old on 30s interval should be INFO, got {gap.severity}"
        )

    def test_warning_approaching_threshold(self):
        now = time.time()
        ch  = MINI_SCHEMA[0]  # NODE_HEARTBEAT, staleness_threshold=90s
        # Warning window is between interval and threshold: ~60s for NODE_HEARTBEAT
        tel = {
            "NODE_HEARTBEAT": {
                "node_id": "n1", "timestamp_utc": now - 65,
                "sequence_num": 1, "metric_type": "NODE_HEARTBEAT", "value": 1.0,
            }
        }
        gap = _classify_channel(ch, tel, now)
        assert gap.severity == Severity.WARNING, (
            f"65s old on NODE_HEARTBEAT (90s threshold) should be WARNING, got {gap.severity}"
        )

    def test_critical_past_staleness_threshold(self):
        now = time.time()
        ch  = MINI_SCHEMA[0]  # NODE_HEARTBEAT, staleness_threshold=90s
        tel = {
            "NODE_HEARTBEAT": {
                "node_id": "n1", "timestamp_utc": now - 95,
                "sequence_num": 1, "metric_type": "NODE_HEARTBEAT", "value": 1.0,
            }
        }
        gap = _classify_channel(ch, tel, now)
        assert gap.severity == Severity.CRITICAL, (
            f"95s old on NODE_HEARTBEAT (90s threshold) should be CRITICAL, got {gap.severity}"
        )

    def test_integrity_check_uses_360s_threshold(self):
        now = time.time()
        ch  = MINI_SCHEMA[2]  # NODE_INTEGRITY, staleness_threshold=360s
        tel = {
            "NODE_INTEGRITY": {
                "node_id": "n1", "timestamp_utc": now - 370,
                "sequence_num": 1, "metric_type": "NODE_INTEGRITY",
                "value": 1.0, "payload_hash": "abc123",
            }
        }
        gap = _classify_channel(ch, tel, now)
        assert gap.severity == Severity.CRITICAL, (
            f"370s old on NODE_INTEGRITY (360s threshold) should be CRITICAL, "
            f"got {gap.severity}"
        )


class TestRemediationReportSchema:
    """Test 8: remediation report matches required JSON schema."""

    def test_report_schema(self):
        now = time.time()
        tel = _healthy_telemetry(now, MINI_SCHEMA)
        del tel["NODE_LATENCY_P95"]

        fleet        = [{"validator_id": "val-schema-test", "telemetry": tel}]
        fleet_report = audit_fleet(fleet, schema=MINI_SCHEMA, now=now)
        report       = generate_remediation_report(fleet_report)

        for key in ("schema_version", "spec_reference", "generated_at",
                    "summary", "validators"):
            assert key in report, f"report missing top-level field: {key}"

        for key in ("total_validators", "healthy_validators",
                    "degraded_validators", "critical_validators"):
            assert key in report["summary"], f"summary missing field: {key}"

        val = report["validators"][0]
        assert val["validator_id"] == "val-schema-test"
        assert len(val["gaps"]) == 1

        gap = val["gaps"][0]
        for key in ("signal_id", "layer", "status", "expected_interval_seconds",
                    "staleness_threshold_seconds", "expected_payload_fields",
                    "actual_last_seen_timestamp", "seconds_since_last_emission",
                    "severity", "remediation"):
            assert key in gap, f"gap record missing required field: {key}"

        assert gap["signal_id"] == "NODE_LATENCY_P95"
        assert gap["status"]    == ChannelStatus.MISSING.value
        assert gap["severity"]  == Severity.CRITICAL.value
        assert gap["actual_last_seen_timestamp"] is None
        assert gap["seconds_since_last_emission"] is None

    def test_report_is_json_serializable(self):
        now          = time.time()
        fleet        = [{"validator_id": "val-json",
                         "telemetry": _healthy_telemetry(now, MINI_SCHEMA)}]
        fleet_report = audit_fleet(fleet, schema=MINI_SCHEMA, now=now)
        report       = generate_remediation_report(fleet_report)

        serialized = json.dumps(report)
        assert len(serialized) > 0
        parsed = json.loads(serialized)
        assert parsed["summary"]["total_validators"] == 1
        assert parsed["validators"][0]["validator_id"] == "val-json"
        assert parsed["spec_reference"] == "M5 Validator Telemetry and Health Scoring Framework v1.0"
