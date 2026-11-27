"""Apply separate rules for source activity and account activity."""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from itertools import groupby

from .parser import AuthEvent


@dataclass(frozen=True, slots=True)
class Rules:
    window_seconds: int = 120
    min_failures: int = 5
    success_min_failures: int = 3


@dataclass(frozen=True, slots=True)
class Alert:
    rule: str
    severity: str
    detected_at: datetime
    first_failure_at: datetime
    host: str
    source_ip: str
    accounts: tuple[str, ...]
    failure_count: int
    evidence_lines: tuple[int, ...]


def _expire(failures: deque[AuthEvent], now: datetime, window_seconds: int) -> None:
    while failures and (now - failures[0].timestamp).total_seconds() > window_seconds:
        failures.popleft()


def _alert(rule: str, severity: str, failures: deque[AuthEvent], trigger: AuthEvent) -> Alert:
    evidence = tuple(event.line_number for event in failures)
    if trigger.accepted:
        evidence += (trigger.line_number,)
    return Alert(
        rule=rule,
        severity=severity,
        detected_at=trigger.timestamp,
        first_failure_at=failures[0].timestamp,
        host=trigger.host,
        source_ip=trigger.source_ip,
        accounts=tuple(sorted({event.account for event in failures})),
        failure_count=len(failures),
        evidence_lines=evidence,
    )


def _source(event: AuthEvent) -> tuple[str, str]:
    return event.host, event.source_ip


def detect_alerts(events: list[AuthEvent], rules: Rules) -> list[Alert]:
    ordered = sorted(events, key=lambda event: (_source(event), event.timestamp, event.line_number))
    alerts: list[Alert] = []

    for _, source_events in groupby(ordered, key=_source):
        source_failures: deque[AuthEvent] = deque()
        account_failures: dict[str, deque[AuthEvent]] = defaultdict(deque)

        for event in source_events:
            failures = account_failures[event.account]
            _expire(failures, event.timestamp, rules.window_seconds)

            if event.accepted:
                if len(failures) >= rules.success_min_failures:
                    alerts.append(_alert("success_after_failures", "high", failures, event))
                account_failures.pop(event.account)
                continue

            failures.append(event)
            _expire(source_failures, event.timestamp, rules.window_seconds)
            source_failures.append(event)
            if len(source_failures) == rules.min_failures:
                alerts.append(_alert("repeated_failures", "medium", source_failures, event))

    return sorted(alerts, key=lambda alert: (alert.detected_at, alert.evidence_lines[-1]))
