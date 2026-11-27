"""Render alert summaries with references to the original log line numbers."""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from html import escape
from pathlib import Path
from string import Template

from .detect import Alert, Rules
from .parser import ParsedLog


RULE_TITLES = {
    "repeated_failures": "Repeated login failures",
    "success_after_failures": "Successful login after failures",
}


@dataclass(frozen=True, slots=True)
class Summary:
    lines_read: int
    auth_events: int
    unique_source_ips: int
    ignored_lines: int
    malformed_lines: int
    first_event: datetime | None
    last_event: datetime | None


@dataclass(frozen=True, slots=True)
class Report:
    summary: Summary
    rules: Rules
    alerts: list[Alert]


def build_report(log: ParsedLog, rules: Rules, alerts: list[Alert]) -> Report:
    timestamps = [event.timestamp for event in log.events]
    return Report(
        summary=Summary(
            lines_read=log.lines_read,
            auth_events=len(log.events),
            unique_source_ips=len({event.source_ip for event in log.events}),
            ignored_lines=log.ignored_lines,
            malformed_lines=log.malformed_lines,
            first_event=min(timestamps, default=None),
            last_event=max(timestamps, default=None),
        ),
        rules=rules,
        alerts=alerts,
    )


def _utc(stamp: datetime) -> str:
    return stamp.isoformat().removesuffix("+00:00") + "Z"


def _line_numbers(alert: Alert) -> str:
    return ", ".join(str(line) for line in alert.evidence_lines)


def terminal_text(value: str) -> str:
    return "".join(
        char if char.isascii() and char.isprintable() else ascii(char)[1:-1]
        for char in value
    )


def render_text(report: Report) -> str:
    summary = report.summary
    lines = [
        f"{summary.auth_events} auth events across {summary.lines_read} lines "
        f"({summary.ignored_lines} ignored, {summary.malformed_lines} malformed)",
        f"{len(report.alerts)} findings",
    ]
    for alert in report.alerts:
        accounts = ", ".join(map(terminal_text, alert.accounts))
        lines.extend([
            f"[{alert.severity.upper()}] {_utc(alert.detected_at)}  {RULE_TITLES[alert.rule]}",
            f"  {terminal_text(alert.host)} | {terminal_text(alert.source_ip)} | "
            f"{alert.failure_count} failures | {accounts}",
            f"  Log lines {_line_numbers(alert)}",
        ])
    return "\n".join(lines)


def render_json(report: Report) -> str:
    return json.dumps(asdict(report), default=_utc, indent=2)


def _html_finding(alert: Alert) -> str:
    accounts = escape(", ".join(alert.accounts))
    return f"""
      <article class="finding">
        <div class="finding-heading">
          <span class="severity {alert.severity}">{alert.severity.title()}</span>
          <h3>{RULE_TITLES[alert.rule]}</h3>
          <time datetime="{_utc(alert.detected_at)}">{_utc(alert.detected_at)}</time>
        </div>
        <dl class="details">
          <div><dt>Host</dt><dd>{escape(alert.host)}</dd></div>
          <div><dt>Source IP</dt><dd>{escape(alert.source_ip)}</dd></div>
          <div><dt>Accounts</dt><dd>{accounts}</dd></div>
          <div><dt>Failures</dt><dd>{alert.failure_count}</dd></div>
        </dl>
        <details>
          <summary>Log evidence</summary>
          <p>First failure <time datetime="{_utc(alert.first_failure_at)}">{_utc(alert.first_failure_at)}</time></p>
          <p>Original line numbers <strong>{_line_numbers(alert)}</strong></p>
        </details>
      </article>"""


def render_html(report: Report) -> str:
    summary = report.summary
    log_window = "No supported authentication events were parsed."
    if summary.first_event is not None and summary.last_event is not None:
        log_window = f"{_utc(summary.first_event)} to {_utc(summary.last_event)}"
    findings = "\n".join(_html_finding(alert) for alert in report.alerts)
    template = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
    html = Template(template).substitute(
        finding_count=len(report.alerts),
        log_window=log_window,
        lines_read=summary.lines_read,
        event_count=summary.auth_events,
        source_count=summary.unique_source_ips,
        ignored_lines=summary.ignored_lines,
        malformed_lines=summary.malformed_lines,
        window_seconds=report.rules.window_seconds,
        min_failures=report.rules.min_failures,
        success_min_failures=report.rules.success_min_failures,
        findings=findings or '<p class="empty">No findings matched the configured rules.</p>',
    )
    return html.encode("ascii", errors="xmlcharrefreplace").decode("ascii")
