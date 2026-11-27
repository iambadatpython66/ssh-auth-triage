import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from ssh_auth_triage.detect import Rules, detect_alerts
from ssh_auth_triage.parser import read_log
from ssh_auth_triage.report import build_report, render_html, render_text


ROOT = Path(__file__).resolve().parents[1]


def record(clock, *, outcome="Failed", account="ops", address="192.0.2.5", host="lab"):
    return f"2026-09-18T{clock}Z {host} sshd[12]: {outcome} password for {account} from {address} port 50221 ssh2"


def analyze(lines, rules=Rules()):
    parsed = read_log(lines)
    return build_report(parsed, rules, detect_alerts(parsed.events, rules))


class ParserTests(unittest.TestCase):
    def test_classic_syslog_normalizes_timezone_host_and_ipv6(self):
        log = ["Sep  8 14:00:02 Lab sshd-session[12]: Failed password for invalid user ops from 2001:0db8::7 port 50221 ssh2"]
        parsed = read_log(log, syslog_year=2026, syslog_zone=timezone(timedelta(hours=4)))
        event = parsed.events[0]
        self.assertEqual(event.timestamp, datetime(2026, 9, 8, 10, 0, 2, tzinfo=timezone.utc))
        self.assertEqual((event.host, event.source_ip, event.account, event.line_number), ("lab", "2001:db8::7", "ops", 1))
        self.assertFalse(event.accepted)

    def test_classic_syslog_requires_year(self):
        with self.assertRaisesRegex(ValueError, "--syslog-year"):
            read_log(["Sep  8 14:00:02 lab sshd[12]: Failed password for ops from 192.0.2.5 port 50221 ssh2"])

    def test_distinguishes_ignored_and_malformed_lines(self):
        parsed = read_log([
            "hello",
            "2026-09-18T10:00:00Z lab sshd[12]: Connection closed by 192.0.2.5 port 50221",
            record("10:00:00", address="invalid-ip"),
            record("28:00:00"),
            record("10:00:00", outcome="Accepted"),
        ])
        self.assertEqual((parsed.lines_read, parsed.ignored_lines, parsed.malformed_lines), (5, 2, 2))
        self.assertEqual(len(parsed.events), 1)
        self.assertTrue(parsed.events[0].accepted)


class DetectionTests(unittest.TestCase):
    def test_orders_events_and_includes_the_window_boundary(self):
        report = analyze([
            record("10:02:00", account="sam"),
            record("10:00:00"),
        ], Rules(min_failures=2))
        alert, = report.alerts
        self.assertEqual(alert.rule, "repeated_failures")
        self.assertEqual(alert.evidence_lines, (2, 1))
        self.assertEqual(alert.accounts, ("ops", "sam"))

    def test_repeated_failures_rearm_after_the_window_expires(self):
        times = ["10:00:00", "10:00:01", "10:00:02", "10:03:00", "10:03:01"]
        report = analyze([record(clock) for clock in times], Rules(min_failures=2))
        self.assertEqual([alert.evidence_lines for alert in report.alerts], [(1, 2), (4, 5)])

    def test_groups_by_host_and_ip(self):
        report = analyze([
            record("10:00:01"),
            record("10:00:02", host="edge"),
            record("10:00:03", address="192.0.2.6"),
        ], Rules(min_failures=2))
        self.assertEqual(report.alerts, [])

    def test_success_requires_matching_account_and_resets_its_count(self):
        report = analyze([
            record("10:00:00"),
            record("10:00:01", account="sam"),
            record("10:00:02", outcome="Accepted"),
            record("10:00:03"),
            record("10:00:04"),
            record("10:00:05", outcome="Accepted"),
            record("10:00:06", outcome="Accepted"),
        ], Rules(success_min_failures=2))
        alert, = report.alerts
        self.assertEqual((alert.rule, alert.failure_count), ("success_after_failures", 2))
        self.assertEqual(alert.evidence_lines, (4, 5, 6))

    def test_old_failures_do_not_trigger_a_later_success(self):
        report = analyze([
            record("10:00:00"),
            record("10:02:01", outcome="Accepted"),
        ], Rules(success_min_failures=1))
        self.assertEqual(report.alerts, [])


class ReportTests(unittest.TestCase):
    def test_escapes_untrusted_log_values(self):
        report = analyze([record("10:00:00", account="<img>&\x1b[31m")], Rules(min_failures=1))
        self.assertIn("&lt;img&gt;&amp;", render_html(report))
        self.assertNotIn("<img>", render_html(report))
        self.assertNotIn("\x1b", render_text(report))
        self.assertIn(r"\x1b", render_text(report))

    def test_empty_report(self):
        html = render_html(analyze([]))
        self.assertIn("No supported authentication events were parsed", html)
        self.assertIn("No findings matched", html)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-B", "-m", "ssh_auth_triage", *args],
            cwd=ROOT,
            capture_output=True,
            encoding="utf-8",
            check=False,
        )

    def test_sample_json_and_alert_exit_code(self):
        result = self.run_cli("samples/sshd.log", "--format", "json", "--fail-on-alert")
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["summary"]["auth_events"], 13)
        self.assertEqual([alert["rule"] for alert in report["alerts"]], ["repeated_failures", "success_after_failures"])
        self.assertEqual(report["alerts"][1]["source_ip"], "2001:db8::7")

    def test_html_output_never_overwrites_an_existing_file(self):
        output = ROOT / f".triage-test-{uuid4().hex}.html"
        self.addCleanup(output.unlink, missing_ok=True)
        args = ("samples/sshd.log", "--format", "html", "--output", str(output))
        first = self.run_cli(*args)
        self.assertEqual(first.returncode, 0, first.stderr)
        contents = output.read_text(encoding="utf-8")
        self.assertIn("Findings timeline", contents)
        self.assertIn("Successful login after failures", contents)
        second = self.run_cli(*args)
        self.assertEqual(second.returncode, 2, second.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), contents)
