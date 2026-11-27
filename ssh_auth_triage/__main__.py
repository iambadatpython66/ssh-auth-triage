"""Command-line entry point for SSH Auth Triage."""

import argparse
import re
import sys
from datetime import timedelta, timezone
from pathlib import Path

from .detect import Rules, detect_alerts
from .parser import read_log
from .report import build_report, render_html, render_json, render_text, terminal_text


FORMATS = {"text": render_text, "json": render_json, "html": render_html}


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def _offset(value: str) -> timezone:
    match = re.fullmatch(r"([+-])([0-9]{2}):([0-9]{2})", value)
    if match is None or int(match[2]) > 23 or int(match[3]) > 59:
        raise argparse.ArgumentTypeError("expected a UTC offset such as +04:00")
    delta = timedelta(hours=int(match[2]), minutes=int(match[3]))
    return timezone(-delta if match[1] == "-" else delta)


def main(argv: list[str] | None = None) -> int:
    defaults = Rules()
    parser = argparse.ArgumentParser(description="Triage a local OpenSSH authentication log.")
    parser.add_argument("logfile", type=Path, help="UTF-8 OpenSSH auth log or syslog export")
    parser.add_argument("--format", choices=FORMATS, default="text", help="report format (default: text)")
    parser.add_argument("--output", type=Path, help="write to a new file instead of stdout")
    parser.add_argument("--window-seconds", type=_positive_int, default=defaults.window_seconds,
                        help="rolling window length (default: %(default)s)")
    parser.add_argument("--min-failures", type=_positive_int, default=defaults.min_failures,
                        help="threshold for repeated failures (default: %(default)s)")
    parser.add_argument("--success-min-failures", type=_positive_int, default=defaults.success_min_failures,
                        help="failures before a matching success (default: %(default)s)")
    parser.add_argument("--syslog-year", type=_positive_int, help="year for classic syslog lines")
    parser.add_argument("--syslog-offset", type=_offset, default=timezone.utc,
                        help="fixed UTC offset for classic syslog lines (default: +00:00)")
    parser.add_argument("--fail-on-alert", action="store_true", help="exit with status 1 when findings exist")
    args = parser.parse_args(argv)
    if args.syslog_year is not None and args.syslog_year > 9999:
        parser.error("--syslog-year must be between 1 and 9999")

    rules = Rules(args.window_seconds, args.min_failures, args.success_min_failures)
    try:
        with args.logfile.open(encoding="utf-8-sig") as log:
            parsed = read_log(log, syslog_year=args.syslog_year, syslog_zone=args.syslog_offset)
        alerts = detect_alerts(parsed.events, rules)
        report = FORMATS[args.format](build_report(parsed, rules, alerts)).rstrip()
        if args.output is None:
            print(report)
        else:
            with args.output.open("x", encoding="utf-8") as output:
                output.write(report + "\n")
    except (OSError, ValueError) as error:
        print(f"error: {terminal_text(str(error))}", file=sys.stderr)
        return 2

    return int(args.fail_on_alert and bool(alerts))


if __name__ == "__main__":
    raise SystemExit(main())
