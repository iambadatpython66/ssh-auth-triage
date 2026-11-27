"""Read authentication events from OpenSSH syslog records."""

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone


SYSLOG_ROW = re.compile(
    r"(?P<stamp>\S+|[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:-session|-auth)?(?:\[[0-9]+\])?:\s+(?P<message>.*)"
)
AUTH_MESSAGE = re.compile(
    r"(?P<outcome>Accepted|Failed) \S+ for (?:invalid user )?"
    r"(?P<account>\S+) from (?P<address>\S+) port [0-9]+(?:\s.*)?"
)
MONTHS = {
    name: number
    for number, name in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)
}


@dataclass(frozen=True, slots=True)
class AuthEvent:
    timestamp: datetime
    host: str
    source_ip: str
    account: str
    accepted: bool
    line_number: int


@dataclass(frozen=True, slots=True)
class ParsedLog:
    events: list[AuthEvent]
    lines_read: int
    ignored_lines: int
    malformed_lines: int


def _parse_time(stamp: str, year: int | None, zone: timezone) -> datetime:
    if " " in stamp:
        month, day, clock = stamp.split()
        if year is None or month not in MONTHS:
            raise ValueError("classic syslog timestamp needs a year and an English month")
        hour, minute, second = map(int, clock.split(":"))
        return datetime(year, MONTHS[month], int(day), hour, minute, second, tzinfo=zone)

    parsed = datetime.fromisoformat(stamp)
    if parsed.tzinfo is None:
        raise ValueError("ISO timestamp needs a UTC offset")
    return parsed


def read_log(
    lines: Iterable[str],
    *,
    syslog_year: int | None = None,
    syslog_zone: timezone = timezone.utc,
) -> ParsedLog:
    events: list[AuthEvent] = []
    lines_read = 0
    malformed_lines = 0

    for lines_read, line in enumerate(lines, start=1):
        row = SYSLOG_ROW.fullmatch(line.rstrip("\r\n"))
        if row is None or not row["message"].startswith(("Accepted ", "Failed ")):
            continue
        match = AUTH_MESSAGE.fullmatch(row["message"])
        if match is None:
            malformed_lines += 1
            continue
        if " " in row["stamp"] and syslog_year is None:
            raise ValueError(f"line {lines_read} uses classic syslog. Provide --syslog-year YEAR.")

        try:
            timestamp = _parse_time(row["stamp"], syslog_year, syslog_zone).astimezone(timezone.utc)
            source_ip = str(ipaddress.ip_address(match["address"]))
        except (ValueError, OverflowError):
            malformed_lines += 1
            continue

        events.append(AuthEvent(
            timestamp=timestamp,
            host=row["host"].lower(),
            source_ip=source_ip,
            account=match["account"],
            accepted=match["outcome"] == "Accepted",
            line_number=lines_read,
        ))

    return ParsedLog(events, lines_read, lines_read - len(events) - malformed_lines, malformed_lines)
