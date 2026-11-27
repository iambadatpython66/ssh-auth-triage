# SSH Auth Triage

A defensive Python tool that reads OpenSSH authentication logs and highlights activity worth investigating. It uses two configurable detection rules and reports the original line numbers for each finding. The analysis runs locally with Python 3.11 or later and uses the standard library.

## Run the demo

From the project folder, run the included synthetic log.

```sh
python -m ssh_auth_triage samples/sshd.log
```

```text
13 auth events across 15 lines (2 ignored, 0 malformed)
2 findings
[MEDIUM] 2026-09-18T10:00:39Z  Repeated login failures
  lab-linux | 198.51.100.42 | 5 failures | admin, backup, root
  Log lines 2, 4, 5, 7, 8
[HIGH] 2026-09-18T10:01:33Z  Successful login after failures
  lab-linux | 2001:db8::7 | 3 failures | ops
  Log lines 10, 11, 12, 14
```

Generate a standalone report and open `triage.html` in a browser. Expand **Log evidence** on either finding to see the supporting line numbers. JSON output is also available for scripting.

```sh
python -m ssh_auth_triage samples/sshd.log --format html --output triage.html
python -m ssh_auth_triage samples/sshd.log --format json --output triage.json
```

## Detection rules

| Finding | Default rule |
| --- | --- |
| Repeated login failures | Flag the threshold crossing when one IP accumulates five failures on one host in 120 seconds. Attempts can span multiple accounts. Once the rolling count drops below five, a later crossing can trigger another finding. |
| Successful login after failures | Flag a success when the same host, IP, and account had at least three failures within the previous 120 seconds. A success clears the account's pending failures for this rule. |

The analyzer normalizes time to UTC and sorts events before applying the rules. Events exactly on the window boundary count. Events with equal timestamps are processed in file order. Findings give you a starting point for review. A user repeatedly mistyping a password or several users sharing an IP can produce similar patterns.

## Analyze your own log

Use a local copy of a UTF-8 OpenSSH syslog export. The parser handles `Accepted` and `Failed` records from `sshd`, `sshd-session`, and `sshd-auth`. It supports IPv4 and IPv6, ISO timestamps with a UTC offset or `Z`, and classic syslog timestamps. For classic logs, specify the year and the offset used by that portion of the file. Run separate files for different years or UTC offsets.

```sh
python -m ssh_auth_triage auth.log --syslog-year 2026 --syslog-offset=+04:00
python -m ssh_auth_triage samples/sshd.log --window-seconds 300 --min-failures 8 --success-min-failures 4
python -m ssh_auth_triage --help
```

The summary shows ignored lines and malformed authentication records. A file with zero parsed events warrants checking the export format before drawing conclusions. Files are analyzed in memory, so use a manageable log export. Keep real logs and reports local when sharing this project. The included sample uses synthetic accounts and documentation IP addresses.

Reports go to stdout by default. `--output` creates a new UTF-8 file. The exit status is `0` after a completed run, `2` on input or argument errors, and `1` when `--fail-on-alert` is set and findings exist.

## Run the tests

```sh
python -m unittest discover -s tests -v
```

The tests exercise timestamp parsing, rolling-window boundaries, source and account correlation, report escaping, and the command-line demo. GitHub Actions runs the suite on Linux and Windows.
