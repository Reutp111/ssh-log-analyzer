
import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

FAILED_PATTERN = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_PATTERN = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)")


def parse_log_file(path: Path):
    failed_by_ip = Counter()
    failed_by_user = Counter()
    success_by_user = Counter()

    with path.open("r", errors="ignore") as f:
        for line in f:
            m_fail = FAILED_PATTERN.search(line)
            if m_fail:
                user = m_fail.group("user")
                ip = m_fail.group("ip")
                failed_by_ip[ip] += 1
                failed_by_user[user] += 1
                continue

            m_ok = ACCEPTED_PATTERN.search(line)
            if m_ok:
                user = m_ok.group("user")
                success_by_user[user] += 1

    return {
        "failed_by_ip": failed_by_ip,
        "failed_by_user": failed_by_user,
        "success_by_user": success_by_user,
    }


def format_report(stats: dict) -> str:
    lines = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append(f"SSH Log Analysis Report - {now}")
    lines.append("=" * 50)
    lines.append("")

    lines.append("Top failed attempts by IP:")
    if stats["failed_by_ip"]:
        for ip, count in stats["failed_by_ip"].most_common(10):
            lines.append(f"  {ip:>15}  ->  {count} failed attempts")
    else:
        lines.append("  (no failed attempts found)")
    lines.append("")

    lines.append("Top failed attempts by username:")
    if stats["failed_by_user"]:
        for user, count in stats["failed_by_user"].most_common(10):
            lines.append(f"  {user:>15}  ->  {count} failed attempts")
    else:
        lines.append("  (no failed attempts found)")
    lines.append("")

    lines.append("Successful logins by username:")
    if stats["success_by_user"]:
        for user, count in stats["success_by_user"].most_common(10):
            lines.append(f"  {user:>15}  ->  {count} successful logins")
    else:
        lines.append("  (no successful logins found)")
    lines.append("")

    # זיהוי brute-force בסיסי
    lines.append("Potential brute-force sources (>= 10 failures from same IP):")
    found = False
    for ip, count in stats["failed_by_ip"].items():
        if count >= 10:
            lines.append(f"  {ip:>15}  ->  {count} failures")
            found = True
    if not found:
        lines.append("  (none detected)")
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Analyze SSH log files for failed/successful logins.")
    parser.add_argument(
        "--log-file",
        default="/var/log/auth.log",
        help="Path to SSH log file (default: /var/log/auth.log)",
    )
    parser.add_argument(
        "--output",
        default="output/ssh_report.txt",
        help="Path to output report file (default: output/ssh_report.txt)",
    )
    args = parser.parse_args()

    log_path = Path(args.log_file)
    if not log_path.exists():
        raise SystemExit(f"Log file not found: {log_path}")

    stats = parse_log_file(log_path)
    report = format_report(stats)

    print(report)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report)
    print(f"\n[+] Report saved to {out_path}")


if __name__ == "__main__":
    main()
