# ssh-log-analyzer

A small Python tool to analyze SSH log files (e.g. `/var/log/auth.log`) and
summarize failed/successful login attempts by IP and username.

## Features

- Count failed SSH login attempts per IP
- Count successful SSH logins per username
- Detect potential brute-force sources (many failures from same IP)
- Export summary to a text report

## Usage

```bash
python3 -m src.ssh_log_analyzer --log-file /var/log/auth.log --output output/report.txt
