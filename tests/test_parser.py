from pathlib import Path
from src.ssh_log_analyzer import parse_log_file


def test_parse_sample_log():
    sample = Path("sample_logs/auth_sample.log")
    stats = parse_log_file(sample)

    failed_by_ip = stats["failed_by_ip"]

    assert failed_by_ip
    assert isinstance(failed_by_ip, dict)
