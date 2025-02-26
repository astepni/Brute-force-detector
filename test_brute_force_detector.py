from typing import Any
from pathlib import Path
import pytest
from main import BruteForceDetector

@pytest.fixture
def sample_log_file(tmp_path: Path):
    log_file = tmp_path / "test_logs.txt"
    log_file.write_text(
        "2025-02-26 13:00:00,192.168.1.1,FAILED\n"
        "2025-02-26 13:00:01,192.168.1.1,FAILED\n"
        "2025-02-26 13:00:02,192.168.1.1,FAILED\n"
        "2025-02-26 13:00:03,192.168.1.1,FAILED\n"
        "2025-02-26 13:00:04,192.168.1.1,FAILED\n"
        "2025-02-26 13:00:05,192.168.1.2,FAILED\n"
    )
    return log_file

def test_parse_logs(sample_log_file: Any):
    detector = BruteForceDetector(str(sample_log_file))
    detector.parse_logs()
    assert len(detector.login_attempts) == 2
    assert len(detector.login_attempts['192.168.1.1']) == 5
    assert len(detector.login_attempts['192.168.1.2']) == 1

def test_detect_brute_force(sample_log_file: Any):
    detector = BruteForceDetector(str(sample_log_file))
    suspicious_ips = detector.detect_brute_force(threshold=4, time_window=10)
    assert suspicious_ips == ['192.168.1.1']

def test_no_brute_force(sample_log_file: Any):
    detector = BruteForceDetector(str(sample_log_file))
    suspicious_ips = detector.detect_brute_force(threshold=10, time_window=10)
    assert suspicious_ips == []

def test_print_summary(sample_log_file: Any, capsys: pytest.CaptureFixture[str]):
    detector = BruteForceDetector(str(sample_log_file))
    suspicious_ips = ['192.168.1.1', '192.168.1.2']
    detector.print_summary(suspicious_ips)
    captured = capsys.readouterr()
    assert "Przeanalizowano plik logów:" in captured.out
    assert "Znaleziono 2 podejrzanych adresów IP:" in captured.out
    assert "- 192.168.1.1" in captured.out
    assert "- 192.168.1.2" in captured.out
