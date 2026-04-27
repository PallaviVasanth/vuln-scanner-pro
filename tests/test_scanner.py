import pytest

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.web.xss_scanner import XSSScanner
from scanner.web.sql_injection import SQLInjectionScanner
from scanner.web.csrf_checker import CSRFChecker
from scanner.web.open_redirect import OpenRedirectScanner
from scanner.web.dir_traversal import DirectoryTraversalScanner
from scanner.web.header_checker import HeaderChecker

from scanner.network.port_scanner import PortScanner
from scanner.network.ssl_checker import SSLChecker

from scanner.scanner_manager import ScannerManager


TEST_TARGET = "http://testphp.vulnweb.com"


# -------------------------------
# 🔹 Helper: Validate API Contract
# -------------------------------
def validate_contract(finding):
    required_keys = [
        "type",
        "endpoint",
        "payload",
        "method",
        "evidence",
        "status_code",
        "response_time",
        "error_detected",
        "payload_reflected"
    ]

    for key in required_keys:
        assert key in finding, f"Missing key: {key}"


# -------------------------------
# 🔹 UNIT TESTS (WEB SCANNERS)
# -------------------------------

def test_xss_scanner():
    scanner = XSSScanner(TEST_TARGET)
    results = scanner.scan()

    assert isinstance(results, list)

    for r in results:
        validate_contract(r)


def test_sqli_scanner():
    scanner = SQLInjectionScanner(TEST_TARGET)
    results = scanner.scan()

    assert isinstance(results, list)

    for r in results:
        validate_contract(r)


def test_csrf_checker():
    scanner = CSRFChecker(TEST_TARGET)
    results = scanner.scan()

    assert isinstance(results, list)

    for r in results:
        validate_contract(r)


def test_open_redirect():
    scanner = OpenRedirectScanner(TEST_TARGET)
    results = scanner.scan()

    assert isinstance(results, list)

    for r in results:
        validate_contract(r)


def test_dir_traversal():
    scanner = DirectoryTraversalScanner(TEST_TARGET)
    results = scanner.scan()

    assert isinstance(results, list)

    for r in results:
        validate_contract(r)


def test_header_checker():
    scanner = HeaderChecker(TEST_TARGET)
    results = scanner.scan()

    assert isinstance(results, list)

    for r in results:
        validate_contract(r)


# -------------------------------
# 🔹 UNIT TESTS (NETWORK)
# -------------------------------

def test_port_scanner():
    scanner = PortScanner("scanme.nmap.org")  # safe public target
    results = scanner.scan()

    assert isinstance(results, list)

    for r in results:
        validate_contract(r)


def test_ssl_checker():
    scanner = SSLChecker("https://google.com")
    results = scanner.scan()

    assert isinstance(results, list)

    for r in results:
        validate_contract(r)


# -------------------------------
# 🔹 INTEGRATION TEST
# -------------------------------

def test_scanner_manager():
    manager = ScannerManager(TEST_TARGET)
    results = manager.run()

    assert isinstance(results, list)

    for r in results:
        validate_contract(r)

        # ML fields check
        assert "prediction" in r
        assert "confidence" in r
        assert "is_vulnerable" in r


# -------------------------------
# 🔹 EDGE CASE TEST
# -------------------------------

def test_invalid_url():
    manager = ScannerManager("http://invalid.localhost.test")
    results = manager.run()

    # should not crash
    assert isinstance(results, list)