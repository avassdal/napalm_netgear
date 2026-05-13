"""Tests for compare_config."""

import os
import pytest
from conftest import PatchedNetgearDriver, FakeNetgearDevice


VARIANTS = ["m4250", "m4350", "m4500"]
MOCK_BASE = os.path.join(os.path.dirname(__file__), "mocked_data")


def make_driver(test_name, variant):
    driver = PatchedNetgearDriver("192.0.2.99", "admin", "admin")
    dev = FakeNetgearDevice()
    dev.current_test = test_name
    dev.current_test_case = variant
    driver.device = dev
    return driver


@pytest.mark.parametrize("variant", VARIANTS)
def test_compare_config_no_candidate(variant):
    """compare_config returns empty string when no candidate is loaded."""
    driver = make_driver("test_get_config", variant)
    driver.config = ""
    assert driver.compare_config() == ""


@pytest.mark.parametrize("variant", VARIANTS)
def test_compare_config_identical(variant):
    """compare_config returns empty string when candidate matches running config."""
    driver = make_driver("test_get_config", variant)
    running = driver.get_config(retrieve="running")["running"]
    driver.config = running
    assert driver.compare_config() == ""


@pytest.mark.parametrize("variant", VARIANTS)
def test_compare_config_diff(variant):
    """compare_config returns a unified diff when candidate differs from running."""
    driver = make_driver("test_get_config", variant)
    running = driver.get_config(retrieve="running")["running"]
    candidate = running + "\nsnmp-server sysname \"new-hostname\"\n"
    driver.config = candidate
    result = driver.compare_config()
    assert result != ""
    assert result.startswith("---")
    assert "+++" in result
    assert "+snmp-server sysname" in result
