"""Tests for GS-series getters."""

import os
import json
import pytest

from napalm.base.test.double import BaseTestDouble
from napalm_netgear import netgear


GS_MOCK_BASE = os.path.join(os.path.dirname(__file__), "gs_mocked_data")


class FakeGSDevice(BaseTestDouble):
    """GS-series device test double."""

    def send_command_timing(self, command, **kwargs):
        """Fake send_command_timing."""
        filename = "{}.txt".format(self.sanitize_text(command))
        full_path = self.find_file(filename)
        result = self.read_txt_file(full_path)
        return str(result)

    def disconnect(self):
        pass


class PatchedGSDriver(netgear.NetgearDriver):
    """Patched GS-series driver with platform pre-set."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)
        self.patched_attrs = ["device"]
        self.device = FakeGSDevice()
        self._platform_type = "gs_series"
        self._gs_port_count = 8

    def open(self):
        pass

    def close(self):
        pass

    def is_alive(self):
        return {"is_alive": True}


def _load_expected(test_name, scenario="gs108tv3"):
    """Load expected_result.json for a given test."""
    path = os.path.join(GS_MOCK_BASE, test_name, scenario, "expected_result.json")
    with open(path) as f:
        return json.load(f)


def _create_driver(test_name, scenario="gs108tv3"):
    """Create a PatchedGSDriver pointed at the correct mock data directory."""
    driver = PatchedGSDriver("localhost", "admin", "password")
    # Point the fake device at the correct mock data directory
    driver.device.device_type = "netgear"
    driver.device.current_test = test_name
    driver.device.current_test_case = scenario
    # Set the mock data path
    driver.device.mock_data_dir = os.path.join(GS_MOCK_BASE, test_name, scenario)
    return driver


class TestGetterGS:
    """Test GS-series getters against mock data."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test driver."""
        self.driver_cls = PatchedGSDriver

    def _get_driver(self, test_name):
        """Get a driver configured for the given test."""
        driver = PatchedGSDriver("localhost", "admin", "password")
        # BaseTestDouble uses find_file which needs these attributes
        driver.device.device_type = "netgear"
        # We need to set the test context so find_file looks in the right directory
        test_dir = os.path.join(GS_MOCK_BASE, test_name, "gs108tv3")
        # Override find_file to look in our GS mock directory
        original_find = driver.device.find_file

        def patched_find(filename):
            path = os.path.join(test_dir, filename)
            if os.path.exists(path):
                return path
            return original_find(filename)

        driver.device.find_file = patched_find
        return driver

    def test_get_facts(self):
        device = self._get_driver("test_get_facts")
        result = device.get_facts()
        expected = _load_expected("test_get_facts")
        assert result["vendor"] == expected["vendor"]
        assert result["model"] == expected["model"]
        assert result["hostname"] == expected["hostname"]
        assert result["os_version"] == expected["os_version"]
        assert result["serial_number"] == expected["serial_number"]
        assert sorted(result["interface_list"]) == sorted(expected["interface_list"])

    def test_get_interfaces(self):
        device = self._get_driver("test_get_interfaces")
        result = device.get_interfaces()
        expected = _load_expected("test_get_interfaces")
        assert set(result.keys()) == set(expected.keys())
        for iface in expected:
            assert result[iface]["is_up"] == expected[iface]["is_up"]

    def test_get_interfaces_counters(self):
        device = self._get_driver("test_get_interfaces_counters")
        result = device.get_interfaces_counters()
        expected = _load_expected("test_get_interfaces_counters")
        assert set(result.keys()) == set(expected.keys())
        for iface in expected:
            for key in expected[iface]:
                assert result[iface][key] == expected[iface][key], \
                    f"{iface}.{key}: {result[iface][key]} != {expected[iface][key]}"

    def test_get_mac_address_table(self):
        device = self._get_driver("test_get_mac_address_table")
        result = device.get_mac_address_table()
        expected = _load_expected("test_get_mac_address_table")
        assert len(result) == len(expected)

    def test_get_lldp_neighbors(self):
        device = self._get_driver("test_get_lldp_neighbors")
        result = device.get_lldp_neighbors()
        expected = _load_expected("test_get_lldp_neighbors")
        assert set(result.keys()) == set(expected.keys())

    def test_get_lldp_neighbors_detail(self):
        device = self._get_driver("test_get_lldp_neighbors_detail")
        result = device.get_lldp_neighbors_detail()
        expected = _load_expected("test_get_lldp_neighbors_detail")
        assert set(result.keys()) == set(expected.keys())

    def test_get_environment(self):
        device = self._get_driver("test_get_environment")
        result = device.get_environment()
        expected = _load_expected("test_get_environment")
        assert "cpu" in result
        assert "memory" in result
        if expected.get("cpu"):
            assert result["cpu"] == expected["cpu"]
        if expected["memory"]["available_ram"] != -1:
            assert result["memory"] == expected["memory"]

    def test_get_interfaces_ip(self):
        device = self._get_driver("test_get_interfaces_ip")
        result = device.get_interfaces_ip()
        expected = _load_expected("test_get_interfaces_ip")
        assert result == expected

    def test_get_config(self):
        device = self._get_driver("test_get_config")
        result = device.get_config()
        assert "startup" in result
        assert "running" in result
        assert len(result["startup"]) > 0
        assert len(result["running"]) > 0

    def test_get_config_sanitized(self):
        device = self._get_driver("test_get_config_sanitized")
        result = device.get_config(sanitized=True)
        assert "secret" not in result.get("running", "").lower() or "secret encrypted" not in result.get("running", "")
