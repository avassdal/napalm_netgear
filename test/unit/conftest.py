"""Test fixtures."""

from builtins import super

import pytest
from napalm.base.test import conftest as parent_conftest

from napalm.base.test.double import BaseTestDouble
from napalm_netgear import netgear


@pytest.fixture(scope="class")
def set_device_parameters(request):
    """Set up the class."""

    def fin():
        request.cls.device.close()

    request.addfinalizer(fin)

    request.cls.driver = netgear.NetgearDriver
    request.cls.patched_driver = PatchedNetgearDriver
    request.cls.vendor = "netgear"
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedNetgearDriver(netgear.NetgearDriver):
    """Patched Netgear Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ["device"]
        self.device = FakeNetgearDevice()

    def disconnect(self):
        pass

    def is_alive(self):
        return {"is_alive": True}  # In testing everything works..

    def open(self):
        pass

    def close(self):
        pass


class FakeNetgearDevice(BaseTestDouble):
    """Netgear device test double."""

    def send_command_timing(self, command, **kwargs):
        """Fake send_command_timing."""
        filename = "{}.txt".format(self.sanitize_text(command))
        full_path = self.find_file(filename)
        result = self.read_txt_file(full_path)
        return str(result)

    def disconnect(self):
        pass
