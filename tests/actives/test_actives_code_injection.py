import pytest
from ava.actives.code_injection import PythonCodeInjectionTimingCheck


class TestPythonCodeInjectionTiming:
    payloads = [
        ("__import__('time').sleep(9)", 9.00),
        ("__import__('os').system('sleep 9')", 9.00),
        ('gANjdGltZQpzbGVlcApxAEsJhXEBUnECLg==', 9.00),
        ('gANjcG9zaXgKc3lzdGVtCnEAWAcAAABzbGVlcCA5cQGFcQJScQMu', 9.00)
    ]

    @pytest.fixture
    def check(self):
        return PythonCodeInjectionTimingCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads
