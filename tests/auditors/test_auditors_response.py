import pytest
from ava.auditors.response import ResponseAuditor, _ResponsePassiveHandler


class TestResponseAuditor:

    @pytest.fixture
    def auditor(self):
        return ResponseAuditor({}, [], [])

    def test_init(self, auditor):
        assert isinstance(auditor._handlers[0], _ResponsePassiveHandler)
