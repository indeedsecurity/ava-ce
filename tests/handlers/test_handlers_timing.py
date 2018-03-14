import pytest
from ava.actives.shell_injection import ShellInjectionTimingCheck
from ava.common.check import _TimingCheck
from ava.handlers.timing import _TimingHandler


@pytest.fixture
def vector():
    vector = {
        "url": "http://www.avascan.com/",
        "method": "get",
        "params": {"param": "avascan"},
        "cookies": {},
        "headers": {}
    }

    return vector


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestTimingHandler:

    @pytest.fixture
    def handler(self):
        return _TimingHandler({'skips': []}, [], {})

    def test_init(self, handler):
        assert handler.handles == _TimingCheck

    def test_execute_check_positive(self, handler, vector, response, mocker):
        check = ShellInjectionTimingCheck()
        auditable = {'vectors': {'original': vector, 'timing': vector},
                     'target': "param",
                     'payload': check._payloads[0][0], 'value': check._payloads[0][0],
                     'delay': 9.00}
        issue = {'auditor': "response",
                 'check': "pii.passive.body",
                 'vector': vector,
                 'target': "email",
                 'value': "email@example.com",
                 'time': "00:00:00.1",
                 'http': "200 OK"}

        # mock
        mocker.patch("ava.handlers.timing._TimingHandler._get_targets", return_value=['param'])
        mocker.patch("ava.handlers.timing._TimingHandler._generate_variations", return_value=[auditable])
        mocker.patch("ava.common.handler._Handler._send_request", return_value=response)
        mocker.patch("ava.actives.shell_injection.ShellInjectionTimingCheck.check", return_value=True)
        mocker.patch("ava.common.handler._Handler._print_status")
        mocker.patch("ava.common.handler._Handler._generate_issue", return_value=issue)

        # issue
        test = handler.execute_check(check, [vector])
        assert test == [issue]

        # no issue
        mocker.patch("ava.actives.shell_injection.ShellInjectionTimingCheck.check", return_value=False)
        test = handler.execute_check(check, [vector])
        assert test == []

    def test_execute_check_negative(self, handler, vector, mocker):
        check = ShellInjectionTimingCheck()
        auditable = {'vectors': {'original': vector, 'timing': vector}, 'value': check._payloads[0][0]}

        # no targets
        mocker.patch("ava.handlers.timing._TimingHandler._get_targets", return_value=[])
        test = handler.execute_check(check, [vector])
        assert test == []

        # no response
        mocker.patch("ava.handlers.timing._TimingHandler._get_targets", return_value=['param'])
        mocker.patch("ava.handlers.timing._TimingHandler._generate_variations", return_value=[auditable])
        mocker.patch("ava.common.handler._Handler._send_request", return_value=None)
        test = handler.execute_check(check, [vector])
        assert test == []

    def test_get_targets(self, handler):
        """implemented by children"""
        test = handler._get_targets({})
        assert test == []

    def test_timing_generate_variations(self, handler):
        # implemented by children
        test = handler._generate_variations(None, None, "")
        assert test == []
