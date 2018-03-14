import pytest
from ava.common.auditor import _Auditor
from ava.common.check import _ValueCheck, _DifferentialCheck, _TimingCheck, _BlindCheck, _PassiveCheck
from ava.handlers.value import _ValueHandler
from ava.handlers.differential import _DifferentialHandler
from ava.handlers.timing import _TimingHandler
from ava.handlers.blind import _BlindHandler
from ava.handlers.passive import _PassiveHandler


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.example.com",
        'method': "get",
        'params': {'ava': "avascan"},
        'cookies': {},
        'headers': {}
    }

    return vector


@pytest.fixture
def issue(vector):
    issue = {
        'auditor': "Parameters",
        'check': None,
        'vector': vector,
        'target': "param",
        'value': None,
        'request': {"url": vector["url"], "method": vector["method"], "headers": [], "body": ""},
        'response': {"code": 200, "reason": "OK", "headers": [], "body": "<html><avascan></avascan></html>"}
    }

    return issue


class TestAuditor:

    @pytest.fixture
    def auditor(self, vector):
        return _Auditor({'processes': 1, 'threads': 3}, [_ValueCheck(), _TimingCheck()], [vector, vector, vector])

    def test_get_handler_supported(self, auditor):
        # simple handler
        handler = _ValueHandler({}, '', None)
        auditor._handlers = [handler]
        test = auditor._get_handler(_ValueCheck())
        assert test == handler

        # differential handler
        handler = _DifferentialHandler({}, '', None)
        auditor._handlers = [handler]
        test = auditor._get_handler(_DifferentialCheck())
        assert test == handler

        # timing handler
        handler = _TimingHandler({}, '', None)
        auditor._handlers = [handler]
        test = auditor._get_handler(_TimingCheck())
        assert test == handler

        # blind handler
        handler = _BlindHandler({}, '', None)
        auditor._handlers = [handler]
        test = auditor._get_handler(_BlindCheck())
        assert test == handler

        # passive handler
        handler = _PassiveHandler({}, '', None)
        auditor._handlers = [handler]
        test = auditor._get_handler(_PassiveCheck())
        assert test == handler

    def test_get_handler_not_supported(self, auditor):
        # not supported
        auditor._handlers = [_ValueHandler({}, '', None)]
        test = auditor._get_handler(_DifferentialCheck())
        assert test is None

    def test_execute_cluster_with_handler(self, auditor, issue, mocker):
        # with handler with issues
        mocker.patch("ava.handlers.value._ValueHandler.execute_check", return_value=[issue])

        auditor._handlers = [_ValueHandler({}, '', None)]
        test = auditor._execute_cluster(auditor._checks[0])
        assert test == [issue, issue, issue]

        # with handler without issues
        mocker.patch("ava.handlers.value._ValueHandler.execute_check", return_value=[])

        auditor._handlers = [_ValueHandler({}, '', None)]
        test = auditor._execute_cluster(auditor._checks[0])
        assert test == []

    def test_execute_cluster_without_handler(self, auditor):
        # without handler
        auditor._handlers = [_ValueHandler({}, '', None)]
        test = auditor._execute_cluster(auditor._checks[1])
        assert test == []

    def test_auditor_run(vector, auditor, issue, mocker):
        auditor._handlers = [_ValueHandler({}, '', None)]

        # with issues
        mocker.patch("ava.handlers.value._ValueHandler.execute_check", return_value=[issue])
        test = auditor.run()
        assert test == [issue, issue, issue]

        # without issues
        mocker.patch("ava.handlers.value._ValueHandler.execute_check", return_value=[])
        test = auditor.run()
        assert test == []
