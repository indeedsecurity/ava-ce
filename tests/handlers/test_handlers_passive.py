import pytest
from ava.common.check import _PassiveCheck
from ava.handlers.passive import _PassiveHandler
from ava.passives.pii import PersonallyIdentifiableInformationCheck


@pytest.fixture
def vector():
    vector = {
        "url": "http://www.example.com/",
        "method": "get",
        "params": {"ava": "avascan"},
        "cookies": {},
        "headers": {}
    }

    return vector


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestPassiveHandler:

    @pytest.fixture
    def handler(self):
        return _PassiveHandler({'ignores': []}, [], {})

    def test_init(self, handler):
        assert handler.handles == _PassiveCheck

    def test_execute_check_positive(self, handler, vector, response, mocker):
        check = PersonallyIdentifiableInformationCheck()
        matches = [('email', "email@example.com")]
        issue = {'auditor': "response",
                 'check': "pii.passive.body",
                 'vector': vector,
                 'target': "email",
                 'value': "email@example.com",
                 'time': "00:00:00.1",
                 'http': "200 OK"}

        # mock
        mocker.patch("ava.common.handler._Handler._send_request", return_value=response)
        mocker.patch("ava.passives.pii.PersonallyIdentifiableInformationCheck.check", return_value=matches)
        mocker.patch("ava.common.handler._Handler._print_status")
        mocker.patch("ava.common.handler._Handler._generate_issue", return_value=issue)

        # issue
        test = handler.execute_check(check, [vector])
        assert test == [issue]

        # no issue
        mocker.patch("ava.passives.pii.PersonallyIdentifiableInformationCheck.check", return_value=[])
        test = handler.execute_check(check, [vector])
        assert test == []

    def test_execute_check_negative(self, handler, vector, mocker):
        check = PersonallyIdentifiableInformationCheck()

        # no response
        mocker.patch("ava.common.handler._Handler._send_request", return_value=None)
        test = handler.execute_check(check, [vector])
        assert test == []
