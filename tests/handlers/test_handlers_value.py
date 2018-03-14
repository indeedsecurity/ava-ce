import pytest
from ava.actives.xss import CrossSiteScriptingCheck
from ava.common.check import _ValueCheck
from ava.handlers.value import _ValueHandler


@pytest.fixture
def vector():
    vector = {
        "url": "http://www.example.com/",
        "method": "get",
        "params": {"param": "avascan"},
        "cookies": {},
        "headers": {}
    }

    return vector


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestValueHandler:

    @pytest.fixture
    def handler(self):
        return _ValueHandler({'skips': []}, [], {})

    def test_init(self, handler):
        assert handler.handles == _ValueCheck

    def test_execute_check_positive(self, handler, vector, response, mocker):
        check = CrossSiteScriptingCheck()
        auditable = {'vector': vector,
                     'target': "param",
                     'payload': check._payloads[0],
                     'value': check._payloads[0]}
        issue = {'auditor': "parameter",
                 'check': "xss.value.tag",
                 'vector': vector,
                 'target': "param",
                 'value': "<avascan></avascan>",
                 'time': "00:00:00.1",
                 'http': "200 OK"}

        # mock
        mocker.patch("ava.handlers.value._ValueHandler._get_targets", return_value=['param'])
        mocker.patch("ava.handlers.value._ValueHandler._generate_variations", return_value=[auditable])
        mocker.patch("ava.common.handler._Handler._send_request", return_value=response)
        mocker.patch("ava.actives.xss.CrossSiteScriptingCheck.check", return_value=True)
        mocker.patch("ava.common.handler._Handler._print_status")
        mocker.patch("ava.common.handler._Handler._generate_issue", return_value=issue)

        # issue
        test = handler.execute_check(check, [vector])
        assert test == [issue]

        # no issue
        mocker.patch("ava.actives.xss.CrossSiteScriptingCheck.check", return_value=False)
        test = handler.execute_check(check, [vector])
        assert test == []

    def test_execute_check_negative(self, handler, vector, mocker):
        check = CrossSiteScriptingCheck()
        auditable = {'vector': vector}

        # no targets
        mocker.patch("ava.handlers.value._ValueHandler._get_targets", return_value=[])
        test = handler.execute_check(check, [vector])
        assert test == []

        # no response
        mocker.patch("ava.handlers.value._ValueHandler._get_targets", return_value=['param'])
        mocker.patch("ava.handlers.value._ValueHandler._generate_variations", return_value=[auditable])
        mocker.patch("ava.common.handler._Handler._send_request", return_value=None)
        test = handler.execute_check(check, [vector])
        assert test == []

    def test_get_targets(self, handler):
        """implemented by children"""
        test = handler._get_targets({})
        assert test == []

    def test_generate_variations(self, handler):
        # implemented by children
        test = handler._generate_variations(None, None, "")
        assert test == []
