import pytest
from ava.actives.sql_injection import SqlInjectionDifferentialCheck
from ava.common.check import _DifferentialCheck
from ava.handlers.differential import _DifferentialHandler


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


class TestDifferentialHandler:

    @pytest.fixture
    def handler(self):
        return _DifferentialHandler({"skips": []}, [], {})

    def test_init(self, handler):
        assert handler.handles == _DifferentialCheck

    def test_execute_check_positive(self, handler, vector, response, mocker):
        check = SqlInjectionDifferentialCheck()
        auditable = {'vectors': {'true': vector, 'false': vector},
                     'target': "param",
                     'payloads': {'true': check._payloads[0][0], 'false': check._payloads[0][1]},
                     'values': {'true': check._payloads[0][0], 'false': check._payloads[0][1]}}
        issue = {'auditor': "parameter",
                 'check': "sql.value.row",
                 'vector': vector,
                 'target': "param",
                 'value': "' OR '1'='1",
                 'time': "00:00:00.1",
                 'http': "200 OK"}

        # mock
        mocker.patch("ava.handlers.differential._DifferentialHandler._get_targets", return_value=['param'])
        mocker.patch("ava.handlers.differential._DifferentialHandler._generate_variations", return_value=[auditable])
        mocker.patch("ava.common.handler._Handler._send_request", return_value=response)
        mocker.patch("ava.actives.sql_injection.SqlInjectionDifferentialCheck.check", return_value=True)
        mocker.patch("ava.common.handler._Handler._print_status")
        mocker.patch("ava.common.handler._Handler._generate_issue", return_value=issue)

        # issue
        test = handler.execute_check(check, [vector])
        assert test == [issue]

        # no issue
        mocker.patch("ava.actives.sql_injection.SqlInjectionDifferentialCheck.check", return_value=False)
        test = handler.execute_check(check, [vector])
        assert test == []

    def test_execute_check_negative(self, handler, vector, mocker):
        check = SqlInjectionDifferentialCheck()
        auditable = {'vectors': {'true': vector, 'false': vector},
                     'values': {'true': check._payloads[0][0], 'false': check._payloads[0][1]}}

        # no targets
        mocker.patch("ava.handlers.differential._DifferentialHandler._get_targets", return_value=[])
        test = handler.execute_check(check, [vector])
        assert test == []

        # no response
        mocker.patch("ava.handlers.differential._DifferentialHandler._get_targets", return_value=['param'])
        mocker.patch("ava.handlers.differential._DifferentialHandler._generate_variations", return_value=[auditable])
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
