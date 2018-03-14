import pytest
import base64
import requests
from requests.exceptions import Timeout, ConnectionError, TooManyRedirects
from ava.actives.xss import CrossSiteScriptingCheck
from ava.auditors.parameter import QueryParameterAuditor
from ava.common.handler import _Handler


@pytest.fixture
def response():
    return type("Response", (object,), {})


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.example.com",
        'method': "GET",
        'params': {'ava': "avascan"},
        'cookies': {},
        'headers': {}
    }

    return vector


class TestHandler:

    def test_execute_check(self):
        # empty method
        handler = _Handler({}, "", None)
        test = handler.execute_check(None, [])
        assert test == []

    def test_filter_skips(self):
        # with skips
        handler = _Handler({'skips': ["token"]}, "", None)
        test = handler._filter_skips(["ava", "token", "cookie", "param"])
        assert sorted(test) == ["ava", "cookie", "param"]

        # with skips no match
        handler = _Handler({'skips': ["SESSIONID"]}, "", None)
        test = handler._filter_skips(["ava", "token", "cookie", "param"])
        assert sorted(test) == ["ava", "cookie", "param", "token"]

        # without skips
        handler = _Handler({'skips': []}, "", None)
        test = handler._filter_skips(["ava", "token", "cookie", "param"])
        assert sorted(test) == ["ava", "cookie", "param", "token"]

    def test_filter_ignores(self):
        matches = [('email', 'email@example.com')]

        # no ignores
        handler = _Handler({'ignores': []}, '', None)
        test = handler._filter_ignores(matches)
        assert test == matches

        # ignores do match
        handler = _Handler({'ignores': ['email@example.com']}, '', None)
        test = handler._filter_ignores(matches)
        assert test == []

        # ignores does not match
        handler = _Handler({'ignores': ['csrftoken']}, '', None)
        test = handler._filter_ignores(matches)
        assert test == matches

        # no matches
        handler = _Handler({'ignores': ['email@example.com']}, '', None)
        test = handler._filter_ignores([])
        assert test == []

    def test_send_request_positive(self, vector, response, mocker):
        configs = {'agent': "AVA/1.22.1", 'timeout': 30, 'proxy': None}
        handler = _Handler(configs, "", requests.Session())

        # valid get
        mocker.patch("ava.common.utility.send_http_request", return_value=response)
        test = handler._send_request(vector)
        assert test == response

        # valid post
        mocker.patch("ava.common.utility.send_http_request", return_value=response)
        vector['method'] = "POST"
        test = handler._send_request(vector)
        assert test == response

    def test_send_request_negative(self, vector, mocker):
        configs = {'agent': "AVA/1.22.1", 'timeout': 30, 'proxy': "127.0.0.1:8080"}
        handler = _Handler(configs, "", requests.Session())

        # Timeout
        mocker.patch("ava.common.utility.send_http_request", side_effect=Timeout)
        test = handler._send_request(vector)
        assert not test

        # ConnectionError
        mocker.patch("ava.common.utility.send_http_request", side_effect=ConnectionError)
        test = handler._send_request(vector)
        assert not test

        # ConnectionResetError
        mocker.patch("ava.common.utility.send_http_request", side_effect=ConnectionResetError)
        test = handler._send_request(vector)
        assert not test

        # TooManyRedirects
        mocker.patch("ava.common.utility.send_http_request", side_effect=TooManyRedirects)
        test = handler._send_request(vector)
        assert not test

    def test_print_status(self, caplog):
        handler = _Handler({}, QueryParameterAuditor, None)
        check = CrossSiteScriptingCheck()

        # vulnerable
        handler._print_status(True, check, "https://www.example.com/", "ava", "avascan")
        assert caplog.records[0].levelname == 'INFO'

        # not vulnerable
        handler._print_status(False, check, "https://www.example.com/", "ava", "avascan")
        assert caplog.records[1].levelname == 'DEBUG'

    def test_handler_generate_issue(self, vector, response, mocker):
        handler = _Handler({}, QueryParameterAuditor, None)
        check = CrossSiteScriptingCheck()
        response.text = "<html><head></head><body>{}</body></html>".format(check._payloads[0])
        response.elapsed = "00:00:00.1"

        # mock
        mocker.patch("requests_toolbelt.utils.dump.dump_all", return_value=response.text.encode())

        # generated
        generated = {
            'auditor': QueryParameterAuditor.key,
            'check': check.key,
            'vector': vector,
            'target': "param",
            'value': check._payloads[0],
            'time': response.elapsed,
            'http': base64.b64encode(response.text.encode()).decode()
        }

        # issue
        test = handler._generate_issue(check, vector, "param", check._payloads[0], response)
        assert test == generated
