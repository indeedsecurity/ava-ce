import pytest
from ava.blinds.xss import CrossSiteScriptingBlindDirectCheck
from ava.common.check import _BlindCheck
from ava.handlers.blind import _BlindHandler


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.avascan.com/",
        'method': "get",
        'params': {"param": "avascan"},
        'cookies': {},
        'headers': {}
    }

    return vector


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestBlindHandler:

    @pytest.fixture
    def handler(self):
        return _BlindHandler({"skips": []}, [], {})

    def test_init(self, handler):
        assert handler.handles == _BlindCheck

    def test_blind_execute_check_positive(self, handler, vector, response, mocker):
        check = CrossSiteScriptingBlindDirectCheck("http://localhost:8080/")
        auditable = {'vector': vector, 'target': "param", 'payload': check._payloads[0], 'value': check._payloads[0]}

        # mock
        mocker.patch("ava.handlers.blind._BlindHandler._get_targets", return_value=['param'])
        mocker.patch("ava.handlers.blind._BlindHandler._generate_variations", return_value=[auditable])
        mocker.patch("ava.common.handler._Handler._send_request", return_value=response)
        mocker.patch("ava.common.handler._Handler._print_status")

        # no issue
        test = handler.execute_check(check, [vector])
        assert test == []

    def test_execute_check_negative(self, handler, vector, mocker):
        check = CrossSiteScriptingBlindDirectCheck("http://localhost:8080/")
        auditable = {'vector': vector}

        # no targets
        mocker.patch("ava.handlers.blind._BlindHandler._get_targets", return_value=[])
        test = handler.execute_check(check, [vector])
        assert test == []

        # no response
        mocker.patch("ava.handlers.blind._BlindHandler._get_targets", return_value=['param'])
        mocker.patch("ava.handlers.blind._BlindHandler._generate_variations", return_value=[auditable])
        mocker.patch("ava.common.handler._Handler._send_request", return_value=None)
        test = handler.execute_check(check, [vector])
        assert test == []

    def test_get_targets(self, handler):
        """implemented by children"""
        test = handler._get_targets({})
        assert test == []

    def test_generate_variations(self, handler):
        test = handler._generate_variations(None, None, "")
        assert test == []
