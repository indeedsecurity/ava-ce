import pytest
from copy import copy
from ava.actives.xss import CrossSiteScriptingCheck
from ava.auditors.text import _TextValueHandler, TextAuditor


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.example.com/",
        'method': "post",
        'cookies': {},
        'headers': {'Content-Type': "text/plain"},
        'params': {},
        'data': 'plain text data'
    }

    return vector


class TestTextValueHandler:

    @pytest.fixture
    def handler(self):
        return _TextValueHandler({'skips': []}, "", None)

    def test_get_targets_positive(self, handler, vector):
        # text data
        test = handler._get_targets(vector)
        assert test == ['0']

    def test_get_targets_negative(self, handler, vector):
        # without data
        test = handler._get_targets({'headers': vector['headers'], 'data': ""})
        assert test == []

        # without content-type
        test = handler._get_targets({'headers': {}, 'data': vector['data']})
        assert test == []

        # other content-type
        test = handler._get_targets({'headers': {'Content-Type': "text/html"}, 'data': vector['data']})
        assert test == []

    def test_generate_variations(self, handler, vector):
        generated = []

        check = CrossSiteScriptingCheck()

        for payload in check.payloads(vector['url'], "ava", "avascan"):
            variation = copy(vector)
            variation['data'] = payload
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

        test = handler._generate_variations(check, vector, "ava")
        assert list(test) == generated


class TestTextAuditor:

    @pytest.fixture
    def auditor(self):
        return TextAuditor({}, [], [])

    def test_init(self, auditor):
        assert isinstance(auditor._handlers[0], _TextValueHandler)
