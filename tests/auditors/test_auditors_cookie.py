import pytest
from copy import deepcopy
from urllib import parse
from ava.actives.xss import CrossSiteScriptingCheck
from ava.actives.open_redirect import OpenRedirectCheck
from ava.auditors.cookie import CookieAuditor, _CookieValueHandler


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.example.com/",
        'method': "get",
        'params': {},
        'cookies': {'ava': "avascan"},
        'headers': {}
    }

    return vector


class TestCookieValueHandler:

    @pytest.fixture
    def handler(self):
        return _CookieValueHandler({'skips': []}, "", None)

    def test_get_targets(self, handler, vector):
        # with cookies
        test = handler._get_targets(vector)
        assert test == ['ava']

        # without cookies
        vector['cookies'] = {}
        test = handler._get_targets(vector)
        assert test == []

    def test_generate_variations_static_payloads(self, handler, vector):
        generated = []

        # check static payloads
        check = CrossSiteScriptingCheck()

        for payload in check.payloads(vector['url'], "ava", "avascan"):
            payload = parse.quote_plus(payload)

            # replace
            variation = deepcopy(vector)
            variation['cookies']['ava'] = payload
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

        test = handler._generate_variations(check, vector, 'ava')
        assert list(test) == generated

    def test_generate_variations_dynamic_payloads(self, handler, vector):
        generated = []

        # check with dynamic payloads
        check = OpenRedirectCheck()

        for payload in check.payloads(vector['url'], "ava", "avascan"):
            payload = parse.quote_plus(payload)

            # replace
            variation = deepcopy(vector)
            variation['cookies']['ava'] = payload
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

        test = handler._generate_variations(check, vector, 'ava')
        assert list(test) == generated


class TestCookieAuditor:

    @pytest.fixture
    def auditor(self):
        return CookieAuditor({}, [], [])

    def test_init(self, auditor):
        assert isinstance(auditor._handlers[0], _CookieValueHandler)
