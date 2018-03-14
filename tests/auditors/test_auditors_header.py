import pytest
from copy import deepcopy
from urllib import parse
from ava.actives.xss import CrossSiteScriptingCheck
from ava.actives.open_redirect import OpenRedirectCheck
from ava.auditors.header import HeaderAuditor, _HeaderValueHandler


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.example.com/",
        'method': "get",
        'params': {},
        'cookies': {},
        'headers': {'ava': "avascan"}
    }

    return vector


class TestHeaderValueHandler:
    
    @pytest.fixture
    def handler(self):
        return _HeaderValueHandler({'skips': []}, "", None)

    def test_get_targets(self, handler, vector):
        # with parameters
        test = handler._get_targets(vector)
        assert test == ['ava']

        # without parameters
        vector['headers'] = {}
        test = handler._get_targets(vector)
        assert test == []

    def test_generate_variations_static_payloads(self, handler, vector):
        generated = []
    
        # check static payloads
        check = CrossSiteScriptingCheck()

        for payload in check.payloads(vector['url'], "ava", "avascan"):
            payload = parse.quote(payload, safe='')

            # replace
            variation = deepcopy(vector)
            variation['headers']['ava'] = payload
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

            # append
            variation = deepcopy(vector)
            variation['headers']['ava'] = "avascan" + payload
            generated.append({'vector': variation, 'payload': payload, 'value': "avascan" + payload})

        test = list(handler._generate_variations(check, vector, 'ava'))
        assert test == generated
    
    def test_generate_variations_dynamic_payloads(self, handler, vector):
        generated = []
        
        # check with dynamic payloads
        check = OpenRedirectCheck()
        
        for payload in check.payloads(vector['url'], "ava", "avascan"):
            payload = parse.quote_plus(payload)

            # replace
            variation = deepcopy(vector)
            variation['headers']['ava'] = payload
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

            # append
            variation = deepcopy(vector)
            variation['headers']['ava'] = "avascan" + payload
            generated.append({'vector': variation, 'payload': payload, 'value': "avascan" + payload})

        test = list(handler._generate_variations(check, vector, 'ava'))
        assert test == generated


class TestHeaderAuditor:
    
    @pytest.fixture
    def auditor(self):
        return HeaderAuditor({}, [], [])
    
    def test_init(self, auditor):
        assert isinstance(auditor._handlers[0], _HeaderValueHandler)
