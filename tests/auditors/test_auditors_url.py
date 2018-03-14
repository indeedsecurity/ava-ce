import pytest
from copy import deepcopy
from urllib import parse
from ava.actives.open_redirect import OpenRedirectCheck
from ava.actives.xss import CrossSiteScriptingCheck
from ava.auditors.url import UrlAuditor, _UrlValueHandler


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


class TestUrlValueHandler:
    
    @pytest.fixture
    def handler(self):
        return _UrlValueHandler({'skips': []}, "", None)

    def test_get_targets(self, handler, vector):
        # with urls
        test = handler._get_targets(vector)
        assert test == ["http://www.example.com/"]

    def test_generate_variations_static_payloads(self, handler, vector):
        generated = []
        url = vector['url']
        
        # check static payloads
        check = CrossSiteScriptingCheck()

        for payload in check.payloads(url, url, url):
            # append
            variation = deepcopy(vector)
            encoded = parse.quote(payload[1:] if payload.startswith('/') else payload, safe='')
            variation['url'] = url.rstrip('/') + '/' + encoded
            generated.append({'vector': variation, 'payload': payload, 'value': url.rstrip('/') + '/' + encoded})
            
            # query
            variation = deepcopy(vector)
            variation['url'] = url + '?' + payload
            generated.append({'vector': variation, 'payload': payload, 'value': url + '?' + payload})
            
            # fragment
            variation = deepcopy(vector)
            variation['url'] = url + '#' + payload
            generated.append({'vector': variation, 'payload': payload, 'value': url + '#' + payload})
            
            # path parameter
            variation = deepcopy(vector)
            variation['url'] = url + ';' + payload
            generated.append({'vector': variation, 'payload': payload, 'value': url + ';' + payload})

        test = list(handler._generate_variations(check, vector, "http://www.example.com/"))
        assert test == generated
        
    def test_generate_variations_dynamic_payloads(self, handler, vector):
        generated = []
        url = vector['url']
    
        # check with dynamic payloads
        check = OpenRedirectCheck()

        for payload in check.payloads(url, url, url):
            # append
            variation = deepcopy(vector)
            encoded = parse.quote(payload[1:] if payload.startswith('/') else payload, safe='')
            variation['url'] = url.rstrip('/') + '/' + encoded
            generated.append({'vector': variation, 'payload': payload, 'value': url.rstrip('/') + '/' + encoded})

            # query
            variation = deepcopy(vector)
            variation['url'] = url + '?' + payload
            generated.append({'vector': variation, 'payload': payload, 'value': url + '?' + payload})

            # fragment
            variation = deepcopy(vector)
            variation['url'] = url + '#' + payload
            generated.append({'vector': variation, 'payload': payload, 'value': url + '#' + payload})

            # path parameter
            variation = deepcopy(vector)
            variation['url'] = url + ';' + payload
            generated.append({'vector': variation, 'payload': payload, 'value': url + ';' + payload})

        test = list(handler._generate_variations(check, vector, "http://www.example.com/"))
        assert test == generated


class TestUrlAuditor:
    
    @pytest.fixture
    def auditor(self):
        return UrlAuditor({}, [], [])

    def test_init(self, auditor):
        assert isinstance(auditor._handlers[0], _UrlValueHandler)
