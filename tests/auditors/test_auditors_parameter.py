import pytest
from copy import deepcopy
from ava.actives.open_redirect import OpenRedirectCheck
from ava.actives.shell_injection import ShellInjectionTimingCheck
from ava.actives.sql_injection import SqlInjectionDifferentialCheck
from ava.actives.xss import CrossSiteScriptingCheck
from ava.auditors.parameter import QueryParameterAuditor, PostParameterAuditor
from ava.auditors.parameter import _QueryParameterValueHandler, _QueryParameterDifferentialHandler
from ava.auditors.parameter import _QueryParameterTimingHandler, _QueryParameterBlindHandler
from ava.auditors.parameter import _PostParameterValueHandler, _PostParameterDifferentialHandler
from ava.auditors.parameter import _PostParameterTimingHandler, _PostParameterBlindHandler
from ava.blinds.xss import CrossSiteScriptingBlindCheck


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.example.com/",
        'method': "get",
        'params': {'ava': "avascan"},
        'data': {'ava': "avascan"},
        'cookies': {},
        'headers': {}
    }

    return vector


class TestQueryParameterValueHandler:

    @pytest.fixture
    def handler(self):
        return _QueryParameterValueHandler({'skips': []}, "", None)
    
    def test_get_targets(self, handler, vector):
        # with parameters
        test = handler._get_targets(vector)
        assert test == ['ava']

        # without parameters
        vector['params'] = {}
        test = handler._get_targets(vector)
        assert test == []

    def test_generate_variations_static_payloads(self, handler, vector):
        generated = []

        # check static payloads
        check = CrossSiteScriptingCheck()

        for payload in check.payloads(vector['url'], "ava", "avascan"):
            # replace
            variation = deepcopy(vector)
            variation['params']['ava'] = payload
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

            # append
            variation = deepcopy(vector)
            variation['params']['ava'] = "avascan" + payload
            generated.append({'vector': variation, 'payload': payload, 'value': "avascan" + payload})

        test = handler._generate_variations(check, vector, 'ava')
        assert list(test) == generated

    def test_generate_variations_dynamic_payloads(self, handler, vector):
        generated = []

        # check with dynamic payloads
        check = OpenRedirectCheck()

        for payload in check.payloads(vector['url'], "ava", "avascan"):
            # replace
            variation = deepcopy(vector)
            variation['params']['ava'] = payload
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

            # append
            variation = deepcopy(vector)
            variation['params']['ava'] = "avascan" + payload
            generated.append({'vector': variation, 'payload': payload, 'value': "avascan" + payload})

        test = handler._generate_variations(check, vector, 'ava')
        assert list(test) == generated


class TestQueryParameterDifferentialHandler:

    @pytest.fixture
    def handler(self):
        return _QueryParameterDifferentialHandler({'skips': []}, "", None)
    
    def test_get_targets(self, handler, vector):
        # with parameters
        test = handler._get_targets(vector)
        assert test == ['ava']

        # without parameters
        vector['params'] = {}
        test = handler._get_targets(vector)
        assert test == []

    def test_generate_variations_static_payloads(self, handler, vector):
        generated = []

        # check static payloads
        check = SqlInjectionDifferentialCheck()

        for true_payload, false_payload in check.payloads(vector['url'], "ava", "avascan"):
            # replace
            true_variation = deepcopy(vector)
            true_variation['params']['ava'] = true_payload
            false_variation = deepcopy(vector)
            false_variation['params']['ava'] = false_payload
            generated.append({'vectors': {'true': true_variation, 'false': false_variation},
                              'payloads': {'true': true_payload, 'false': false_payload},
                              'values': {'true': true_payload, 'false': false_payload}})

            # append
            true_variation = deepcopy(vector)
            true_variation['params']['ava'] = "avascan" + true_payload
            false_variation = deepcopy(vector)
            false_variation['params']['ava'] = "avascan" + false_payload
            generated.append({'vectors': {'true': true_variation, 'false': false_variation},
                              'payloads': {'true': true_payload, 'false': false_payload},
                              'values': {'true': "avascan" + true_payload, 'false': "avascan" + false_payload}})

        test = handler._generate_variations(check, vector, 'ava')
        assert list(test) == generated


class TestQueryParameterTimingHandler:

    @pytest.fixture
    def handler(self):
        return _QueryParameterTimingHandler({'skips': []}, "", None)
    
    def test_get_targets(self, handler, vector):
        # with parameters
        test = handler._get_targets(vector)
        assert test == ['ava']

        # without parameters
        vector['params'] = {}
        test = handler._get_targets(vector)
        assert test == []

    def test_generate_variations_static_payloads(self, handler, vector):
        generated = []

        # check static payloads
        check = ShellInjectionTimingCheck()

        for payload, delay in check.payloads(vector['url'], "ava", "avascan"):
            # replace
            variation = deepcopy(vector)
            variation['params']['ava'] = payload
            generated.append({'vectors': {'original': vector, 'timing': variation},
                              'payload': payload,
                              'value': payload,
                              'delay': delay})

            # append
            variation = deepcopy(vector)
            variation['params']['ava'] = "avascan" + payload
            generated.append({'vectors': {'original': vector, 'timing': variation},
                              'payload': payload,
                              'value': "avascan" + payload,
                              'delay': delay})

        test = handler._generate_variations(check, vector, 'ava')
        assert list(test) == generated


class TestQueryParameterBlindHandler:

    @pytest.fixture
    def handler(self):
        return _QueryParameterBlindHandler({'skips': []}, "", None)
    
    def test_get_targets(self, handler, vector):
        # with parameters
        test = handler._get_targets(vector)
        assert test == ['ava']

        # without parameters
        vector['params'] = {}
        test = handler._get_targets(vector)
        assert test == []

    def test_generate_variations_static_payloads(self, handler, vector):
        generated = []

        # check static payloads
        check = CrossSiteScriptingBlindCheck("http://localhost:8080/")

        for payload in check.payloads(vector['url'], "ava", "avascan"):
            # replace
            variation = deepcopy(vector)
            variation['params']['ava'] = payload
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

            # append
            variation = deepcopy(vector)
            variation['params']['ava'] = "avascan" + payload
            generated.append({'vector': variation, 'payload': payload, 'value': "avascan" + payload})

        test = handler._generate_variations(check, vector, 'ava')
        assert list(test) == generated


class TestQueryParameterAuditor:

    @pytest.fixture
    def auditor(self):
        return QueryParameterAuditor({}, [], [])

    def test_init(self, auditor):
        assert isinstance(auditor._handlers[0], _QueryParameterValueHandler)
        assert isinstance(auditor._handlers[1], _QueryParameterDifferentialHandler)
        assert isinstance(auditor._handlers[2], _QueryParameterTimingHandler)
        assert isinstance(auditor._handlers[3], _QueryParameterBlindHandler)


class TestPostParameterValueHandler:

    @pytest.fixture
    def handler(self):
        return _PostParameterValueHandler({}, "", None)

    def test_get_targets_supported(self, handler, vector):
        # with parameters
        vector['headers'] = {"Content-Type": "application/x-www-form-urlencoded"}
        test = handler._get_targets(vector)
        assert test == ['ava']

        # with parameters with charset
        vector['headers'] = {"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"}
        test = handler._get_targets(vector)
        assert test == ['ava']

        # without parameters
        vector['data'] = {}
        test = handler._get_targets(vector)
        assert test == []

    def test_get_targets_not_supported(self, handler, vector):
        # data not dictionary
        test = handler._get_targets({'headers': vector['headers'], 'data': ""})
        assert test == []

        # without content-type
        test = handler._get_targets({'headers': {}, 'data': vector['data']})
        assert test == []

        # other content-type
        test = handler._get_targets({'headers': {"Content-Type": "application/json"}, 'data': vector['data']})
        assert test == []


class TestPostParameterDifferentialHandler:

    @pytest.fixture
    def handler(self):
        return _PostParameterDifferentialHandler({}, "", None)

    def test_get_targets_supported(self, handler, vector):
        # with parameters
        vector['headers'] = {"Content-Type": "application/x-www-form-urlencoded"}
        test = handler._get_targets(vector)
        assert test == ['ava']

        # with parameters with charset
        vector['headers'] = {"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"}
        test = handler._get_targets(vector)
        assert test == ['ava']

        # without parameters
        vector['data'] = {}
        test = handler._get_targets(vector)
        assert test == []

    def test_get_targets_not_supported(self, handler, vector):
        # data not dictionary
        test = handler._get_targets({'headers': vector['headers'], 'data': ""})
        assert test == []

        # without content-type
        test = handler._get_targets({'headers': {}, 'data': vector['data']})
        assert test == []

        # other content-type
        test = handler._get_targets({'headers': {"Content-Type": "application/json"}, 'data': vector['data']})
        assert test == []


class TestPostParameterTimingHandler:

    @pytest.fixture
    def handler(self):
        return _PostParameterTimingHandler({}, "", None)

    def test_get_targets_supported(self, handler, vector):
        # with parameters
        vector['headers'] = {"Content-Type": "application/x-www-form-urlencoded"}
        test = handler._get_targets(vector)
        assert test == ['ava']

        # with parameters with charset
        vector['headers'] = {"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"}
        test = handler._get_targets(vector)
        assert test == ['ava']

        # without parameters
        vector['data'] = {}
        test = handler._get_targets(vector)
        assert test == []

    def test_get_targets_not_supported(self, handler, vector):
        # data not dictionary
        test = handler._get_targets({'headers': vector['headers'], 'data': ""})
        assert test == []

        # without content-type
        test = handler._get_targets({'headers': {}, 'data': vector['data']})
        assert test == []

        # other content-type
        test = handler._get_targets({'headers': {"Content-Type": "application/json"}, 'data': vector['data']})
        assert test == []


class TestPostParameterBlindHandler:

    @pytest.fixture
    def handler(self):
        return _PostParameterBlindHandler({}, "", None)

    def test_get_targets_supported(self, handler, vector):
        # with parameters
        vector['headers'] = {"Content-Type": "application/x-www-form-urlencoded"}
        test = handler._get_targets(vector)
        assert test == ['ava']

        # with parameters with charset
        vector['headers'] = {"Content-Type": "application/x-www-form-urlencoded;charset=utf-8"}
        test = handler._get_targets(vector)
        assert test == ['ava']

        # without parameters
        vector['data'] = {}
        test = handler._get_targets(vector)
        assert test == []

    def test_get_targets_not_supported(self, handler, vector):
        # data not dictionary
        test = handler._get_targets({'headers': vector['headers'], 'data': ""})
        assert test == []

        # without content-type
        test = handler._get_targets({'headers': {}, 'data': vector['data']})
        assert test == []

        # other content-type
        test = handler._get_targets({'headers': {"Content-Type": "application/json"}, 'data': vector['data']})
        assert test == []


class TestPostParameterAuditor:

    @pytest.fixture
    def auditor(self):
        return PostParameterAuditor({}, [], [])

    def test_init(self, auditor):
        assert isinstance(auditor._handlers[0], _PostParameterValueHandler)
        assert isinstance(auditor._handlers[1], _PostParameterDifferentialHandler)
        assert isinstance(auditor._handlers[2], _PostParameterTimingHandler)
        assert isinstance(auditor._handlers[3], _PostParameterBlindHandler)
