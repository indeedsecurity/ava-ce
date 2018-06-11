import pytest
import json
from copy import copy
from ava.actives.sql_injection import SqlInjectionCheck, SqlInjectionDifferentialCheck, SqlInjectionTimingCheck
from ava.auditors.json import _JsonValueHandler, _JsonDifferentialHandler, _JsonTimingHandler, _JsonBlindHandler
from ava.auditors.json import JsonAuditor
from ava.blinds.xss import CrossSiteScriptingBlindDirectCheck


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.example.com/",
        'method': "post",
        'cookies': {},
        'headers': {'Content-Type': "application/json"},
        'params': {},
        'data': '{"ava": "avascan"}'
    }

    return vector


class TestJsonValueHandler:

    @pytest.fixture
    def handler(self):
        return _JsonValueHandler({'skips': []}, "", None)

    def test_get_targets_positive(self, handler, vector):
        # with json
        test = handler._get_targets(vector)
        assert test == ['ava']

    def test_get_targets_negative(self, handler, vector):
        # without data
        test = handler._get_targets({'headers': vector['headers'], 'data': ""})
        assert test == []

        # without content-type
        test = handler._get_targets({'headers': {}, 'data': vector['data']})
        assert test == []

        # other content-type
        test = handler._get_targets({'headers': {'Content-Type': "text/plain"}, 'data': vector['data']})
        assert test == []

    def test_generate_variations(self, handler, vector):
        generated = []

        check = SqlInjectionCheck()

        for payload in check.payloads(vector['url'], "ava", "avascan"):
            variation = copy(vector)
            variation['data'] = '{{"ava": {}}}'.format(json.dumps(payload))
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

        test = handler._generate_variations(check, vector, "ava")
        assert list(test) == generated


class TestJsonDifferentialHandler:

    @pytest.fixture
    def handler(self):
        return _JsonDifferentialHandler({'skips': []}, "", None)

    def test_get_targets_positive(self, handler, vector):
        # with json
        test = handler._get_targets(vector)
        assert test == ['ava']

    def test_get_targets_negative(self, handler, vector):
        # without data
        test = handler._get_targets({'headers': vector['headers'], 'data': ""})
        assert test == []

        # without content-type
        test = handler._get_targets({'headers': {}, 'data': vector['data']})
        assert test == []

        # other content-type
        test = handler._get_targets({'headers': {'Content-Type': "text/plain"}, 'data': vector['data']})
        assert test == []

    def test_generate_variations(self, handler, vector):
        generated = []

        check = SqlInjectionDifferentialCheck()

        for true_payload, false_payload in check.payloads(vector['url'], "ava", "avascan"):
            true_variation = copy(vector)
            true_variation['data'] = '{{"ava": {}}}'.format(json.dumps(true_payload))
            false_variation = copy(vector)
            false_variation['data'] = '{{"ava": {}}}'.format(json.dumps(false_payload))
            generated.append({'vectors': {'true': true_variation, 'false': false_variation},
                              'payloads': {'true': true_payload, 'false': false_payload},
                              'values': {'true': true_payload, 'false': false_payload}})

        test = handler._generate_variations(check, vector, "ava")
        assert list(test) == generated


class TestJsonTimingHandler:

    @pytest.fixture
    def handler(self):
        return _JsonTimingHandler({'skips': []}, "", None)

    def test_get_targets_positive(self, handler, vector):
        # with json
        test = handler._get_targets(vector)
        assert test == ['ava']

    def test_get_targets_negative(self, handler, vector):
        # without data
        test = handler._get_targets({'headers': vector['headers'], 'data': ""})
        assert test == []

        # without content-type
        test = handler._get_targets({'headers': {}, 'data': vector['data']})
        assert test == []

        # other content-type
        test = handler._get_targets({'headers': {'Content-Type': "text/plain"}, 'data': vector['data']})
        assert test == []

    def test_generate_variations(self, handler, vector):
        generated = []

        check = SqlInjectionTimingCheck()

        for payload, delay in check.payloads(vector['url'], "ava", "avascan"):
            variation = copy(vector)
            variation['data'] = '{{"ava": {}}}'.format(json.dumps(payload))
            generated.append({'vectors': {'original': vector, 'timing': variation},
                              'payload': payload,
                              'value': payload,
                              'delay': delay})

        test = handler._generate_variations(check, vector, "ava")
        assert list(test) == generated


class TestJsonBlindHandler:

    @pytest.fixture
    def handler(self):
        return _JsonBlindHandler({'skips': []}, "", None)

    def test_get_targets_positive(self, handler, vector):
        # with json
        test = handler._get_targets(vector)
        assert test == ['ava']

    def test_get_targets_negative(self, handler, vector):
        # without data
        test = handler._get_targets({'headers': vector['headers'], 'data': ""})
        assert test == []

        # without content-type
        test = handler._get_targets({'headers': {}, 'data': vector['data']})
        assert test == []

        # other content-type
        test = handler._get_targets({'headers': {'Content-Type': "text/plain"}, 'data': vector['data']})
        assert test == []

    def test_generate_variations(self, handler, vector):
        generated = []

        check = CrossSiteScriptingBlindDirectCheck("http://localhost:8080/")

        for payload in check.payloads(vector['url'], "ava", "avascan"):
            variation = copy(vector)
            variation['data'] = '{{"ava": {}}}'.format(json.dumps(payload))
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

        test = handler._generate_variations(check, vector, "ava")
        assert list(test) == generated


class TestJsonAuditor:

    @pytest.fixture
    def auditor(self):
        return JsonAuditor({}, [], [])

    def test_init(self, auditor):
        assert isinstance(auditor._handlers[0], _JsonValueHandler)
        assert isinstance(auditor._handlers[1], _JsonDifferentialHandler)
        assert isinstance(auditor._handlers[2], _JsonTimingHandler)
        assert isinstance(auditor._handlers[3], _JsonBlindHandler)
