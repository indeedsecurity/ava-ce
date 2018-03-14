import pytest
from copy import copy
from ava.actives.open_redirect import OpenRedirectCheck
from ava.auditors.multipart import _MultipartValueHandler, MultipartAuditor


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.example.com/",
        'method': "post",
        'cookies': {},
        'headers': {'Content-Type': "multipart/form-data; boundary=boundary"},
        'params': {},
        'data': '--boundary\r\nContent-Disposition: form-data; name="ava"\r\n\r\navascan\r\n--boundary--\r\n'
    }

    return vector


class TestMultipartValueHandler:

    @pytest.fixture
    def handler(self):
        return _MultipartValueHandler({'skips': []}, "", None)

    def test_get_targets_positive(self, handler, vector):
        # multipart data
        test = handler._get_targets(vector)
        assert test == ["ava"]

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
        original = vector['data']
        generated = []

        check = OpenRedirectCheck()

        for payload in check.payloads(vector['url'], "ava", "avascan"):
            variation = copy(vector)
            variation['data'] = original.replace("avascan", payload)
            generated.append({'vector': variation, 'payload': payload, 'value': payload})

        test = handler._generate_variations(check, vector, "ava")
        assert list(test) == generated


class TestMultipartAuditor:

    @pytest.fixture
    def auditor(self):
        return MultipartAuditor({}, [], [])

    def test_init(self, auditor):
        assert isinstance(auditor._handlers[0], _MultipartValueHandler)
