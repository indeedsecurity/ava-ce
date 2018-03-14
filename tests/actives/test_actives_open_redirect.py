import pytest
from ava.actives.open_redirect import OpenRedirectCheck, OpenRedirectHtmlCheck, OpenRedirectScriptCheck


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestOpenRedirectCheck:
    payloads = [
        "http://www.avascan.com",
        "https://www.avascan.com",
        "//www.avascan.com",
        "/\t/www.avascan.com",
        "/\\www.avascan.com",
        "https:www.avascan.com"
    ]

    dynamic = [
        "http://www.example.com:pass@www.avascan.com",
        "http://www.example.com.www.avascan.com",
        "http://www.avascan.com\\www.example.com",
        "http://www.avascan.com/www.example.com"
    ]

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="avascan")
        return OpenRedirectCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads

    def test_payloads(self, check):
        # payloads
        test = check.payloads("http://www.example.com/", "target", "value")
        assert test == self.payloads + self.dynamic

    def test_check_true_positive(self, check, response):
        # true positive 301
        response.status_code = 301
        response.headers = {"Location": check._payloads[0]}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive 302
        response.status_code = 302
        response.headers = {"Location": check._payloads[0]}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive 307
        response.status_code = 307
        response.headers = {"Location": check._payloads[0]}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive 308
        response.status_code = 308
        response.headers = {"Location": check._payloads[0]}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive with query string
        response.status_code = 302
        response.headers = {"Location": check._payloads[0] + "/?param=test"}
        test = check.check(response, check._payloads[0])
        assert test

    def test_check_true_negative(self, check, response):
        # true negative code
        response.status_code = 200
        response.headers = {}
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative header
        response.status_code = 302
        response.headers = {}
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative location
        response.status_code = 302
        response.headers = {"Location": "http://www.notavanscan.com"}
        test = check.check(response, check._payloads[0])
        assert not test


class TestOpenRedirectHtmlCheck(TestOpenRedirectCheck):

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="avascan")
        return OpenRedirectHtmlCheck()

    def test_check_true_positive(self, check, response):
        # true positive
        response.text = '<html><body><a href="http://www.avascan.com">Link</a></body></html>'
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive with query string
        response.text = '<html><body><a href="http://www.avascan.com/?param=test">Link</a></body></html>'
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

    def test_check_true_negative(self, check, response):
        # true negative empty
        response.text = ""
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative not html
        response.text = '{"field": "value"}'
        response.headers = {'Content-Type': "application/json"}
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative html
        response.text = '<html><body><a href="http://www.notavascan.com">Link</a></body></html>'
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert not test


class TestOpenRedirectScriptCheck(TestOpenRedirectCheck):

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="avascan")
        return OpenRedirectScriptCheck()

    def test_check_true_positive(self, check, response):
        html = '<html><body><script>{}</script></body></html>'

        # true positive window.location
        response.text = html.format('window.location = "http://www.avascan.com/";')
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive window.location.href
        response.text = html.format('window.location.href = "http://www.avascan.com/";')
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive document.location
        response.text = html.format('document.location = "http://www.avascan.com/";')
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive document.location.href
        response.text = html.format('document.location.href = "http://www.avascan.com/";')
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive document.location
        response.text = html.format('self.location = "http://www.avascan.com/";')
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive document.location.href
        response.text = html.format('self.location.href = "http://www.avascan.com/";')
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive escaped
        response.text = html.format('window.location = "http:\/\/www.avascan.com\/";')
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive with query string
        response.text = html.format('window.location = "http://www.avascan.com/?p=test";')
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

        # true positive with string concatenate
        response.text = html.format('window.location = "http://www.avascan.com/" + "?p=test";')
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert test

    def test_check_true_negative(self, check, response):
        # true negative empty
        response.text = ""
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative not html
        response.text = '{"field": "value"}'
        response.headers = {'Content-Type': "application/json"}
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative html
        response.text = '<html><body><script>window.location = "http://www.notavascan.com/";</script></body></html>'
        response.headers = {'Content-Type': "text/html"}
        test = check.check(response, check._payloads[0])
        assert not test
