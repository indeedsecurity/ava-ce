import pytest
import re
from ava.actives.header_injection import HeaderInjectionCheck
from ava.common.exception import InvalidFormatException


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestHeaderInjectionCheck:
    payloads = [
        "\r\nSet-Cookie: avascan=avascan",
        "\nSet-Cookie: avascan=avascan",
        "\rSet-Cookie: avascan=avascan",
        "čĊSet-Cookie: avascan=avascan"
    ]

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="avascan")
        return HeaderInjectionCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads

    def test_check_true_positive(self, check, response):
        # true positive
        response.cookies = {"avascan": "ava"}
        test = check.check(response, check._payloads[0])
        assert test

    def test_check_true_negative(self, check, response):
        # true negative with cookies
        response.cookies = {"key": "value"}
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative without cookies
        response.cookies = {}
        test = check.check(response, check._payloads[0])
        assert not test

    def test_check_payloads_positive(self, check):
        # positive
        payloads = ["Set-Cookie: {}={}"]
        assert re.match(r"^Set-Cookie: \w*=\w*$", check._check_payloads(payloads)[0])

    def test_check_payloads_negative(self, check):
        # negative
        payloads = ["Invalid payload"]
        with pytest.raises(InvalidFormatException):
            check._check_payloads(payloads)
