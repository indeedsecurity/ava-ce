import pytest
from ava.blinds.ssrf import ServerSideRequestForgeryCheck
from ava.common.exception import InvalidFormatException

class TestServerSideRequestForgeryCheck:
    payloads = [
        'http://127.0.0.1:8080/',
        'http://example.com#@127.0.0.1:8080/',
        'http://foo@127.0.0.1:8080@example.com/',
        'http://foo@127.0.0.1:8080 @example.com/',
        'http://①②⑦｡⓪｡⓪｡①:8080/'
    ]

    @pytest.fixture
    def check(self):
        listener = "http://127.0.0.1:8080/"
        return ServerSideRequestForgeryCheck(listener)

    def test_init(self, check):
        assert check._payloads == self.payloads

    def test_check_payloads_positive(self, check):
        payloads = ["{}://{}/"]
        correct = ["http://127.0.0.1:8080/"]
        assert check._check_payloads(payloads) == correct

    def test_check_payloads_negative(self, check):
        # one bracket
        payloads = ["http://{}/"]
        with pytest.raises(InvalidFormatException):
            check._check_payloads(payloads)
