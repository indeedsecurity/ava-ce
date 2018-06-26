import pytest
from ava.actives.shell_injection import ShellInjectionCheck, ShellInjectionTimingCheck
from ava.common.exception import InvalidFormatException


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestShellInjectionCheck:
    payloads = [
        '; id #',
        '| id #',
        '&& id #',
        '|| id #',
        "' ; id #",
        "' | id #",
        "' && id #",
        "' || id #",
        '" ; id #',
        '" | id #',
        '" && id #',
        '" || id #',
        '`id`',
        '$(id)'
    ]

    @pytest.fixture
    def check(self):
        return ShellInjectionCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads

    def test_check_true_positive(self, check, response):
        html = "<html><head></head><body>{}</body</html>"

        # true positive
        body = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        response.text = html.format(body)
        test = check.check(response, check._payloads[0])
        assert test

    def test_check_true_negative(self, check, response):
        html = "<html><head></head><body>{}</body</html>"

        # true negative
        body = "Not found"
        response.text = html.format(body)
        test = check.check(response, check._payloads[0])
        assert not test

        # empty
        response.text = ""
        test = check.check(response, check._payloads[0])
        assert not test

    def test_check_payloads_positive(self, check):
        # positive
        payloads = ["; id #"]
        assert payloads == check._check_payloads(payloads)

    def test_check_payloads_negative(self, check):
        # negative
        payloads = ["; ls #"]
        with pytest.raises(InvalidFormatException):
            check._check_payloads(payloads)

class TestShellInjectionTimingCheck:
    payloads = [
        ('; sleep 9 #', 9.00),
        ('| sleep 9 #', 9.00),
        ('&& sleep 9 #', 9.00),
        ('|| sleep 9 #', 9.00),
        ("' ; sleep 9 #", 9.00),
        ("' | sleep 9 #", 9.00),
        ("' && sleep 9 #", 9.00),
        ("' || sleep 9 #", 9.00),
        ('" ; sleep 9 #', 9.00),
        ('" | sleep 9 #', 9.00),
        ('" && sleep 9 #', 9.00),
        ('" || sleep 9 #', 9.00),
        ('`sleep 9`', 9.00),
        ('$(sleep 9)', 9.00)
    ]

    @pytest.fixture
    def check(self):
        return ShellInjectionTimingCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads
