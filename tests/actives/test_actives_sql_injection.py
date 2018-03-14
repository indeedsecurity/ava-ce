import pytest
from ava.actives.sql_injection import SqlInjectionCheck, SqlInjectionDifferentialCheck, SqlInjectionTimingCheck


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestSqlInjectionCheck:
    payloads = [
        "'",
        '"',
        '(',
        ')',
        "NULL",
        "ava1221",
        "ava1221",
        "--"
    ]

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="ava1221")
        return SqlInjectionCheck()

    def test_init(self, check):
        assert check._payloads == self.payloads

    def test_check_positive(self, check, response):
        response.status_code = 500
        response.text = "Traceback (most recent call last):\nSQLException: syntax error &quot;&#039;&quot"

        # true positive
        test = check.check(response, check._payloads[0])
        assert test

    def test_check_negative(self, check, response):
        # empty response body
        response.text = ""
        test = check.check(response, check._payloads[0])
        assert not test

        # wrong status code
        response.status_code = 200
        response.text = "<html><head></head><body>Successful</body>"
        test = check.check(response, check._payloads[0])
        assert not test

        # no stack trace
        response.status_code = 500
        response.text = "<html><head></head><body>An error has occurred</body>"
        test = check.check(response, check._payloads[0])
        assert not test


class TestSqlInjectionDifferentialCheck:
    payloads = [
        ("' AND 'ava'='ava", "' AND 'ava'='!ava"),
        ("' AND 'ava'='ava' -- ", "' AND 'ava'='!ava' -- "),
        ("' AND 'ava'='ava' #", "' AND 'ava'='!ava' #"),
        ("' OR 'ava'='ava", "' AND 'ava'='!ava"),
        ("' OR 'ava'='ava' -- ", "' AND 'ava'='!ava' -- "),
        ("' OR 'ava'='ava' #", "' AND 'ava'='!ava' #"),
        ("%' AND '%'='", "%' AND '%'='!"),
        ("%' OR '%'='", "%' AND '%'='!"),
        ('" OR "ava"="ava', '" AND "ava"="!ava'),
        ('" OR "ava"="ava" -- ', '" AND "ava"="!ava" -- '),
        ('" OR "ava"="ava" #', '" AND "ava"="!ava" #'),
        ("1 OR 1221=1221", "1 AND 1221=2112"),
        ("') AND ('ava'='ava", "') AND ('ava'='!ava"),
        ("') OR ('ava'='ava", "') AND ('ava'='!ava")
    ]

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="ava")
        return SqlInjectionDifferentialCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads


class TestSqlInjectionTimingCheck:
    payloads = [
        ("' UNION SELECT SLEEP(9) -- ", 9.00),
        ("' UNION SELECT null,SLEEP(9) -- ", 9.00),
        ("' UNION SELECT null,null,SLEEP(9) -- ", 9.00),
        ("' UNION SELECT null,null,null,SLEEP(9) -- ", 9.00),
        ("' UNION SELECT null,null,null,null,SLEEP(9) -- ", 9.00),
        ('" UNION SELECT SLEEP(9) -- ', 9.00),
        ('" UNION SELECT null,SLEEP(9) -- ', 9.00),
        ('" UNION SELECT null,null,SLEEP(9) -- ', 9.00),
        ('" UNION SELECT null,null,null,SLEEP(9) -- ', 9.00),
        ('" UNION SELECT null,null,null,null,SLEEP(9) -- ', 9.00),
        ("1 UNION SELECT SLEEP(9) -- ", 9.00),
        ("1 UNION SELECT null,SLEEP(9) -- ", 9.00),
        ("1 UNION SELECT null,null,SLEEP(9) -- ", 9.00),
        ("1 UNION SELECT null,null,null,SLEEP(9) -- ", 9.00),
        ("1 UNION SELECT null,null,null,null,SLEEP(9) -- ", 9.00),
        ("' AND SLEEP(9) AND 'ava'='ava", 9.00),
        ("' OR SLEEP(9) AND 'ava'='ava", 9.00),
        ("') AND SLEEP(9) AND ('ava'='ava", 9.00),
        ("') OR SLEEP(9) AND ('ava'='ava", 9.00)
    ]

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="ava")
        return SqlInjectionTimingCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads
