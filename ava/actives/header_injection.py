import string
from ava.common import utility
from ava.common.check import _ValueCheck


# metadata
name = __name__
description = "checks for header injection"


class HeaderInjectionCheck(_ValueCheck):
    """
    Checks for Header Injection in the response's header.  The payload sets a cookie of 'ava=avascan' using CRLF
    character variations, such as removing each CR/LF character and encoding as UTF-8.
    """
    key = "header.value.cookie"
    name = "Header Injection"
    description = "Checks for Header Injection in response headers"

    def __init__(self):
        """Define static payloads"""
        payloads = [
            '\r\nSet-Cookie: {}={}',
            '\nSet-Cookie: {}={}',
            '\rSet-Cookie: {}={}',
            'čĊSet-Cookie: {}={}'
        ]

        # generate random and add to payloads
        self._random = utility.generate_random(string.ascii_lowercase)
        self._payloads = [payload.format(self._random, self._random) for payload in payloads]

    def check(self, response, payload):
        """
        Checks for Header Injections by looking for the 'Set-Cookie' payload in the response's headers.
        :param response: response object from server
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # check cookies
        if not response.cookies:
            return False

        # check random in cookies
        if self._random in response.cookies:
            return True
        else:
            return False
