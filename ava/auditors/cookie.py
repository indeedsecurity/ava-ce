from copy import copy
from urllib import parse
from ava.common import utility
from ava.common.auditor import _Auditor
from ava.handlers.value import _ValueHandler


# metadata
name = __name__
description = "audits each cookie"


class _CookieValueHandler(_ValueHandler):
    def _get_targets(self, vector):
        """
        Returns cookies for the vector
        :param vector: vector dictionary
        :return: cookie list
        """
        return list(vector['cookies'])

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for simple checks. Variations are created by replacing and appending values.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        originals = vector['cookies']

        # each payload for check
        for payload in check.payloads(vector['url'], target, originals[target]):

            # manually encode
            payload = parse.quote_plus(payload)

            # parse cookies
            parsed = utility.parse_cookie(originals[target])

            # each replacement
            for replacement in parsed.replace(payload):
                # set target
                cookies = copy(originals)
                cookies[target] = replacement

                # set vector
                variation = copy(vector)
                variation['cookies'] = cookies

                # set auditable
                auditable = {
                    'vector': variation,
                    'payload': payload,
                    'value': replacement
                }

                yield auditable


class CookieAuditor(_Auditor):
    """
    Audits each cookie of each vector. It audits by replacing cookie values with a payload and then inserting
    payloads within cookie values. It implements _execute_check(), which is passed a chunk of vectors and returns
    a list of issues. Vectors without cookies are skipped.
    """
    key = "cookie"
    name = "Cookies"
    description = "Audits by replacing and inserting payloads to each cookie"
    handlers = [
        _CookieValueHandler
    ]
