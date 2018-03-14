from copy import copy
from urllib import parse
from ava.common.auditor import _Auditor
from ava.handlers.value import _ValueHandler


# metadata
name = __name__
description = "audits each url"


class _UrlValueHandler(_ValueHandler):
    def _get_targets(self, vector):
        """
        Returns URL for the vector.
        :param vector: vector dictionary
        :return: URL as list
        """
        return [vector['url']]

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for simple checks. Variations are created by replacing and appending values.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        original = vector['url']

        # each payload for check
        for payload in check.payloads(vector['url'], original, original):

            # each variation append, query, fragment, path
            for value in [original.rstrip('/') + '/', original + '?', original + '#', original + ';']:
                # strip and encode
                if value.endswith('/'):
                    current = parse.quote(payload[1:] if payload.startswith('/') else payload, safe='')
                else:
                    current = payload

                # set target and vector
                variation = copy(vector)
                variation['url'] = value + current

                # set auditable
                auditable = {
                    'vector': variation,
                    'payload': payload,
                    'value': value + current
                }

                yield auditable


class UrlAuditor(_Auditor):
    """
    Audits each URL of each vector. It audits by adding payloads to the URL, query string, fragment, and path parameter.
    It implements _execute_check(), which is passed a chunk of vectors and returns a list of issues.
    """
    key = "url"
    name = "URLs"
    description = "Audits by appending payloads to each url"
    handlers = [
        _UrlValueHandler
    ]
