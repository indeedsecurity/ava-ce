from copy import copy
from urllib import parse
from ava.common.auditor import _Auditor
from ava.handlers.value import _ValueHandler


# metadata
name = __name__
description = "audits each header"


class _HeaderValueHandler(_ValueHandler):
    def _get_targets(self, vector):
        """
        Returns headers for the vector.
        :param vector: vector dictionary
        :return: headers list
        """
        return list(vector['headers'])

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for simple checks. Variations are created by replacing and appending values.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        originals = vector['headers']

        # each payload for check
        for payload in check.payloads(vector['url'], target, originals[target]):

            # manually encode
            payload = parse.quote(payload, safe='')

            # each variation replace and append
            replace = ''
            for value in [replace, originals[target]]:
                # set target
                headers = copy(originals)
                headers[target] = value + payload

                # set vector
                variation = copy(vector)
                variation['headers'] = headers

                # set auditable
                auditable = {
                    'vector': variation,
                    'payload': payload,
                    'value': value + payload
                }

                yield auditable


class HeaderAuditor(_Auditor):
    """
    Audits each header of each vector. It audits by replacing header values with a payload and then appending
    header values with a payload. It implements _execute_check(), which is passed a chunk of vectors and returns
    a list of issues. Vectors without headers are skipped.
    """
    key = "header"
    name = "Headers"
    description = "Audits by replacing and appending payloads to each header"
    handlers = [
        _HeaderValueHandler
    ]
