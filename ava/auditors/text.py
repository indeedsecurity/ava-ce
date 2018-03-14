from copy import copy
from ava.common.auditor import _Auditor
from ava.common.constant import HTTP
from ava.handlers.value import _ValueHandler


# metadata
name = __name__
description = "audits text data"


class _TextValueHandler(_ValueHandler):
    def _get_targets(self, vector):
        """
        Returns list with a single target for text data. Content-Type must be text/plain.
        :param vector: vector dictionary
        :return: target as list
        """
        headers = vector['headers']
        targets = []

        # check data
        if not vector['data']:
            return []

        # check content-type
        content_type = headers.get('Content-Type')
        if content_type and content_type.startswith(HTTP.CONTENT_TYPE.TEXT):
            targets = ['0']

        return targets

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for value checks. Variations are created by replacing text data with payloads.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        original = vector['data']

        # each payload for check
        for payload in check.payloads(vector['url'], target, original):
            # set vector
            variation = copy(vector)
            variation['data'] = payload

            # set auditable
            auditable = {
                'vector': variation,
                'payload': payload,
                'value': payload
            }

            yield auditable


class TextAuditor(_Auditor):
    """
    Audits parts of text data. It audits by replacing text data with payloads from the given check.
    """
    key = "text"
    name = "Text Data"
    description = "Audits by replacing plain text data"
    handlers = [
        _TextValueHandler
    ]
