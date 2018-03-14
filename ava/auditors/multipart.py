from copy import copy
from ava.common import utility
from ava.common.auditor import _Auditor
from ava.common.constant import HTTP
from ava.handlers.value import _ValueHandler


# metadata
name = __name__
description = "audits multipart data"


class _MultipartValueHandler(_ValueHandler):
    def _get_targets(self, vector):
        """
        Returns list of names for multipart data. Content-Type must be multipart/form-data.
        :param vector: vector dictionary
        :return: names as list
        """
        headers = vector['headers']
        targets = []

        # check data
        if not vector['data']:
            return []

        # check content-type
        content_type = headers.get('Content-Type')
        if content_type and content_type.startswith(HTTP.CONTENT_TYPE.MULTIPART):
            parsed = utility.parse_multipart(vector['data'], content_type)
            targets = list(parsed.names())

        return targets

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for value checks. Variations are created by parsing the multipart data and replacing
        value at the target name with payloads.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        original = vector['data']
        headers = vector['headers']

        # parse original
        parsed = utility.parse_multipart(original, headers['Content-Type'])
        names = parsed.names()

        # each payload for check
        for payload in check.payloads(vector['url'], target, names[target]):
            # set vector
            variation = copy(vector)
            variation['data'] = parsed.replace(target, payload)

            # set auditable
            auditable = {
                'vector': variation,
                'payload': payload,
                'value': payload
            }

            yield auditable


class MultipartAuditor(_Auditor):
    """
    Audits parts of multipart form data. It audits by parsing the multipart data and replacing parts one-by-one
    with payloads from the given check.
    """
    key = "multipart"
    name = "Multipart Data"
    description = "Audits by replacing parts of multipart form data"
    handlers = [
        _MultipartValueHandler
    ]
