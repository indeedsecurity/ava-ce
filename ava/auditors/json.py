from copy import copy
from ava.common import utility
from ava.common.auditor import _Auditor
from ava.common.constant import HTTP
from ava.handlers.blind import _BlindHandler
from ava.handlers.differential import _DifferentialHandler
from ava.handlers.timing import _TimingHandler
from ava.handlers.value import _ValueHandler


# metadata
name = __name__
description = "audits json data"


class _JsonValueHandler(_ValueHandler):
    def _get_targets(self, vector):
        """
        Returns list of literal keys for JSON data. Content-Type must be application/json.
        :param vector: vector dictionary
        :return: literal keys as list
        """
        headers = vector['headers']
        targets = []

        # check data
        if not vector['data']:
            return []

        # check content-type
        content_type = headers.get('Content-Type')
        if content_type and content_type.startswith(HTTP.CONTENT_TYPE.JSON):
            parsed = utility.parse_json(vector['data'])
            targets = list(parsed.literals())

        return targets

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for value checks. Variations are created by parsing the JSON and replacing literal at the
        target key with payloads.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        original = vector['data']

        # parse original
        parsed = utility.parse_json(original)
        literals = parsed.literals()

        # each payload for check
        for payload in check.payloads(vector['url'], target, literals[target]):

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


class _JsonDifferentialHandler(_DifferentialHandler):
    def _get_targets(self, vector):
        """
        Returns JSON for the vector. Content-Type must be application/json.
        :param vector: vector dictionary
        :return: JSON as list
        """
        headers = vector['headers']
        targets = []

        # check data
        if not vector['data']:
            return []

        # check content-type
        content_type = headers.get('Content-Type')
        if content_type and content_type.startswith(HTTP.CONTENT_TYPE.JSON):
            parsed = utility.parse_json(vector['data'])
            targets = list(parsed.literals())

        return targets

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for differential checks. Variations are created by parsing the JSON and replacing literals
        one-by-one with true and false payloads.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        original = vector['data']

        # parse original
        parsed = utility.parse_json(original)
        literals = parsed.literals()

        # each payload for check
        for true_payload, false_payload in check.payloads(vector['url'], target, literals[target]):

            # set true vector
            true_variation = copy(vector)
            true_variation['data'] = parsed.replace(target, true_payload)

            # set false vector
            false_variation = copy(vector)
            false_variation['data'] = parsed.replace(target, false_payload)

            # set auditable
            auditable = {
                'vectors': {'true': true_variation, 'false': false_variation},
                'payloads': {'true': true_payload, 'false': false_payload},
                'values': {'true': true_payload, 'false': false_payload}
            }

            yield auditable


class _JsonTimingHandler(_TimingHandler):
    def _get_targets(self, vector):
        """
        Returns JSON for the vector. Content-Type must be application/json.
        :param vector: vector dictionary
        :return: JSON as list
        """
        headers = vector['headers']
        targets = []

        # check data
        if not vector['data']:
            return []

        # check content-type
        content_type = headers.get('Content-Type')
        if content_type and content_type.startswith(HTTP.CONTENT_TYPE.JSON):
            parsed = utility.parse_json(vector['data'])
            targets = list(parsed.literals())

        return targets

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for timing checks. Variations are created by parsing the JSON and replacing literals
        one-by-one with timing payloads.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        original = vector['data']

        # parse original
        parsed = utility.parse_json(original)
        literals = parsed.literals()

        # each payload for check
        for payload, delay in check.payloads(vector['url'], target, literals[target]):

            # set original vector
            original_variation = copy(vector)

            # set timing vector
            timing_variation = copy(vector)
            timing_variation['data'] = parsed.replace(target, payload)

            # set auditable
            auditable = {
                'vectors': {'original': original_variation, 'timing': timing_variation},
                'payload': payload,
                'value': payload,
                'delay': delay
            }

            yield auditable


class _JsonBlindHandler(_BlindHandler):
    def _get_targets(self, vector):
        """
        Returns JSON for the vector. Content-Type must be application/json.
        :param vector: vector dictionary
        :return: JSON as list
        """
        headers = vector['headers']
        targets = []

        # check data
        if not vector['data']:
            return []

        # check content-type
        content_type = headers.get('Content-Type')
        if content_type and content_type.startswith(HTTP.CONTENT_TYPE.JSON):
            parsed = utility.parse_json(vector['data'])
            targets = list(parsed.literals())

        return targets

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for blind checks. Variations are created by parsing the JSON and replacing literals
        one-by-one with payloads.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        original = vector['data']

        # parse original
        parsed = utility.parse_json(original)
        literals = parsed.literals()

        # each payload for check
        for payload in check.payloads(vector['url'], target, literals[target]):

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


class JsonAuditor(_Auditor):
    """
    Audits literals in JSON objects. It audits by parsing the JSON object and replacing literals one-by-one
    with payloads from the given check.
    """
    key = "json"
    name = "JSON Data"
    description = "Audits by replacing literals in JSON objects"
    handlers = [
        _JsonValueHandler,
        _JsonDifferentialHandler,
        _JsonTimingHandler,
        _JsonBlindHandler
    ]
