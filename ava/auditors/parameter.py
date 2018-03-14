from copy import copy
from ava.common.auditor import _Auditor
from ava.common.constant import HTTP
from ava.handlers.value import _ValueHandler
from ava.handlers.differential import _DifferentialHandler
from ava.handlers.timing import _TimingHandler
from ava.handlers.blind import _BlindHandler


# metadata
name = __name__
description = "audits each parameter"


class _QueryParameterValueHandler(_ValueHandler):
    _parameter = 'params'

    def _get_targets(self, vector):
        """
        Returns parameters for the vector.
        :param vector: vector dictionary
        :return: parameter list
        """
        return list(vector[self._parameter])

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for value checks. Variations are created by replacing and appending values.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        # get originals
        originals = vector[self._parameter]

        # each payload for check
        for payload in check.payloads(vector['url'], target, originals[target]):

            # each variation replace and append
            replace = ''
            for value in [replace, originals[target]]:
                # set target
                params = copy(originals)
                params[target] = value + payload

                # set vector
                variation = copy(vector)
                variation[self._parameter] = params

                # set auditable
                auditable = {
                    'vector': variation,
                    'payload': payload,
                    'value': value + payload
                }

                yield auditable


class _QueryParameterDifferentialHandler(_DifferentialHandler):
    _parameter = 'params'

    def _get_targets(self, vector):
        """
        Returns parameters for the vector.
        :param vector: vector dictionary
        :return: parameter list
        """
        return list(vector[self._parameter])

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for differential checks. Variations are created by replacing and appending values.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        # get originals
        originals = vector[self._parameter]

        # each payload for check
        for true_payload, false_payload in check.payloads(vector['url'], target, originals[target]):

            # each variation replace and append
            replace = ''
            for value in [replace, originals[target]]:
                # set true vector
                true_params = copy(originals)
                true_params[target] = value + true_payload
                true_variation = copy(vector)
                true_variation[self._parameter] = true_params

                # set false vector
                false_params = copy(originals)
                false_params[target] = value + false_payload
                false_variation = copy(vector)
                false_variation[self._parameter] = false_params

                # set auditable
                auditable = {
                    'vectors': {'true': true_variation, 'false': false_variation},
                    'payloads': {'true': true_payload, 'false': false_payload},
                    'values': {'true': value + true_payload, 'false': value + false_payload}
                }

                yield auditable


class _QueryParameterTimingHandler(_TimingHandler):
    _parameter = 'params'

    def _get_targets(self, vector):
        """
        Returns parameters for the vector.
        :param vector: vector dictionary
        :return: parameter list
        """
        return list(vector[self._parameter])

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for timing checks. Variations are created by replacing and appending values.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        # get originals
        originals = vector[self._parameter]

        # each payload for check
        for payload, delay in check.payloads(vector['url'], target, originals[target]):

            # each variation replace and append
            replace = ''
            for value in [replace, originals[target]]:
                # set original vector
                original_variation = copy(vector)

                # set timing vector
                timing_params = copy(originals)
                timing_params[target] = value + payload
                timing_variation = copy(vector)
                timing_variation[self._parameter] = timing_params

                # set auditable
                auditable = {
                    'vectors': {'original': original_variation, 'timing': timing_variation},
                    'payload': payload,
                    'value': value + payload,
                    'delay': delay
                }

                yield auditable


class _QueryParameterBlindHandler(_BlindHandler):
    _parameter = 'params'

    def _get_targets(self, vector):
        """
        Returns parameters for the vector.
        :param vector: vector dictionary
        :return: parameter list
        """
        return list(vector[self._parameter])

    def _generate_variations(self, check, vector, target):
        """
        Generates variations for blind checks. Variations are created by replacing and appending values.
        :param check: check object
        :param vector: vector dictionary
        :param target: target key
        :return: list of variations
        """
        # get originals
        originals = vector[self._parameter]

        # each payload for check
        for payload in check.payloads(vector['url'], target, originals[target]):

            # each variation replace and append
            replace = ''
            for value in [replace, originals[target]]:
                # set target
                params = copy(originals)
                params[target] = value + payload

                # set vector
                variation = copy(vector)
                variation[self._parameter] = params

                # set auditable
                auditable = {
                    'vector': variation,
                    'payload': payload,
                    'value': value + payload
                }

                yield auditable


class QueryParameterAuditor(_Auditor):
    """
    Audits each parameter of each vector. It audits by replacing parameter values with a payload and then appending
    parameter values with a payload. It implements _execute_check(), which is passed a chunk of vectors and returns
    a list of issues. Vectors without parameters are skipped.
    """
    key = "parameter.query"
    name = "Query Parameters"
    description = "Audits by replacing and appending payloads to each query string parameter"
    handlers = [
        _QueryParameterValueHandler,
        _QueryParameterDifferentialHandler,
        _QueryParameterTimingHandler,
        _QueryParameterBlindHandler
    ]


class _PostParameterValueHandler(_QueryParameterValueHandler):
    _parameter = 'data'

    def _get_targets(self, vector):
        """
        Returns parameters for the vector. Content-Type must be x-www-form-urlencoded.
        :param vector: vector dictionary
        :return: parameter list
        """
        headers = vector['headers']
        targets = []

        # check if parameters
        if not isinstance(vector[self._parameter], dict):
            return []

        # check content-type
        content_type = headers.get('Content-Type')
        if content_type and content_type.startswith(HTTP.CONTENT_TYPE.FORM):
            targets = list(vector[self._parameter])

        return targets


class _PostParameterDifferentialHandler(_QueryParameterDifferentialHandler):
    _parameter = 'data'

    def _get_targets(self, vector):
        """
        Returns parameters for the vector. Content-Type must be x-www-form-urlencoded.
        :param vector: vector dictionary
        :return: parameter list
        """
        headers = vector['headers']
        targets = []

        # check if parameters
        if not isinstance(vector[self._parameter], dict):
            return []

        # check content-type
        content_type = headers.get('Content-Type')
        if content_type and content_type.startswith(HTTP.CONTENT_TYPE.FORM):
            targets = list(vector[self._parameter])

        return targets


class _PostParameterTimingHandler(_QueryParameterTimingHandler):
    _parameter = 'data'

    def _get_targets(self, vector):
        """
        Returns parameters for the vector. Content-Type must be x-www-form-urlencoded.
        :param vector: vector dictionary
        :return: parameter list
        """
        headers = vector['headers']
        targets = []

        # check if parameters
        if not isinstance(vector[self._parameter], dict):
            return []

        # check content-type
        content_type = headers.get('Content-Type')
        if content_type and content_type.startswith(HTTP.CONTENT_TYPE.FORM):
            targets = list(vector[self._parameter])

        return targets


class _PostParameterBlindHandler(_QueryParameterBlindHandler):
    _parameter = 'data'

    def _get_targets(self, vector):
        """
        Returns parameters for the original vector. Content-Type must be x-www-form-urlencoded.
        :param vector: vector dictionary
        :return: parameter list
        """
        headers = vector['headers']
        targets = []

        # check if parameters
        if not isinstance(vector[self._parameter], dict):
            return []

        # check content-type
        content_type = headers.get('Content-Type')
        if content_type and content_type.startswith(HTTP.CONTENT_TYPE.FORM):
            targets = list(vector[self._parameter])

        return targets


class PostParameterAuditor(QueryParameterAuditor):
    """
    Audits each parameter of each vector. It audits by replacing parameter values with a payload and then appending
    parameter values with a payload. It implements _execute_check(), which is passed a chunk of vectors and returns
    a list of issues. Vectors without parameters are skipped.
    """
    key = "parameter.post"
    name = "Post Parameters"
    description = "Audits by replacing and appending payloads to each post data parameter"
    handlers = [
        _PostParameterValueHandler,
        _PostParameterDifferentialHandler,
        _PostParameterTimingHandler,
        _PostParameterBlindHandler
    ]
