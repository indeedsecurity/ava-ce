import base64
import logging
import re
import string
from urllib import parse
from ava.common import utility
from ava.common.check import _Check
from requests.exceptions import Timeout, ConnectionError, TooManyRedirects
from requests_toolbelt.utils import dump


# configure logging
logger = logging.getLogger(__name__)


class _Handler:
    """
    Handles auditing of checks for Auditors. There are subclasses for each type of check.
    """
    handles = _Check

    def __init__(self, configs, auditor, session):
        """Set AVA configs, auditor, and session"""
        self._configs = configs
        self._auditor = auditor
        self._session = session

    def execute_check(self, check, chunks):
        """Method should be implemented by children"""
        return []

    def _filter_skips(self, targets):
        """
        Checks the list of HTTP targets, such as parameters, cookies, or headers, against skips. Targets not in
        skips are returned.
        :param targets: dictionary of targets
        :return: list of targets without skips
        """
        # check skips
        if not self._configs['skips']:
            return targets

        # add targets not in skips
        filtered = [target for target in targets if target not in self._configs['skips']]

        return filtered

    def _filter_ignores(self, matches):
        """
        Check the list of ignores and remove any matches.
        :param matches: list of matches
        :return: list of matches without ignores
        """
        # check ignores
        if not self._configs['ignores']:
            return matches

        # add matches not in ignores
        filtered = [(category, value) for category, value in matches if value not in self._configs['ignores']]

        return filtered

    def _send_request(self, vector):
        """
        Wrapper method for sending GET and POST requests to server. It sets HTTP specific values, such as User-Agent,
        timeout, and proxy. It also handles exceptions and returns None, if the request was not successful. This
        behavior is intended to reduce the overhead involved with calling the method.
        :param vector: vector dictionary
        :return: response object or None
        """
        try:
            # send http request
            response = utility.send_http_request(self._session, vector, self._configs)
        except (ConnectionError, ConnectionResetError, Timeout, TooManyRedirects) as e:
            err = re.findall("[A-Z][a-z]+", type(e).__name__)
            logger.warning("%s for '%s'. Ignoring.", ' '.join(err).capitalize(), parse.quote(vector['url'], safe='/:'))
            response = None

        return response

    def _print_status(self, vulnerable, check, url, target, value):
        """
        Prints the status of the current vector. Vulnerable vectors print at INFO and non-vulnerable print at DEBUG.
        :param vulnerable: boolean, if vector is vulnerable
        :param check: check object
        :param url: URL string
        :param target: target string
        :param value: payload string
        """
        # encode value
        value = parse.quote_plus(value, safe=string.punctuation)

        # print status
        if vulnerable:
            logger.info("%s : Found %s [%s : %s : %s]", self._auditor.name, check.name, url, target, value)
        else:
            logger.debug("%s : %s [%s : %s : %s]", self._auditor.name, check.name, url, target, value)

    def _generate_issue(self, check, vector, target, value, response):
        """
        Generates an issue for later inclusion in reports. URL, method, headers, and body are extracted from request.
        Status code, reason, headers, and body are extracted from response.
        :param check: check object
        :param vector: vector dictionary
        :param target: target string
        :param value: payload string
        :param response: response object
        :return: issue as dictionary
        """
        # create issue
        issue = {
            'auditor': self._auditor.key,
            'check': check.key,
            'vector': vector,
            'target': target,
            'value': parse.quote_plus(value, safe=string.punctuation),
            'time': str(response.elapsed),
            'http': base64.b64encode(dump.dump_all(response, request_prefix=b'', response_prefix=b'')).decode()
        }

        return issue
