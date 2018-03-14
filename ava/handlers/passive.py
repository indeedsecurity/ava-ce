import logging
from ava.common.check import _PassiveCheck
from ava.common.handler import _Handler


# configure logging
logger = logging.getLogger(__name__)


class _PassiveHandler(_Handler):
    handles = _PassiveCheck

    def execute_check(self, check, chunks):
        """
        Audits passive checks by sending a single request and checking a single response.
        :param check: check object
        :param chunks: vector list
        :return: issues list
        """
        issues = []

        # check each vector
        for vector in chunks:
            url = vector['url']

            # send request
            response = self._send_request(vector)
            if response is None:  # must be None check
                continue

            # check response
            matches = check.check(response)

            # filter matches
            filtered = self._filter_ignores(matches)

            # print status manually
            logger.debug("%s : %s [%s]", self._auditor, check.name, url)

            # print each match
            for category, value in filtered:
                self._print_status(True, check, url, category, value)

            # add each match to issues
            for category, value in filtered:
                issue = self._generate_issue(check, vector, category, value, response)
                issues.append(issue)

        return issues
