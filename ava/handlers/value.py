from ava.common.check import _ValueCheck
from ava.common.handler import _Handler


class _ValueHandler(_Handler):
    handles = _ValueCheck

    def execute_check(self, check, chunks):
        """
        Audits simple checks by applying a single payload and checking a single response.
        :param check: check object
        :param chunks: vector list
        :return: issues list
        """
        issues = []

        # audit each vector
        for vector in chunks:

            # get targets
            targets = self._get_targets(vector)
            if not targets:
                continue

            # audit each target without skips
            for target in self._filter_skips(targets):

                # audit each variation
                for auditable in self._generate_variations(check, vector, target):
                    variation = auditable['vector']

                    # send request
                    response = self._send_request(variation)
                    if response is None:  # must be None check, responses suppressed with if not check
                        continue

                    # check response
                    vulnerable = check.check(response, auditable['payload'])

                    # print status
                    self._print_status(vulnerable, check, vector['url'], target, auditable['value'])

                    # check if vulnerable and add to issues
                    if vulnerable:
                        issue = self._generate_issue(check, vector, target, auditable['value'], response)
                        issues.append(issue)
                        break

        # return
        return issues

    def _get_targets(self, vector):
        """Method should be implemented by children"""
        return []

    def _generate_variations(self, check, vector, target):
        """Method should be implemented by children"""
        return []
