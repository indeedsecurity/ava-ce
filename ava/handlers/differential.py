from ava.common.check import _DifferentialCheck
from ava.common.handler import _Handler


class _DifferentialHandler(_Handler):
    handles = _DifferentialCheck

    def execute_check(self, check, chunks):
        """
        Audits differential checks by applying a true/false payloads and checking the difference between responses.
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
                    variations = auditable['vectors']
                    values = auditable['values']

                    # send requests
                    true_response = self._send_request(variations['true'])
                    if true_response is None:  # must be None check
                        continue

                    false_response = self._send_request(variations['false'])
                    if false_response is None:  # pragma: no cover
                        continue

                    # check responses
                    responses = {'true': true_response, 'false': false_response}
                    vulnerable = check.check(responses, auditable['payloads'])

                    # print status
                    self._print_status(vulnerable, check, vector['url'], target, values['true'])

                    # check if vulnerable and add to issues
                    if vulnerable:
                        issue = self._generate_issue(check, vector, target, values['true'], responses['true'])
                        issues.append(issue)
                        break

        return issues

    def _get_targets(self, vector):
        """Method should be implemented by children"""
        return []

    def _generate_variations(self, check, vector, target):
        """Method should be implemented by children"""
        return []
