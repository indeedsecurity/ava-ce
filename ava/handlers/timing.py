from ava.common.check import _TimingCheck
from ava.common.handler import _Handler


class _TimingHandler(_Handler):
    handles = _TimingCheck

    def execute_check(self, check, chunks):
        """
        Audits timing checks by sending original/timing requests and checking the elapsed times between responses.
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
                    value = auditable['value']

                    # send requests
                    original_response = self._send_request(variations['original'])
                    if original_response is None:  # must be None check
                        continue

                    timing_response = self._send_request(variations['timing'])
                    if timing_response is None:  # pragma: no cover
                        continue

                    # check responses
                    responses = {'original': original_response, 'timing': timing_response}
                    vulnerable = check.check(responses, auditable['payload'], auditable['delay'])

                    # print status
                    self._print_status(vulnerable, check, vector['url'], target, value)

                    # check if vulnerable and add to issues
                    if vulnerable:
                        issue = self._generate_issue(check, vector, target, value, responses['timing'])
                        issues.append(issue)
                        break

        return issues

    def _get_targets(self, vector):
        """Method should be implemented by children"""
        return []

    def _generate_variations(self, check, vector, target):
        """Method should be implemented by children"""
        return []
