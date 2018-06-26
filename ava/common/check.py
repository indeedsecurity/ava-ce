from bs4 import BeautifulSoup
from difflib import SequenceMatcher


class _Check:
    """
    Parent check class. All other checks should be a subclass of this class.
    """
    key = "check"
    name = "Check"
    description = "Parent check"


class _BlindCheck(_Check):
    """
    These checks identify issues in internal systems. The payloads include a host that listens for callbacks from the
    internal system. These checks do not raise issues directly. The listener server maintains issue information.
    """
    _payloads = []  # attribute should be populated by children's __init___ method
    example = "Payload example"

    def payloads(self, url, target, value):
        """
        Returns the check's payloads. Children can override to provide dynamic payloads.
        :param url: url value
        :param target: target name
        :param value: target value
        :return: list of payloads
        """
        # return
        return self._payloads

    def _check_payloads(self, payloads):
        """
        Checks if the payloads are adoptable for this class and modify the payloads to adjust to check function.
        InvalidFormatException is raised, if a payload is not adoptable.
        Children can override.
        :param payloads: list of payloads
        :return: list of modified payloads
        """
        return payloads

    def set_payloads(self, payloads):
        """
        Overwrite the check's payloads.
        :param payloads: list of payloads
        """
        self._payloads = self._check_payloads(payloads)

    def add_payloads(self, payloads):
        """
        Add payloads to the check's payloads.
        :param payloads: list of payloads
        """
        self._payloads += self._check_payloads(payloads)


class _PassiveCheck(_Check):
    """
    These checks identify sensitive information in responses. The response from the server may be checked for social
    security numbers, credit card numbers, email addresses, etc. These checks do not have payloads.
    """
    def check(self, response):
        """Method should be implemented by children"""
        pass


class _ActiveCheck(_Check):
    """
    Parent class for active checks. Subclasses include simple, differential, and timing checks.
    """
    _payloads = []  # attribute should be populated by children's __init___ method
    example = "Payload example"

    def payloads(self, url, target, value):
        """
        Returns the check's payloads. Children can override to provide dynamic payloads.
        :param url: url value
        :param target: target name
        :param value: target value
        :return: list of payloads
        """
        return self._payloads

    def _check_payloads(self, payloads):
        """
        Checks if the payloads are adoptable for this class and modify the payloads to adjust to check function.
        InvalidFormatException is raised, if a payload is not adoptable.
        Children can override.
        :param payloads: list of payloads
        :return: list of modified payloads
        """
        return payloads

    def set_payloads(self, payloads):
        """
        Overwrite the check's payloads.
        :param payloads: list of payloads
        """
        self._payloads = self._check_payloads(payloads)

    def add_payloads(self, payloads):
        """
        Add payloads to the check's payloads.
        :param payloads: list of payloads
        """
        self._payloads += self._check_payloads(payloads)


class _ValueCheck(_ActiveCheck):
    """
    These checks perform value analysis to identify issues. For instance, they may analyze text in HTML bodies or
    values in HTTP headers. These checks audit using a single payload and single response.
    """
    def check(self, response, payload):
        """Method should be implemented by children"""
        pass


class _DifferentialCheck(_ActiveCheck):
    """
    These checks perform differential analysis between true and false payloads to identify issues. If the difference
    between the payloads' responses is below a threshold, then an issue is raised. These checks audit using two
    payloads and two responses.
    """
    _threshold = 0.90

    def check(self, responses, payload):
        """
        Checks for issues by looking for the difference between response bodies. HTML script and style tags are
        removed from HTML responses.
        :param responses: response objects from server
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # extract
        true_response = responses['true']
        false_response = responses['false']

        # check response
        if not true_response.text or not false_response.text:
            return False

        # check status code
        if true_response.status_code != false_response.status_code:
            return False

        # soup
        true_soup = BeautifulSoup(true_response.text, "html.parser")
        false_soup = BeautifulSoup(false_response.text, "html.parser")

        # remove script and style tags
        excludes = ["script", "style"]
        true_tags = [tag for tag in true_soup.find_all(text=True) if tag.parent.name not in excludes]
        false_tags = [tag for tag in false_soup.find_all(text=True) if tag.parent.name not in excludes]

        # join back
        true_text = ' '.join(true_tags)
        false_text = ' '.join(false_tags)

        # calculate ratio
        sequence = SequenceMatcher(None, true_text, false_text)
        ratio = sequence.quick_ratio()

        # check difference
        if ratio < _DifferentialCheck._threshold:
            return True
        else:
            return False


class _TimingCheck(_ActiveCheck):
    """
    These checks perform timing analysis from delays to identify issues. If the response's elapsed time is above a
    threshold, then an issue is raised. These checks audit using one payload, the payload's delay, and one response.
    """
    _padding = 0.50

    def check(self, responses, payload, delay):
        """
        Checks for issues by measuring the elapsed time of the response. It uses a padding to prevent slow endpoints
        from producing false positives.
        :param responses: response objects from server
        :param payload: payload value
        :param delay: time as float
        :return: true if vulnerable, false otherwise
        """
        # extract
        original_response = responses['original']
        timing_response = responses['timing']

        # calculate elapsed time
        original_elapsed = original_response.elapsed.seconds + (original_response.elapsed.microseconds / 1000000)
        timing_elapsed = timing_response.elapsed.seconds + (timing_response.elapsed.microseconds / 1000000)

        # calculate padding
        padding = original_elapsed * _TimingCheck._padding

        # check time
        if timing_elapsed > (delay + padding):
            return True
        else:
            return False

    def _check_payloads(self, payloads):
        """
        Checks if the payloads are adoptable for this class and modify the payloads to adjust to check function.
        InvalidFormatException is raised, if a payload is not adoptable.
        Children can override.
        :param payloads: list of payloads
        :return: list of modified payloads
        """
        return [(payload, 9) for payload in payloads]
