import re
from urllib.parse import urlparse
from ava.common.check import _BlindCheck
from ava.common.exception import InvalidFormatException
from ava.common.utility import replace_with_unicode

# metadata
name = __name__
description = "checks for server-side request forgery"

class ServerSideRequestForgeryCheck(_BlindCheck):
    """
    Checks for Server-Side Request Forgery by executing callbacks. A listener server should be deployed and configured
    in order to listen for callbacks from the payloads.
    """
    key = "ssrf.blind.callback"
    name = "Server-Side Request Forgery"
    description = "checks for server-side request forgery by specifying a listener server's url"
    example = "{}://{}/"

    def __init__(self, listener):
        """
        Generate payloads by including the listener's endpoint into the templates. Payloads can reference the listener
        directly. Direct payloads are shorter and may bypass length restrictions.
        :param listener: listener endpoint
        """
        payloads = [
            '{}://{}/',
            '{}://example.com#@{}/',
            '{}://foo@{}@example.com/',
            '{}://foo@{} @example.com/'
        ]

        # parse the url and assign payloads
        parsed = urlparse(listener)
        self._payloads = [payload.format(parsed.scheme, parsed.netloc) for payload in payloads]

        # replace hostname with unicode
        encoded_hostname = replace_with_unicode(parsed.hostname)
        payload = "{}://{}".format(parsed.scheme, encoded_hostname)
        payload += ":{}/".format(parsed.port) if parsed.port else "/"
        self._payloads.append(payload)

        # assign listener
        self._listener = listener

    def _check_payloads(self, payloads):
        """
        Checks if the payloads are adoptable for this class and modify the payloads to adjust to check function.
        InvalidFormatException is raised, if a payload is not adoptable.
        :param payloads: list of payloads
        :return: list of modified payloads
        """
        # parse url
        parsed = urlparse(self._listener)
        for i, payload in enumerate(payloads):
            if re.match(r"\{\}.*\{\}", payload) is None:
                raise InvalidFormatException("Payload of {} must include two of '{{}}' which will be replaced with scheme and host name".format(self.key))
            payloads[i] = payload.format(parsed.scheme, parsed.netloc)
        return payloads
