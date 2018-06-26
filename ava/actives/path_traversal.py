import re

from ava.common.check import _ValueCheck
from ava.common.exception import InvalidFormatException

# metadata
name = __name__
description = "checks for path traversal"


class PathTraversalCheck(_ValueCheck):
    """
    Checks for Path Traversal by accessing local files. The payloads use path traversal to locate /etc/group.
    """
    key = "path.value.file"
    name = "Path Traversal"
    description = "checks for path traversal by accessing local files"
    example = "../etc/group"

    def __init__(self):
        """Define static payloads"""
        self._payloads = [
            'etc/group',
            '/etc/group',
            '../etc/group',
            '../../etc/group',
            '../../../etc/group',
            '../../../../etc/group',
            '../../../../../etc/group',
            '../../../../../../etc/group',
            '../../../../../../../etc/group',
            '../../../../../../../../etc/group',
            '../../../../../../../../../etc/group'
        ]

    def check(self, response, payload):
        """
        Checks for Path Traversal by looking for /etc/group entries in the response's body.
        :param response: response object from server
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # check response body
        if not response.text:
            return False

        # check entries
        # group:x:id:users
        regex = r"(\w+:x:\d+:[\w,]*\W+)+"
        if re.search(regex, response.text):
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
        for i, payload in enumerate(payloads):
            if 'etc/group' not in payload:
                raise InvalidFormatException("Payload of {} must include 'etc/group' as a part of path".format(self.key))
        return payloads
