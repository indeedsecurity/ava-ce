import re

from ava.common.check import _ValueCheck

# metadata
name = __name__
description = "checks for path traversal"


class PathTraversalCheck(_ValueCheck):
    """
    Checks for Path Traversal by accessing local files. The payloads use path traversal to locate /etc/group.
    """
    key = "path.value.file"
    name = "Path Traversal"
    description = "Checks for Path Traversal by accessing local files"

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
