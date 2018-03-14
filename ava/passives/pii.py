import re
from ava.common.check import _PassiveCheck


# metadata
name = __name__
description = "checks for personally identifiable information"


class PersonallyIdentifiableInformationCheck(_PassiveCheck):
    """
    Checks for PII by searching each response using regular expressions. PII includes email address, mailing address,
    phone number, social security number, credit card number, etc.
    """
    key = "pii.passive.body"
    name = "Personally Identifiable Information"
    description = "Checks for Personally Identifiable Information in responses"

    def __init__(self):
        regexs = [
            ('email', r"\W([\w.+-]+@[\w-]+\.(?:com|org|net|int|edu|gov|mil))\W"),
            ('ssn', r"\W(\d{3}[ -]\d{2}[ -]\d{4})\W"),
            ('credit card', r"\W(4\d{3}[ -]\d{4}[ -]\d{4}[ -]\d{4})\W"),  # visa
            ('credit card', r"\W(5[15]\d{2}[ -]\d{4}[ -]\d{4}[ -]\d{4})\W"),  # mastercard
            ('credit card', r"\W((?:6011|6[45]\d{2})[ -]\d{4}[ -]\d{4}[ -]\d{4})\W"),  # discover
            ('credit card', r"\W(3[47]\d{2}[ -]\d{6}[ -]\d{5})\W"),  # american express
        ]

        # compile regular expressions
        self._regexs = [(category, re.compile(regex, re.IGNORECASE)) for category, regex in regexs]

    def check(self, response):
        """
        Checks for PII by searching each response using regular expressions.
        :param response: response object
        :return: list of matches as tuples
        """
        matches = []

        # check response body
        if not response.text:
            return []

        # check each regular expression
        for category, regex in self._regexs:
            values = regex.findall(response.text)

            # add unique matches
            for value in set(values):
                matches.append((category, value))

        return matches
