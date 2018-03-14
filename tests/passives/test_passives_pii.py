import pytest
import re
from ava.passives.pii import PersonallyIdentifiableInformationCheck


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestPersonallyIdentifiableInformationCheck:
    regexs = [
        ('email', re.compile(r"\W([\w.+-]+@[\w-]+\.(?:com|org|net|int|edu|gov|mil))\W", re.IGNORECASE)),
        ('ssn', re.compile(r"\W(\d{3}[ -]\d{2}[ -]\d{4})\W", re.IGNORECASE)),
        ('credit card', re.compile(r"\W(4\d{3}[ -]\d{4}[ -]\d{4}[ -]\d{4})\W", re.IGNORECASE)),
        ('credit card', re.compile(r"\W(5[15]\d{2}[ -]\d{4}[ -]\d{4}[ -]\d{4})\W", re.IGNORECASE)),
        ('credit card', re.compile(r"\W((?:6011|6[45]\d{2})[ -]\d{4}[ -]\d{4}[ -]\d{4})\W", re.IGNORECASE)),
        ('credit card', re.compile(r"\W(3[47]\d{2}[ -]\d{6}[ -]\d{5})\W", re.IGNORECASE))
    ]

    @pytest.fixture
    def check(self):
        return PersonallyIdentifiableInformationCheck()

    def test_init(self, check):
        # init
        assert check._regexs == self.regexs

    def test_pii_check_true_positive(self, check, response):
        html = "<html><head></head><body>{}</body></html>"

        # single true positive
        response.text = html.format("email@example.com")
        test = check.check(response)
        assert test == [('email', 'email@example.com')]

        # multiple true positives
        response.text = html.format("contact@example.com, 123-45-6789, 4321-1234-1234-1234")
        test = check.check(response)
        assert sorted(test) == [('credit card', '4321-1234-1234-1234'),
                                ('email', 'contact@example.com'),
                                ('ssn', '123-45-6789')]

    def test_check_true_negative(self, check, response):
        html = "<html><head></head><body>{}</body></html>"

        # true negative
        response.text = html.format("this line does not contain an email address")
        test = check.check(response)
        assert test == []

        # true negative empty
        response.text = ""
        test = check.check(response)
        assert test == []
