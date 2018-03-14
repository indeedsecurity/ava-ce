import pytest
from ava.actives.xxe import XmlExternalEntityCheck


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestXmlExternalEntityCheck:
    payloads = [
        '<?xml version="1.0"?><!DOCTYPE ava [<!ENTITY ava SYSTEM "file:///etc/group">]><ava>&ava;</ava>'
    ]

    dynamic = [
        '<?xml version="1.0"?><!DOCTYPE xml [<!ENTITY ava SYSTEM "file:///etc/group">]><xml>&ava;</xml>'
    ]

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="ava")
        return XmlExternalEntityCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads

    def test_payloads_xml(self, check):
        # xml value
        value = "<xml>test</xml>"
        test = check.payloads("http://www.example.com/", "xml", value)
        assert test == self.payloads + self.dynamic

    def test_payloads_non_xml(self, check):
        # non-xml value
        value = "avascan"
        test = check.payloads("http://www.example.com/", "xml", value)
        assert test == self.payloads

        # bad xml value
        value = "<this is not xml>"
        test = check.payloads("http://www.example.com/", "xml", value)
        assert test == self.payloads

    def test_check_true_positive(self, check, response):
        html = "<html><head></head><body>{}</body</html>"

        # true positive
        body = "root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:user"
        response.text = html.format(body)
        test = check.check(response, check._payloads[0])
        assert test

    def test_check_true_negative(self, check, response):
        html = "<html><head></head><body>{}</body</html>"

        # true negative
        body = "Error occurred"
        response.text = html.format(body)
        test = check.check(response, check._payloads[0])
        assert not test

        # empty
        response.text = ""
        test = check.check(response, check._payloads[0])
        assert not test
