import pytest
import pickle
from defusedxml import ElementTree
from ava.common.exception import InvalidFormatException
from ava.parsers.xml import XmlDocument


@pytest.fixture
def xmls():
    xmls = [
        "<avascan>one text</avascan>",
        "<avascan><test>one text</test><test>two texts</test></avascan>",
        "<avascan><outer><inner>nested text</inner></outer></avascan>",
        "<avascan><test></test><outer><inner></inner></outer></avascan>"
    ]
    return xmls


class TestXmlDocument:

    def test_parse_xml_positive(self, xmls):
        xml = XmlDocument("<test></test>")

        # one text
        test = xml._parse_xml(xmls[0])
        assert pickle.dumps(test) == pickle.dumps(ElementTree.fromstring(xmls[0]))

        # two texts
        test = xml._parse_xml(xmls[1])
        assert pickle.dumps(test) == pickle.dumps(ElementTree.fromstring(xmls[1]))

        # nested text
        test = xml._parse_xml(xmls[2])
        assert pickle.dumps(test) == pickle.dumps(ElementTree.fromstring(xmls[2]))

        # no text
        test = xml._parse_xml(xmls[3])
        assert pickle.dumps(test) == pickle.dumps(ElementTree.fromstring(xmls[3]))

    def test_parse_xml_negative(self):
        xml = XmlDocument("<test></test>")

        # bad xml
        with pytest.raises(InvalidFormatException):
            xml._parse_xml("<test><error></test>")

        # not xml
        with pytest.raises(InvalidFormatException):
            xml._parse_xml("not-xml")

    def test_get_count(self, xmls):
        # one text
        parsed = XmlDocument(xmls[0])
        test = parsed._get_count()
        assert test == 1

        # two texts
        parsed = XmlDocument(xmls[1])
        test = parsed._get_count()
        assert test == 2

        # nested text
        parsed = XmlDocument(xmls[2])
        test = parsed._get_count()
        assert test == 1

        # no text
        parsed = XmlDocument(xmls[3])
        test = parsed._get_count()
        assert test == 0

    def test_replace_at(self, xmls):
        # one text
        parsed = XmlDocument(xmls[0])
        test = parsed._replace_at(0)
        assert test == "<avascan>{}</avascan>"

        # two text
        parsed = XmlDocument(xmls[1])
        test = parsed._replace_at(0)
        assert test == "<avascan><test>{}</test><test>two texts</test></avascan>"

        parsed = XmlDocument(xmls[1])
        test = parsed._replace_at(1)
        assert test == "<avascan><test>one text</test><test>{}</test></avascan>"

        # inner text
        parsed = XmlDocument(xmls[2])
        test = parsed._replace_at(0)
        assert test == "<avascan><outer><inner>{}</inner></outer></avascan>"

    def test_replace(self, xmls):
        # one text
        parsed = XmlDocument(xmls[0])
        test = parsed.replace("&replaced;")
        assert list(test) == ["<avascan>&replaced;</avascan>"]

        # two texts
        parsed = XmlDocument(xmls[1])
        test = parsed.replace("&replaced;")
        assert list(test) == ["<avascan><test>&replaced;</test><test>two texts</test></avascan>",
                              "<avascan><test>one text</test><test>&replaced;</test></avascan>"]

        # inner text
        parsed = XmlDocument(xmls[2])
        test = parsed.replace("&replaced;")
        assert list(test) == ["<avascan><outer><inner>&replaced;</inner></outer></avascan>"]

        # no text
        parsed = XmlDocument(xmls[3])
        test = parsed.replace("&replaced;")
        assert list(test) == []
