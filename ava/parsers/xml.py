from copy import deepcopy
from defusedxml import ElementTree
from defusedxml.ElementTree import ParseError
from ava.common.exception import InvalidFormatException


class XmlDocument:
    """
    This class provides methods for manipulating XML in string format. Its methods replace text within the XML with
    another string value.
    """
    def __init__(self, xml_string):
        """Parse and count"""
        self._root = self._parse_xml(xml_string)
        self._count = self._get_count()
        self.root_tag = self._root.tag

    def _parse_xml(self, xml_string):
        """
        Parse the XML string and return the root element.
        :param xml_string: XML as string
        :return: root element
        """
        # parse
        try:
            root = ElementTree.fromstring(xml_string)
        except ParseError:
            raise InvalidFormatException("Unable to parse XML string")

        # return
        return root

    def _get_count(self):
        """
        Counts the number of text instances within the XML.
        :return: count number
        """
        count = 0

        # count each text instance
        for element in self._root.iter():
            if element.text:
                count += 1

        # return
        return count

    def _replace_at(self, index):
        """
        Replaces the text instance at the given index with braces for use with string formatting. String formatting in
        replace_text() allows for XML characters, such as &, to be set within the text.
        :param index: index number
        :return: replacement string with format braces
        """
        replacement = ""

        # copy over
        root = deepcopy(self._root)

        # iterate
        current = -1
        for element in root.iter():
            # count
            if element.text:
                current += 1

                # replace at index
                if current == index:
                    element.text = '{}'
                    replacement = ElementTree.tostring(root, encoding="unicode")
                    break

        # return
        return replacement

    def replace(self, value):
        """
        Replaces each text instance within the XML with the given value. Returns all instances with the text replaced
        one-by-one.
        :param value: value string
        :return: list of replacements
        """
        # replace each text instance
        for i in range(self._count):
            replacement = self._replace_at(i)
            yield replacement.format(value)
