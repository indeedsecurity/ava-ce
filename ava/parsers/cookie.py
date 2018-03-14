import re
from copy import copy


class SimpleCookie:
    """
    This is for simple cookies. They are normally single values. The entire value can be replaced with a payload.
    """
    def __init__(self, cookie):
        """Sets the string and removes quotes."""
        self._value = cookie
        self._quoted = False

        # check quotes
        if len(self._value) > 1 and self._value.startswith('"') and self._value.endswith('"'):
            self._value = self._value[1:-1]
            self._quoted = True

    def replace(self, payload):
        """
        Replace entire cookie value and add back quotes. List will have a single item.
        :param payload: payload string
        :return: list of replacements
        """
        # check quotes
        if self._quoted:
            yield '"' + payload + '"'
        else:
            yield payload


class ComplexCookie(SimpleCookie):
    """
    This is for complex cookie. They are cookie strings that contain list of key/value pairs delimited by &, :, and =.
    String are decomposed into key/value pairs. Values can be replaced with payloads within a re-created cookie string.
    """
    def __init__(self, cookie):
        """Sets the string, parses the cookie into tokens, and sets the value count."""
        super().__init__(cookie)

        # parse
        symbols, count = self._parse_cookie()
        self._symbols = symbols
        self._count = count

    def _parse_cookie(self):
        """
        Parse the cookie into a set of tokens to specify key/value pairs and delimiters. Cookie strings are decomposed
        by =, then :, then & into symbols. Key/value pairs can be delimited by = or :. Lists of key/value pairs can be
        delimited by & or :.
        :return: list of symbols and count
        """
        # deconstruct
        symbols = re.split(r"([=:&])", self._value)

        # calculate last symbol and count
        # index = (symbol - 2) / 4
        last = (len(symbols) - 3) // 4
        count = last + 1

        return symbols, count

    def _replace_at(self, index, payload):
        """
        Replace value at specified index with given payload. This is used by replace_values() to replace values
        individually.
        :param index: value index as integer
        :param payload: payload string
        :return: replacement string
        """
        replacement = copy(self._symbols)

        # replace value at index
        # symbol = (index * 4) + 2
        current = (index * 4) + 2
        replacement[current] = payload

        # check quotes and stringify
        if self._quoted:
            return '"' + ''.join(replacement) + '"'
        else:
            return ''.join(replacement)

    def replace(self, payload):
        """
        Replace each value of key/value pairs within the cookie string with given payload. Values are replaced
        individually and returned as a list of replacements.
        :param payload: payload string
        :return: list of replacements
        """
        # replace as if simple cookie
        yield next(super().replace(payload))

        # replace each value individually
        for i in range(self._count):
            yield self._replace_at(i, payload)
