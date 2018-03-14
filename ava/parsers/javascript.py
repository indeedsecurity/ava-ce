class JavaScriptParser:
    """
    Parser to remove strings and comments from JavaScript text. This allows for the detection of XSS vulnerabilities
    within a JavaScript context. This object is an iterator. Each instance can only be used once.
    """
    def __init__(self, text):
        """Initialize text, length, and index"""
        self._text = text
        self._length = len(text)
        self._index = -1

    def __iter__(self):
        """
        Return self for iteration.
        :return: self instance
        """
        return self

    def __next__(self):
        """
        Get the next character in text and forward the index. If the index is greater than the length of text,
        then raise a StopIteration exception.
        :return: next character
        """
        self._index += 1

        # get character
        if self._index < self._length:
            return self._text[self._index]
        else:
            raise StopIteration()

    def _peek(self):
        """
        Get the next character in text, but do no forward the index. If the index is greater than the length of text,
        then return an empty string.
        :return: next character
        """
        index = self._index + 1

        # get character
        if index < self._length:
            return self._text[index]
        else:
            return ''

    def _strip_string(self, quote):
        """
        Forward the index past the current string. This is achieved by forwarding the index until the given single
        or double quote is detected. Escaped quotes are ignored.
        :param quote: quote character
        """
        escaped = False

        for char in iter(self):
            # check backslash
            if char == '\\' and not escaped:
                escaped = True
                continue

            # check matching quote
            if char == quote and not escaped:
                return

            # disable escape
            if escaped:
                escaped = False

    def _strip_comment(self, start):
        """
        Forward the index past the current comment. This is achieved by forwarding the index until either a newline for
        single line comments or '*/' for multi-line comments is detected.
        :param start: comment characters
        """
        end = '\n' if start == "//" else "*/"

        for char in iter(self):
            # single line
            if end == '\n' and self._peek() == end:
                return

            # multi-line
            if end == '*/' and char + self._peek() == end:
                self.__next__()
                return

    def strip(self):
        """
        Strip strings and comments from JavaScript and return the remaining text. This can be used for the detection
        of XSS vulnerabilities within a JavaScript context.
        :return: stripped text
        """
        remainder = []

        # check text
        if not self._text:
            return ""

        for char in iter(self):
            # check for comments
            if char == '/' and self._peek() in ['/', '*']:
                self._strip_comment(char + self._peek())
                continue

            # check for quotes
            if char in ['"', "'"]:
                self._strip_string(char)
                continue

            # store character
            remainder.append(char)

        # combine
        return ''.join(remainder)
