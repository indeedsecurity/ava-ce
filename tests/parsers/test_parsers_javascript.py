import pytest

from ava.parsers.javascript import JavaScriptParser


class TestJavaScriptParser:

    @pytest.fixture
    def scripts(self):
        scripts = [
            '''var x = "test";''',
            '''var x = 'test';''',
            '''var x = 'test a "quote"';''',
            '''var x = "test a 'quote'";''',
            '''var x = "test an \\"escaped\\" quote";''',
            '''var x = 'test an \\'escaped\\' quote';''',
            '''var x = "test" + function() + "test";''',
            '''var x = 'test' + function() + 'test';''',
            '''var x = "test"; function(); //"test";''',
            '''var x = 'test'; function(); //'test';''',
            '''var x = "test comments"; // ignore this''',
            '''var x = "test " + /* it's a // mixed comment */ + "comments";'''
        ]
        return scripts

    def test_next_positive(self, scripts):
        parser = JavaScriptParser(scripts[0])

        # first character
        test = parser.__next__()
        assert test == 'v'
        assert parser._index == 0

        # middle character
        parser._index = 8
        test = parser.__next__()
        assert test == 't'
        assert parser._index == 9

        # last character
        parser._index = 13
        test = parser.__next__()
        assert test == ';'
        assert parser._index == 14

    def test_next_negative(self, scripts):
        parser = JavaScriptParser(scripts[0])

        # end of text
        parser._index = parser._length - 1
        with pytest.raises(StopIteration):
            parser.__next__()

        # past length
        parser._index = parser._length + 1
        with pytest.raises(StopIteration):
            parser.__next__()

    def test_peek_positive(self, scripts):
        parser = JavaScriptParser(scripts[0])

        # first character
        test = parser._peek()
        assert test == 'v'
        assert parser._index == -1

        # middle character
        parser._index = 8
        test = parser._peek()
        assert test == 't'
        assert parser._index == 8

        # last character
        parser._index = 13
        test = parser._peek()
        assert test == ';'
        assert parser._index == 13

    def test_peek_negative(self, scripts):
        parser = JavaScriptParser(scripts[0])

        # end of text
        parser._index = parser._length - 1
        test = parser._peek()
        assert test == ''

        # past length
        parser._index = parser._length + 1
        test = parser._peek()
        assert test == ''

    def test_strip_string_positive(self):
        # double quotes
        text = 'test"; function();'
        parser = JavaScriptParser(text)
        parser._strip_string('"')
        assert parser._index == 4

        # single quotes
        text = "test'; function();"
        parser = JavaScriptParser(text)
        parser._strip_string("'")
        assert parser._index == 4

        # mixed quotes
        text = 'test a "quote"\'; function();'
        parser = JavaScriptParser(text)
        parser._strip_string("'")
        assert parser._index == 14

        # escaped quotes
        text = 'test an \\"escaped\\" quote"; function();'
        parser = JavaScriptParser(text)
        parser._strip_string('"')
        assert parser._index == 25

    def test_strip_string_negative(self):
        # unterminated
        text = 'unterminated string'
        parser = JavaScriptParser(text)
        parser._strip_string('"')
        assert parser._index == 19

    def test_strip_comment_single_line(self):
        # last line
        text = "ignore this\n"
        parser = JavaScriptParser(text)
        parser._strip_comment("//")
        assert parser._index == 10

        # more lines
        text = "ignore this\n next line\n"
        parser = JavaScriptParser(text)
        parser._strip_comment("//")
        assert parser._index == 10

        # with apostrophe
        text = "it's a comment to ignore\n next line\n"
        parser = JavaScriptParser(text)
        parser._strip_comment("//")
        assert parser._index == 23

        # with string
        text = 'ignore this "string"\n next line\n'
        parser = JavaScriptParser(text)
        parser._strip_comment("//")
        assert parser._index == 19

    def test_strip_comment_multi_line(self):
        # whole line
        text = "ignore this */\n"
        parser = JavaScriptParser(text)
        parser._strip_comment("/*")
        assert parser._index == 13

        # multi-line
        text = "this comment\nspans multiple\nlines*/\n"
        parser = JavaScriptParser(text)
        parser._strip_comment("/*")
        assert parser._index == 34

        # middle of line
        text = "ignore this */ function();"
        parser = JavaScriptParser(text)
        parser._strip_comment("/*")
        assert parser._index == 13

        # with apostrophe
        text = "it's a comment to ignore */\n"
        parser = JavaScriptParser(text)
        parser._strip_comment("/*")
        assert parser._index == 26

        # with string
        text = 'ignore this "string" */\n'
        parser = JavaScriptParser(text)
        parser._strip_comment("/*")
        assert parser._index == 22

        # with single line comment
        text = "it's a // mixed comment */\n"
        parser = JavaScriptParser(text)
        parser._strip_comment("/*")
        assert parser._index == 25

    def test_strip_with_text(self, scripts):
        # double quotes
        test = JavaScriptParser(scripts[0]).strip()
        assert test == 'var x = ;'

        # single quotes
        test = JavaScriptParser(scripts[1]).strip()
        assert test == 'var x = ;'

        # mixed double quotes
        test = JavaScriptParser(scripts[2]).strip()
        assert test == 'var x = ;'

        # mixed single quotes
        test = JavaScriptParser(scripts[3]).strip()
        assert test == 'var x = ;'

        # escaped double quotes
        test = JavaScriptParser(scripts[4]).strip()
        assert test == 'var x = ;'

        # escaped single quotes
        test = JavaScriptParser(scripts[5]).strip()
        assert test == 'var x = ;'

        # double quotes concatenate
        test = JavaScriptParser(scripts[6]).strip()
        assert test == 'var x =  + function() + ;'

        # single quotes concatenate
        test = JavaScriptParser(scripts[7]).strip()
        assert test == 'var x =  + function() + ;'

        # double quotes statement
        test = JavaScriptParser(scripts[8]).strip()
        assert test == 'var x = ; function(); '

        # single quotes statement
        test = JavaScriptParser(scripts[9]).strip()
        assert test == 'var x = ; function(); '

        # double quotes single line comment
        test = JavaScriptParser(scripts[10]).strip()
        assert test == 'var x = ; '

        # double quote multi-line comment
        '''var x = "test " + /* it's a // comment */ + "comments";'''
        test = JavaScriptParser(scripts[11]).strip()
        assert test == 'var x =  +  + ;'

    def test_strip_empty(self):
        # empty
        test = JavaScriptParser("").strip()
        assert test == ''
