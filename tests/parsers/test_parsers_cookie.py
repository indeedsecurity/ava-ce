import pytest
from ava.parsers.cookie import SimpleCookie, ComplexCookie


@pytest.fixture
def simples():
    simples = [
        '',
        '1',
        "true",
        "1489785928609",
        "tvkeDPiyTQV64x2nEkhhsTg0FGtNCAOX",
        "dGVzdGFiDQo=",
        "dGVzdGENCg=="
    ]

    return simples


@pytest.fixture
def complexes():
    complexes = [
        "key=value",
        "key:value",
        "key1=value1:key2=value2",
        "key1=value1&key2=value2",
        "key1:value1&key2:value2",
        "key11=value11&key21=value21:key12=value12&key22=value22"
    ]

    return complexes


class TestSimpleCookie:

    def test_simple_cookie_init(self, simples):
        # no quotes
        test = SimpleCookie(simples[3])
        assert not test._quoted
        assert test._value == simples[3]

        # with quotes
        test = SimpleCookie('"' + simples[3] + '"')
        assert test._quoted
        assert test._value == simples[3]

    def test_simple_cookie_replace(self, simples):
        payload = "[payload]"

        # no quotes
        cookie = SimpleCookie(simples[3])
        test = cookie.replace(payload)
        assert list(test) == [payload]

        # with quotes
        cookie = SimpleCookie('"' + simples[3] + '"')
        test = cookie.replace(payload)
        assert list(test) == ['"' + payload + '"']


class TestComplexCookie:

    def test_init(self, complexes, mocker):
        # mock
        symbols = ["key", '=', 'value']
        mocker.patch("ava.parsers.cookie.ComplexCookie._parse_cookie", return_value=(symbols, 1))

        # init
        cookie = ComplexCookie(complexes[0])
        assert cookie._value == complexes[0]
        assert not cookie._quoted
        assert cookie._symbols == symbols
        assert cookie._count == 1

    def test_parse_cookie(self, complexes):
        # key=value
        cookie = ComplexCookie(complexes[0])
        symbols, count = cookie._parse_cookie()
        assert symbols == ["key", '=', 'value']
        assert count == 1

        # key:value
        cookie = ComplexCookie(complexes[1])
        symbols, count = cookie._parse_cookie()
        assert symbols == ["key", ':', 'value']
        assert count == 1

        # key1=value1:key2=value2
        cookie = ComplexCookie(complexes[2])
        symbols, count = cookie._parse_cookie()
        assert symbols == ["key1", '=', 'value1', ':', "key2", '=', 'value2']
        assert count == 2

        # key1=value1&key2=value2
        cookie = ComplexCookie(complexes[3])
        symbols, count = cookie._parse_cookie()
        assert symbols == ["key1", '=', 'value1', '&', "key2", '=', 'value2']
        assert count == 2

        # key1:value1&key2:value2
        cookie = ComplexCookie(complexes[4])
        symbols, count = cookie._parse_cookie()
        assert symbols == ["key1", ':', 'value1', '&', "key2", ':', 'value2']
        assert count == 2

        # key11=value11&key21=value21:key12=value12&key22=value22
        cookie = ComplexCookie(complexes[5])
        symbols, count = cookie._parse_cookie()
        assert symbols == ["key11", '=', 'value11', '&', "key21", '=', 'value21',
                           ':',
                           "key12", '=', 'value12', '&', "key22", '=', 'value22']
        assert count == 4

    def test_replace_at(self, complexes):
        cookie = ComplexCookie(complexes[5])
        payload = "[payload]"

        # replace 0
        test = cookie._replace_at(0, payload)
        assert test == "key11=" + payload + "&key21=value21:key12=value12&key22=value22"

        # replace 1
        test = cookie._replace_at(1, payload)
        assert test == "key11=value11&key21=" + payload + ":key12=value12&key22=value22"

        # replace 2
        test = cookie._replace_at(2, payload)
        assert test == "key11=value11&key21=value21:key12=" + payload + "&key22=value22"

        # replace 3
        test = cookie._replace_at(3, payload)
        assert test == "key11=value11&key21=value21:key12=value12&key22=" + payload

    def test_replace(self, complexes):
        payload = "[payload]"

        # key=value
        cookie = ComplexCookie(complexes[0])
        test = cookie.replace(payload)
        assert list(test) == [payload, "key=" + payload]

        # "key=value"
        cookie = ComplexCookie('"' + complexes[0] + '"')
        test = cookie.replace(payload)
        assert list(test) == ['"' + payload + '"', '"key=' + payload + '"']

        # key:value
        cookie = ComplexCookie(complexes[1])
        test = cookie.replace(payload)
        assert list(test) == [payload, "key:" + payload]

        # "key:value"
        cookie = ComplexCookie('"' + complexes[1] + '"')
        test = cookie.replace(payload)
        assert list(test) == ['"' + payload + '"', '"key:' + payload + '"']

        # key1=value1&key2=value2
        cookie = ComplexCookie(complexes[3])
        test = cookie.replace(payload)
        assert list(test) == [payload, "key1=" + payload + "&key2=value2", "key1=value1&key2=" + payload]

        # key11=value11&key21=value21:key12=value12&key22=value22
        cookie = ComplexCookie(complexes[5])
        test = cookie.replace(payload)
        assert list(test) == [payload,
                              "key11=" + payload + "&key21=value21:key12=value12&key22=value22",
                              "key11=value11&key21=" + payload + ":key12=value12&key22=value22",
                              "key11=value11&key21=value21:key12=" + payload + "&key22=value22",
                              "key11=value11&key21=value21:key12=value12&key22=" + payload]
