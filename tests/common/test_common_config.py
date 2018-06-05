import pytest
from copy import copy
from ava.common import config
from ava.common.exception import InvalidValueException, UnknownKeyException


def test_check_modules_positive(mocker):
    # one module in checks
    mocker.patch("os.listdir", return_value=["__init__.py", "xss.py", "open_redirect.py"])
    test = config._check_modules("actives", ["xss"])
    assert test == ["xss"]

    # multiple modules in checks
    mocker.patch("os.listdir", return_value=["__init__.py", "xss.py", "open_redirect.py"])
    test = config._check_modules("actives", ["xss", "open_redirect"])
    assert test == ["xss", "open_redirect"]


def test_check_modules_negative(mocker):
    # __init__
    mocker.patch("os.listdir", return_value=["__init__.py", "xss.py", "open_redirect.py"])
    with pytest.raises(InvalidValueException):
        config._check_modules("actives", ["__init__"])

    # non-existent module in checks
    mocker.patch("os.listdir", return_value=["__init__.py", "xss.py", "open_redirect.py"])
    with pytest.raises(InvalidValueException):
        config._check_modules("actives", ["module_does_not_exist"])


def test_check_url_positive():
    # url with path
    url = "http://localhost/"
    test = config._check_url(url)
    assert test == url

    # url without path
    url = "http://localhost"
    test = config._check_url(url)
    assert test == url + '/'

    # url with ip address
    url = "http://127.0.0.1/"
    test = config._check_url(url)
    assert test == url

    # url with ip address and port
    url = "http://127.0.0.1:8000/"
    test = config._check_url(url)
    assert test == url


def test_check_url_negative():
    # missing scheme
    with pytest.raises(InvalidValueException):
        url = "localhost:8080"
        config._check_url(url)

    # missing hostname
    with pytest.raises(InvalidValueException):
        url = "http:///listener"
        config._check_url(url)


def test_check_modules_urls_positive():
    # valid url and module
    test = config._check_modules_and_urls("blinds", {"xss": "http://localhost/"})
    assert test == {"xss": "http://localhost/"}

    # valid url without path
    test = config._check_modules_and_urls("blinds", {"xss": "http://localhost"})
    assert test == {"xss": "http://localhost/"}


def test_check_modules_urls_negative():
    # invalid url
    with pytest.raises(InvalidValueException):
        config._check_modules_and_urls("blinds", {"xss": "localhost:8080"})

    # missing module
    with pytest.raises(InvalidValueException):
        config._check_modules_and_urls("blinds", {"fake": "localhost:8080"})

    # missing url
    with pytest.raises(InvalidValueException):
        config._check_modules_and_urls("blinds", {"xss": ""})


def test_check_dict_positive():
    # all values
    values = {'ava': "avascan", 'test': "token"}
    test = config._check_dict(values)
    assert test == values


def test_check_dict_negative():
    # None value
    test = config._check_dict({'ava': "avascan", 'test': None})
    assert test == {'ava': "avascan", 'test': ""}

    # empty dictionary
    test = config._check_dict({})
    assert test == {}


def test_check_int_positive():
    # positive integer
    test = config._check_int("test", 1)
    assert test == 1


def test_check_int_negative():
    # zero or negative integer
    with pytest.raises(InvalidValueException):
        config._check_int("test", 0)


def test_check_proxy_positive():
    # proxy value
    test = config._check_proxy("127.0.0.1:8080")
    assert test == "127.0.0.1:8080"

    # proxy value http
    test = config._check_proxy("http://127.0.0.1:8080")
    assert test == "http://127.0.0.1:8080"

    # proxy value https
    test = config._check_proxy("https://127.0.0.1:8080")
    assert test == "https://127.0.0.1:8080"

    # proxy value with auth and scheme
    test = config._check_proxy("http://user:pass@127.0.0.1:8080")
    assert test == "http://user:pass@127.0.0.1:8080"


def test_check_proxy_negative():
    # invalid format
    with pytest.raises(InvalidValueException):
        config._check_proxy("127.0.0.1")

    # missing port
    with pytest.raises(InvalidValueException):
        config._check_proxy("127.0.0.1:")

    # invalid ip
    with pytest.raises(InvalidValueException):
        config._check_proxy("127.0.0.1337:8080")

    # invalid port
    with pytest.raises(InvalidValueException):
        config._check_proxy("127.0.0.1:test")


def test_check_alternative_url_positive():
    # ip
    test = config._check_alternative_url("127.0.0.1")
    assert test == "127.0.0.1"

    # http
    test = config._check_alternative_url("http://127.0.0.1")
    assert test == "http://127.0.0.1"

    # https
    test = config._check_alternative_url("https://127.0.0.1")
    assert test == "https://127.0.0.1"

    # http with port
    test = config._check_alternative_url("http://127.0.0.1:80")
    assert test == "http://127.0.0.1:80"


def test_check_alternative_url_negative():
    # invalid port
    with pytest.raises(InvalidValueException):
        config._check_alternative_url("127.0.0.1:test")

    # with path
    with pytest.raises(InvalidValueException):
        config._check_alternative_url("http://127.0.0.1/path")

    # with path
    with pytest.raises(InvalidValueException):
        config._check_alternative_url("127.0.0.1/path")

    # wrong scheme
    with pytest.raises(InvalidValueException):
        config._check_alternative_url("ftp://127.0.0.1")


def test_generate_positive():
    users = {
        'auditors': ["parameter", "cookie"],
        'actives': ["xss", "open_redirect"],
        'blinds': {'xss': "http://localhost/"},
        'passives': ["pii"],
        'report': "report.json",
        'cookies': {'key': "value"},
        'headers': {'key': "value"},
        'parameters': {'key': "value"},
        'excludes': ["/admin"],
        'skips': ["token"],
        'ignores': ["email@avascan.com"],
        'domain': "example.com",
        'agent': "Mozilla/5.0",
        'timeout': 5,
        'proxy': "127.0.0.1:8080",
        'processes': 4,
        'threads': 4,
        'value': "test",
        'follow': True,
        'reduce': True,
        'url': "127.0.0.1",
        'summary': True,
        'hars': ["vectors.har"]
    }

    converted = {
        'auditors': ["parameter", "cookie"],
        'actives': ["xss", "open_redirect"],
        'blinds': {'xss': "http://localhost/"},
        'passives': ["pii"],
        'report': "report.json",
        'cookies': {'key': "value"},
        'headers': {'key': "value"},
        'parameters': {'key': "value"},
        'excludes': ["/admin"],
        'skips': ["token"],
        'ignores': ["email@avascan.com"],
        'domain': "example.com",
        'agent': "Mozilla/5.0",
        'timeout': 5,
        'proxy': "127.0.0.1:8080",
        'processes': 4,
        'threads': 4,
        'value': "test",
        'follow': True,
        'reduce': True,
        'url': "127.0.0.1",
        'summary': True,
        'hars': ["vectors.har"]
    }

    # split
    args = {key: value for key, value in users.items() if key in ['auditors', 'actives', 'proxy', 'summary']}
    yamls = {key: value for key, value in users.items() if key not in args}

    # args
    generated = copy(config.defaults)
    generated.update({key: value for key, value in converted.items() if key in args})
    test = config.generate(args, {})
    assert test == generated

    # yaml
    generated = copy(config.defaults)
    generated.update({key: value for key, value in converted.items() if key in yamls})
    test = config.generate({}, yamls)
    assert test == generated

    # args and ini
    test = config.generate(args, yamls)
    assert test == converted


def test_generate_default():
    # no args or ini
    test = config.generate({}, {})
    assert test == config.defaults

    # args None
    test = config.generate({'agent': None, 'timeout': None}, {})
    assert test == config.defaults

    # ini None
    test = config.generate({}, {'processes': None, 'threads': None})
    assert test == config.defaults

    # other keys
    test = config.generate({'config': "config.ini", 'quiet': False, 'debug': True}, {})
    assert test == config.defaults


def test_generate_negative():
    # unknown args key
    with pytest.raises(UnknownKeyException):
        config.generate({'key_does_not_exist': "value"}, {})

    # unknown ini key
    with pytest.raises(UnknownKeyException):
        config.generate({}, {'key_does_not_exist': "value"})
