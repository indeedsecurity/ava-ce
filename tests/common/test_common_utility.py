import pytest
import string
import requests
from ava.common import utility
from ava.actives.open_redirect import OpenRedirectCheck, OpenRedirectHtmlCheck, OpenRedirectScriptCheck
from ava.auditors.parameter import QueryParameterAuditor, PostParameterAuditor
from ava.common.exception import InvalidFormatException, UnknownKeyException
from ava.parsers.cookie import SimpleCookie, ComplexCookie
from ava.parsers.json import JsonObject
from ava.parsers.multipart import MultipartForm
from ava.parsers.xml import XmlDocument


@pytest.fixture
def response():
    request = type("Request", (object,), {})
    return type("Response", (object,), {'request': request(), 'next': request()})


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.example.com",
        'method': "get",
        'params': {'param': "avascan"},
        'cookies': {},
        'headers': {},
        'data': {}
    }

    return vector


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


@pytest.fixture
def xmls():
    xmls = [
        "<avascan>one text</avascan>",
        "<avascan><test>one text</test><test>two texts</test></avascan>",
        "<avascan><outer><inner>nested text</inner></outer></avascan>",
        "<avascan><test></test><outer><inner></inner></outer></avascan>"
    ]
    return xmls


@pytest.fixture
def multiparts():
    content_type = "multipart/form-data; boundary=boundary"
    multipart_data = [
        ('--boundary\r\nContent-Disposition: form-data; name="ava"\r\n'
         '\r\navascan\r\n--boundary--\r\n'),
        ('--boundary\r\nContent-Disposition: form-data; name="ava"; filename="data.txt"\r\nContent-Type: text/plain\r\n'
         '\r\navascan\r\n--boundary--\r\n')
    ]

    return content_type, multipart_data


def test_generate_random():
    # ascii letters
    test = utility.generate_random(string.ascii_letters)
    assert test.isalpha()
    assert len(test) == 7

    # digits
    test = utility.generate_random(string.digits)
    assert test.isdigit()
    assert len(test) == 7

    # custom size
    test = utility.generate_random(string.ascii_letters, size=20)
    assert test.isalpha()
    assert len(test) == 20

    # empty
    test = utility.generate_random('')
    assert test == ''


def test_fingerprint_vector_positive(vector, multiparts):
    vector['headers'] = {'User-Agent': "Mozilla/5.0"}
    vector['cookies'] = {'session': "identifier"}
    vector['params'] = {}

    # post parameters
    vector['headers']['Content-Type'] = "application/x-www-form-urlencoded"
    vector['data'] = {'ava': "avascan"}
    test = utility.fingerprint_vector(vector)
    assert test == {'url': vector['url'], 'method': vector['method'], 'params': {}, 'data': {'ava': "avascan"}}

    # post json
    vector['headers']['Content-Type'] = "application/json"
    vector['data'] = '{"ava": "avascan"}'
    test = utility.fingerprint_vector(vector)
    assert test == {'url': vector['url'], 'method': vector['method'], 'params': {}, 'data': {'ava': "avascan"}}

    # post multipart
    vector['headers']['Content-Type'] = multiparts[0]
    vector['data'] = multiparts[1][0]
    test = utility.fingerprint_vector(vector)
    assert test == {'url': vector['url'], 'method': vector['method'], 'params': {}, 'data': {'ava': "avascan"}}

    # post text
    vector['headers']['Content-Type'] = "text/plain"
    vector['data'] = " token "
    test = utility.fingerprint_vector(vector)
    assert test == {'url': vector['url'], 'method': vector['method'], 'params': {}, 'data': "token"}

    # query string
    vector['params'] = {'ava': "avascan"}
    vector['data'] = {}
    test = utility.fingerprint_vector(vector)
    assert test == {'url': vector['url'], 'method': vector['method'], 'params': {'ava': "avascan"}, 'data': {}}


def test_fingerprint_vector_negative():
    # unsupported content-type
    with pytest.raises(UnknownKeyException):
        vector = {'headers': {'Content-Type': "application/unsupported"}, 'data': "unsupported data"}
        utility.fingerprint_vector(vector)


def test_get_package_classes(mocker):
    actives = [OpenRedirectCheck, OpenRedirectHtmlCheck, OpenRedirectScriptCheck]
    auditors = [QueryParameterAuditor, PostParameterAuditor]

    # checks includes
    test = utility.get_package_classes("actives", ["open_redirect"])
    assert test == set(actives)

    # auditors includes
    test = utility.get_package_classes("auditors", ["parameter"])
    assert test == set(auditors)

    # checks listdir
    mocker.patch("os.listdir", return_value=["__init__.py", "open_redirect.py"])
    test = utility.get_package_classes("actives", [])
    assert test == set(actives)

    # auditors listdir
    mocker.patch("os.listdir", return_value=["__init__.py", "parameter.py"])
    test = utility.get_package_classes("auditors", [])
    assert test == set(auditors)


def test_get_package_info(mocker):
    # checks
    mocker.patch("ava.common.utility.get_package_classes", return_value=[OpenRedirectCheck])
    test = utility.get_package_info("actives")
    assert test == [("open_redirect", "checks for open redirects")]

    # auditors
    mocker.patch("ava.common.utility.get_package_classes", return_value=[QueryParameterAuditor])
    test = utility.get_package_info("auditors")
    assert test == [("parameter", "audits each parameter")]


def test_parse_cookie(simples, complexes):
    # simple values
    tests = []
    for cookie in simples:
        test = utility.parse_cookie(cookie)
        tests.append(test)
    assert all(isinstance(test, SimpleCookie) for test in tests)

    # complex values
    tests = []
    for cookie in complexes:
        test = utility.parse_cookie(cookie)
        tests.append(test)
    assert all(isinstance(test, ComplexCookie) for test in tests)


def test_check_base64_positive(simples):
    # one equals
    test = utility._check_base64(simples[5])
    assert test

    # two equals
    test = utility._check_base64(simples[6])
    assert test

    # starts with !
    test = utility._check_base64('!' + simples[5])
    assert test

    # quoted one equals
    test = utility._check_base64('"' + simples[5] + '"')
    assert test

    # quoted two equals
    test = utility._check_base64('"' + simples[6] + '"')
    assert test


def test_check_base64_negative():
    # not base64
    test = utility._check_base64("tvkeDPiyTQV64x2nEkhhsTg0FGtNCAOX")
    assert not test


def test_parse_xml_positive(xmls):
    # one text
    test = utility.parse_xml(xmls[0])
    assert isinstance(test, XmlDocument)

    # two texts
    test = utility.parse_xml(xmls[1])
    assert isinstance(test, XmlDocument)

    # inner text
    test = utility.parse_xml(xmls[2])
    assert isinstance(test, XmlDocument)

    # no text
    test = utility.parse_xml(xmls[3])
    assert isinstance(test, XmlDocument)


def test_parse_xml_negative():
    # wrong format
    test = utility.parse_xml("not-xml")
    assert not test

    # bad xml
    test = utility.parse_xml("<test><error></test>")
    assert not test


def test_parse_javascript():
    # with text
    test = utility.parse_javascript('var x = "test";')
    assert test == 'var x = ;'

    # empty
    test = utility.parse_javascript("")
    assert test == ''


def test_parse_json_positive():
    # object
    test = utility.parse_json('{"test": "token"}')
    assert isinstance(test, JsonObject)

    # list
    test = utility.parse_json('["test", "token"]')
    assert isinstance(test, JsonObject)

    # literal
    test = utility.parse_json('"test token"')
    assert isinstance(test, JsonObject)


def test_parse_json_negative():
    # invalid json
    with pytest.raises(InvalidFormatException):
        utility.parse_json('{"test": "token"')


def test_parse_multipart_positive(multiparts):
    content_type = multiparts[0]
    multipart_data = multiparts[1]

    # value
    test = utility.parse_multipart(multipart_data[0], content_type)
    assert isinstance(test, MultipartForm)

    # file
    test = utility.parse_multipart(multipart_data[1], content_type)
    assert isinstance(test, MultipartForm)


def test_parse_multipart_negative(multiparts):
    content_type = multiparts[0]
    multipart_data = multiparts[1]

    # invalid multipart data
    with pytest.raises(InvalidFormatException):
        utility.parse_multipart("invalid data", content_type)

    # invalid multipart content-type
    with pytest.raises(InvalidFormatException):
        utility.parse_multipart(multipart_data[0], "text/plain")

    # missing content-type boundary
    with pytest.raises(InvalidFormatException):
        utility.parse_multipart(multipart_data[0], "multipart/form-data;")


def test_check_http_redirect_follow(response):
    response.is_redirect = True

    # with domain same domain
    configs = {'domain': ".example.com", 'excludes': []}
    response.request.url = "https://www.example.com/"
    response.next.url = "https://www.example.com/account"
    test = utility._check_http_redirect(response, configs)
    assert test

    # with domain different domain
    configs = {'domain': ".example.com", 'excludes': []}
    response.request.url = "https://www.example.com/"
    response.next.url = "https://account.example.com/"
    test = utility._check_http_redirect(response, configs)
    assert test

    # with domain with excludes
    configs = {'domain': "www.example.com", 'excludes': ["/logout"]}
    response.request.url = "https://www.example.com/"
    response.next.url = "https://www.example.com/account"
    test = utility._check_http_redirect(response, configs)
    assert test

    # without domain same domain
    configs = {'domain': "", 'excludes': []}
    response.request.url = "https://www.example.com/"
    response.next.url = "https://www.example.com/account"
    test = utility._check_http_redirect(response, configs)
    assert test

    # without domain with excludes
    configs = {'domain': "", 'excludes': ["/logout"]}
    response.request.url = "https://www.example.com/"
    response.next.url = "https://www.example.com/account"
    test = utility._check_http_redirect(response, configs)
    assert test


def test_check_http_redirect_no_follow(response):
    response.is_redirect = True

    # with domain different domain
    configs = {'domain': ".example.com", 'excludes': []}
    response.request.url = "https://www.example.com/"
    response.next.url = "https://www.not-example.com/"
    test = utility._check_http_redirect(response, configs)
    assert not test

    # with domain with excludes
    configs = {'domain': "www.example.com", 'excludes': ["/logout"]}
    response.request.url = "https://www.example.com/"
    response.next.url = "https://www.example.com/logout"
    test = utility._check_http_redirect(response, configs)
    assert not test

    # without domain different domain
    configs = {'domain': "", 'excludes': []}
    response.request.url = "https://www.example.com/"
    response.next.url = "https://acount.example.com/"
    test = utility._check_http_redirect(response, configs)
    assert not test

    # without domain with excludes
    configs = {'domain': ".example.com", 'excludes': ["/account/"]}
    response.request.url = "https://www.example.com/"
    response.next.url = "https://www.example.com/account/logout"
    test = utility._check_http_redirect(response, configs)
    assert not test

    # not redirect
    response.is_redirect = False
    test = utility._check_http_redirect(response, configs)
    assert not test


def test_send_http_request_no_follow(vector, mocker, response):
    session = requests.Session()
    response.is_redirect = False
    response.request.method = vector['method']
    response.request.url = vector['url']
    response.status_code = 200

    # without proxy
    configs = {'agent': "Mozilla/5.0", 'timeout': 30, 'proxy': "", 'follow': False}
    mocker.patch("requests.Session.request", return_value=response)
    test = utility.send_http_request(session, vector, configs)
    assert test == response

    # with proxy
    configs = {'agent': "Mozilla/5.0", 'timeout': 30, 'proxy': "127.0.0.1:8080", 'follow': False}
    mocker.patch("requests.Session.request", return_value=response)
    test = utility.send_http_request(session, vector, configs)
    assert test == response


def test_send_http_requests_follow(vector, mocker, response):
    session = requests.Session()
    configs = {'agent': "Mozilla/5.0", 'timeout': 30, 'proxy': "127.0.0.1:8080",
               'follow': True, 'domain': "", 'excludes': []}

    # set redirect
    redirect = response()
    redirect.is_redirect = True
    redirect.request.method = vector['method']
    redirect.request.url = vector['url']
    redirect.status_code = 302
    redirect.next.url = vector['url'] + "/account"

    # set response
    non_redirect = response()
    non_redirect.is_redirect = False
    non_redirect.status_code = 200
    non_redirect.history = []

    # with follow and without redirect
    mocker.patch("requests.Session.request", return_value=non_redirect)
    mocker.patch("requests.Session.resolve_redirects", return_value=iter([]))
    test = utility.send_http_request(session, vector, configs)
    assert test == non_redirect
    assert test.history == []

    # with follow and redirect
    mocker.patch("requests.Session.request", return_value=redirect)
    mocker.patch("requests.Session.resolve_redirects", return_value=iter([non_redirect]))
    test = utility.send_http_request(session, vector, configs)
    assert test == non_redirect
    assert test.history == [redirect]
