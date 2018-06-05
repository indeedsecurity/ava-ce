import pytest
from ava.common.exception import InvalidFormatException
from ava.readers.vector import HarReader
from json.decoder import JSONDecodeError


@pytest.fixture
def requests():
    requests = [
        {  # GET request
            'method': "GET",
            'url': "https://www.example.com/",
            'cookies': [{'name': "cookie", 'value': "cookies"}],
            'headers': [{'name': "header", 'value': "headers"}],
            'queryString': [{'name': "query", 'value': "queries"}],
            'postData': {
                'mimeType': "",
                'params': []
            }
        },
        {  # POST request
            'method': "POST",
            'url': "https://www.example.com/",
            'cookies': [{'name': "cookie", 'value': "cookies"}],
            'headers': [{'name': "header", 'value': "headers"}],
            'queryString': [],
            'postData': {
                'mimeType': "application/x-www-form-urlencoded",
                'params': [{'name': "post", 'value': "posts"}]
            }
        },
        {  # without URL
            'method': "GET",
            'url': "",
            'cookies': [{'name': "cookie", 'value': "cookies"}],
            'headers': [{'name': "header", 'value': "headers"}],
            'queryString': [{'name': "query", 'value': "queries"}],
            'postData': {
                'mimeType': "",
                'params': []
            }
        },
        {  # outside domain
            'method': "POST",
            'url': "https://www.not-example.com/",
            'cookies': [{'name': "cookie", 'value': "cookies"}],
            'headers': [{'name': "header", 'value': "headers"}],
            'queryString': [],
            'postData': {
                'mimeType': "application/x-www-form-urlencoded",
                'params': [{'name': "post", 'value': "posts"}]
            }
        },
        {  # excludes path
            'method': "GET",
            'url': "https://www.example.com/admin",
            'cookies': [{'name': "cookie", 'value': "cookies"}],
            'headers': [{'name': "header", 'value': "headers"}],
            'queryString': [],
            'postData': {
                'mimeType': "",
                'params': []
            }
        },
        {  # unsupported method
            'method': "TEST",
            'url': "https://www.example.com/",
            'cookies': [{'name': "cookie", 'value': "cookies"}],
            'headers': [{'name': "header", 'value': "headers"}],
            'queryString': [],
            'postData': {
                'mimeType': "",
                'params': []
            }
        },
        {  # unsupported content-type
            'method': "POST",
            'url': "https://www.example.com/",
            'cookies': [{'name': "cookie", 'value': "cookies"}],
            'headers': [{'name': "header", 'value': "headers"}],
            'queryString': [],
            'postData': {
                'mimeType': "application/x-text",
                'params': [{'name': "post", 'value': "posts"}]
            }
        }
    ]

    return requests


@pytest.fixture
def vectors():
    vectors = [
        {  # GET vector
            'url': "https://www.example.com/",
            'method': "GET",
            'cookies': {'cookie': "cookies"},
            'headers': {'Header': "headers", 'User-Agent': "AVA/1.22.1"},
            'params': {'query': "queries"},
            'data': {},
        },
        {  # POST vector
            'url': "https://www.example.com/",
            'method': "POST",
            'cookies': {'cookie': "cookies"},
            'headers': {'Header': "headers", 'User-Agent': "AVA/1.22.1",
                        'Content-Type': "application/x-www-form-urlencoded"},
            'params': {},
            'data': {'post': "posts"},
        }
    ]
    return vectors


class TestVectorReader:

    @pytest.fixture
    def reader(self):
        return HarReader(["test.json"])

    def test_convert_elements_with_elements(self, reader):
        elements = [{'name': "ava", 'value': "avascan"}, {'name': "test", 'value': "token"}]

        # with elements
        test = reader._convert_elements(elements)
        assert test == {'ava': "avascan", 'test': "token"}

    def test_convert_elements_without_elements(self, reader):
        # without elements
        test = reader._convert_elements([])
        assert test == {}

    def test_convert_post_data_with_data(self, reader):
        # with params
        post_data = {'params': [{'name': "ava", 'value': "avascan"}], 'text': ""}
        test = reader._convert_post_data(post_data)
        assert test == {'ava': "avascan"}

        # with text
        post_data = {'params': [], 'text': "avascan"}
        test = reader._convert_post_data(post_data)
        assert test == "avascan"

        # with params and text
        post_data = {'params': [{'name': "ava", 'value': "avascan"}], 'text': "avascan"}
        test = reader._convert_post_data(post_data)
        assert test == {'ava': "avascan"}

    def test_convert_post_data_without_data(self, reader):
        # empty post data
        test = reader._convert_post_data({})
        assert test == {}

        # without params or text
        test = reader._convert_post_data({'params': [], 'text': ""})
        assert test == {}

    def test_convert_request_with_elements(self, reader):
        elements = [{'name': "ava", 'value': "avascan"}]
        request = {'url': "https://www.example.com/", 'method': "GET",
                   'cookies': elements, 'headers': elements, 'queryString': elements,
                   'postData': {'params': elements, 'text': ""}}
        generated = {'url': "https://www.example.com/", 'method': "GET",
                     'cookies': {'ava': "avascan"}, 'headers': {'ava': "avascan"},
                     'params': {'ava': "avascan"}, 'data': {'ava': "avascan"}}

        # convert with elements
        test = reader._convert_request(request)
        assert test == generated

    def test_convert_request_without_elements(self, reader):
        request = {'url': "https://www.example.com/", 'method': "GET",
                   'cookies': [], 'headers': [], 'queryString': [],
                   'postData': {'params': [], 'text': ""}}

        generated = {'url': "https://www.example.com/", 'method': "GET",
                     'cookies': {}, 'headers': {}, 'params': {}, 'data': {}}

        # convert with empty elements
        test = reader._convert_request(request)
        assert test == generated

        # convert without elements
        request = {'url': "https://www.example.com/", 'method': "GET"}
        test = reader._convert_request(request)
        assert test == generated

    def test_check_url_positive(self, reader):
        # http
        vector = {'url': "http://www.example.com/"}
        test = reader._check_url(vector, 1, "file.har")
        assert vector['url'] == "http://www.example.com/"
        assert test

        # https
        vector = {'url': "https://www.example.com/"}
        test = reader._check_url(vector, 1, "file.har")
        assert vector['url'] == "https://www.example.com/"
        assert test

        # missing path
        vector = {'url': "http://www.example.com"}
        test = reader._check_url(vector, 1, "file.har")
        assert vector['url'] == "http://www.example.com/"
        assert test

    def test_check_url_negative(self, reader):
        # missing url
        url = {'url': ""}
        test = reader._check_url(url, 1, "file.har")
        assert not test

        # ftp
        url = {'url': "ftp://www.example.com/"}
        test = reader._check_url(url, 1, "file.har")
        assert not test

        # javascript
        url = {'url': "javascript://www.example.com/"}
        test = reader._check_url(url, 1, "file.har")
        assert not test

        # missing hostname
        url = {'url': "https:///target"}
        test = reader._check_url(url, 1, "file.har")
        assert not test

    def test_change_hostname(self, reader):
        # hostname
        vector = {'url': "http://127.0.0.1/", 'headers': {'Host': "127.0.0.1"}}
        url = "example.com"
        test = reader._change_hostname(vector, url)
        assert vector['url'] == "http://example.com/"

        # hostname with port
        vector = {'url': "http://127.0.0.1/", "headers": {"Host": "127.0.0.1"}}
        url = "example.com:80"
        test = reader._change_hostname(vector, url)
        assert vector['url'] == "http://example.com:80/"

        # http
        vector = {'url': "https://127.0.0.1/", "headers": {"Host": "127.0.0.1"}}
        url = "http://example.com"
        test = reader._change_hostname(vector, url)
        assert vector['url'] == "http://example.com/"

        # https
        vector = {'url': "http://127.0.0.1/", "headers": {"Host": "127.0.0.1"}}
        url = "https://example.com"
        test = reader._change_hostname(vector, url)
        assert vector['url'] == "https://example.com/"

        # https with port
        vector = {'url': "http://127.0.0.1/", "headers": {"Host": "127.0.0.1"}}
        url = "https://example.com:80"
        test = reader._change_hostname(vector, url)
        assert vector['url'] == "https://example.com:80/"

    def test_check_domain_positive(self, reader):
        # within domain exact
        url = {'url': "http://www.example.com/"}
        domain = {'domain': "www.example.com"}
        test = reader._check_domain(url, domain, 1, "file.har")
        assert test

        # within domain parent www
        url = {'url': "http://www.example.com/"}
        domain = {'domain': "example.com"}
        test = reader._check_domain(url, domain, 1, "file.har")
        assert test

        # within domain parent other
        url = {'url': "http://subdomain.example.com/"}
        domain = {'domain': "example.com"}
        test = reader._check_domain(url, domain, 1, "file.har")
        assert test

        # ip address exact
        url = {'url': "http://127.0.0.1:8000/"}
        domain = {'domain': "127.0.0.1"}
        test = reader._check_domain(url, domain, 1, "file.har")
        assert test

    def test_check_domain_negative(self, reader):
        # outside domain
        url = {'url': "http://www.not-example.com/"}
        domain = {'domain': "www.example.com"}
        test = reader._check_domain(url, domain, 1, "file.har")
        assert not test

        # different subdomain
        url = {'url': "http://subdomain.example.com/"}
        domain = {'domain': "www.example.com"}
        test = reader._check_domain(url, domain, 1, "file.har")
        assert not test

        # outside ip address
        url = {'url': "http://172.0.0.1/"}
        domain = {'domain': "127.0.0.1"}
        test = reader._check_domain(url, domain, 1, "file.har")
        assert not test

        # empty domain
        url = {'url': "http://www.example.com/"}
        domain = {'domain': ""}
        test = reader._check_domain(url, domain, 1, "file.har")
        assert test

    def test_check_excludes_with_match(self, reader):
        # match base path
        url = {'url': "http://www.example.com/admin"}
        configs = {"excludes": ["/admin"]}
        test = reader._check_excludes(url, configs, 1, "file.har")
        assert test

        # match sub-path
        url = {'url': "http://www.example.com/admin/accounts"}
        configs = {"excludes": ["/admin/"]}
        test = reader._check_excludes(url, configs, 1, "file.har")
        assert test

        # match url with multiple excludes
        url = {'url': "http://www.example.com/admin"}
        configs = {"excludes": ["/delete", "/admin"]}
        test = reader._check_excludes(url, configs, 1, "file.har")
        assert test

        # url with special characters
        url = {'url': "http://www.example.com/(?P<variable>[^/]*/show"}
        configs = {"excludes": ["/(?P"]}
        test = reader._check_excludes(url, configs, 1, "file.har")
        assert test

    def test_check_excludes_without_match(self, reader):
        url = {'url': "http://www.example.com/scan"}

        # not match url
        configs = {"excludes": ["/admin/"]}
        test = reader._check_excludes(url, configs, 1, "file.har")
        assert not test

        # not match url with multiple excludes
        configs = {"excludes": ["/delete", "/admin"]}
        test = reader._check_excludes(url, configs, 1, "file.har")
        assert not test

        # empty excludes
        configs = {"excludes": []}
        test = reader._check_excludes(url, configs, 1, "file.har")
        assert not test

    def test_check_method_positive(self, reader):
        # GET method
        vector = {'method': "GET"}
        test = reader._check_method(vector, 1, "file.har")
        assert vector['method'] == "GET"
        assert test

        # POST method
        vector = {'method': "POST"}
        test = reader._check_method(vector, 1, "file.har")
        assert vector['method'] == "POST"
        assert test

        # PUT method
        vector = {'method': "PUT"}
        test = reader._check_method(vector, 1, "file.har")
        assert vector['method'] == "PUT"
        assert test

    def test_check_method_negative(self, reader):
        # lowercase method
        vector = {'method': "get"}
        test = reader._check_method(vector, 1, "file.har")
        assert vector['method'] == "GET"
        assert test

        # missing method
        vector = {'method': ""}
        test = reader._check_method(vector, 1, "file.har")
        assert not test

        # unsupported method
        test = reader._check_method({'method': "TEST"}, 1, "file.har")
        assert not test

    def test_check_cookies_with_cookies(self, reader):
        # with cookies
        vector = {'cookies': {'ava': "avascan", 'test': "token"}, 'headers': {}}
        reader._check_cookies(vector, {'cookies': {}})
        assert vector['cookies'] == {'ava': "avascan", 'test': "token"}

        # without cookies
        vector = {'cookies': {}, 'headers': {}}
        reader._check_cookies(vector, {'cookies': {}})
        assert vector['cookies'] == {}

    def test_check_cookies_with_configs(self, reader):
        # only configs
        vector = {'cookies': {}, 'headers': {}}
        reader._check_cookies(vector, {'cookies': {'ava': "avascan"}})
        assert vector['cookies'] == {'ava': "avascan"}

        # values and configs
        vector = {'cookies': {'test': "token"}, 'headers': {}}
        reader._check_cookies(vector, {'cookies': {'ava': "avascan"}})
        assert vector['cookies'] == {'ava': "avascan", 'test': "token"}

    def test_check_cookies_with_headers(self, reader):
        # with 'Cookie' headers
        vector = {'cookies': {}, 'headers': {'Cookie': "ava=avascan; test=token"}}
        reader._check_cookies(vector, {'cookies': {}})
        assert vector['cookies'] == {'ava': "avascan", 'test': "token"}

        # without 'Cookie' header
        vector = {'cookies': {}, 'headers': {'Content-Type': "application/json"}}
        reader._check_cookies(vector, {'cookies': {}})
        assert vector['cookies'] == {}

    def test_check_headers_with_headers(self, reader):
        # with headers
        vector = {'headers': {'Content-Type': "application/json"}}
        reader._check_headers(vector, {'headers': {}})
        assert vector['headers'] == {'Content-Type': "application/json"}

        # with headers lowercase
        vector = {'headers': {'content-type': "application/json"}}
        reader._check_headers(vector, {'headers': {}})
        assert vector['headers'] == {'Content-Type': "application/json"}

        # with headers in blacklist
        vector = {'headers': {'Host': "www.example.com", 'Content-Type': "application/json"}}
        reader._check_headers(vector, {'headers': {}})
        assert vector['headers'] == {'Content-Type': "application/json"}

    def test_check_headers_without_headers(self, reader):
        # without headers
        vector = {'headers': {}}
        reader._check_headers(vector, {'headers': {}})
        assert vector['headers'] == {}

    def test_check_headers_with_configs(self, reader):
        # only configs
        vector = {'headers': {}}
        reader._check_headers(vector, {'headers': {'ava': "avascan"}})
        assert vector['headers'] == {'ava': "avascan"}

        # values and configs
        vector = {'headers': {'test': "token"}}
        reader._check_headers(vector, {'headers': {'ava': "avascan"}})
        assert vector['headers'] == {'ava': "avascan", 'Test': "token"}

    def test_check_query_string_with_parameters(self, reader):
        configs = {'value': "avascan", 'parameters': {}}
        url = {'url': "https://www.example.com/"}

        # with params with values
        vector = {'method': "GET", 'params': {'test': "token"}}
        reader._check_query_string(vector, url, configs)
        assert vector['params'] == {'test': "token"}

        # with params without values
        vector = {'method': "GET", 'params': {'test': ""}}
        reader._check_query_string(vector, url, configs)
        assert vector['params'] == {'test': "avascan"}

        # without params
        vector = {'method': "GET", 'params': {}}
        reader._check_query_string(vector, url, configs)
        assert vector['params'] == {}

    def test_check_query_string_with_configs(self, reader):
        configs = {'value': "avascan", 'parameters': {'ava': "avascan"}}
        url = {'url': "https://www.example.com/"}

        # only configs
        vector = {'method': "GET", 'params': {}}
        reader._check_query_string(vector, url, configs)
        assert vector['params'] == {'ava': "avascan"}

        # values and configs
        vector = {'method': "GET", 'params': {'test': "token"}}
        reader._check_query_string(vector, url, configs)
        assert vector['params'] == {'test': "token", 'ava': "avascan"}

    def test_check_query_string_with_url(self, reader):
        configs = {'value': "avascan", 'parameters': {}}

        # with url with values
        vector = {'method': "GET", 'params': {}}
        url = {'url': "https://www.example.com/?test=token"}
        reader._check_query_string(vector, url, configs)
        assert vector['params'] == {'test': "token"}

        # with url without values
        url = {'url': "https://www.example.com/?test="}
        vector = {'method': "GET", 'params': {}}
        reader._check_query_string(vector, url, configs)
        assert vector['params'] == {'test': "avascan"}

    def test_check_post_data_with_parameters(self, reader):
        configs = {'value': "avascan", 'parameters': {}}
        headers = {'Content-Type': "application/x-www-form-urlencoded"}

        # with params with values
        vector = {'headers': headers, 'method': "POST", 'data': {'test': "token"}}
        reader._check_post_data(vector, configs)
        assert vector['data'] == {'test': "token"}
        assert vector['headers'] == headers

        # with params without values
        vector = {'headers': headers, 'method': "POST", 'data': {'test': ""}}
        reader._check_post_data(vector, configs)
        assert vector['data'] == {'test': "avascan"}
        assert vector['headers'] == headers

    def test_check_post_data_without_parameters(self, reader):
        configs = {'value': "avascan", 'parameters': {}}

        # without params
        vector = {'headers': {}, 'method': "POST", 'data': {}}
        reader._check_post_data(vector, configs)
        assert vector['data'] == {}
        assert vector['headers'] == {}

        # string data
        vector = {'headers': {'Content-Type': "text/plain"}, 'method': "POST", 'data': "avascan"}
        reader._check_post_data(vector, configs)
        assert vector['data'] == "avascan"
        assert vector['headers'] == {'Content-Type': "text/plain"}

    def test_check_post_data_with_configs(self, reader):
        configs = {'value': "avascan", 'parameters': {'ava': "avascan"}}
        headers = {'Content-Type': "application/x-www-form-urlencoded"}

        # only configs
        vector = {'headers': {}, 'method': "POST", 'data': {}}
        reader._check_post_data(vector, configs)
        assert vector['data'] == {'ava': "avascan"}
        assert vector['headers'] == headers

        # values and configs
        vector = {'headers': {}, 'method': "POST", 'data': {'test': "token"}}
        reader._check_post_data(vector, configs)
        assert vector['data'] == {'test': "token", 'ava': "avascan"}
        assert vector['headers'] == headers

    def test_check_user_agent_with_header(self, reader):
        # without configs
        vector = {'headers': {'User-Agent': "Mozilla/5.0 (Macintosh)"}}
        reader._check_user_agent(vector, {'agent': ""})
        assert vector['headers']['User-Agent'] == "Mozilla/5.0 (Macintosh)"

        # with configs
        vector = {'headers': {'User-Agent': "Mozilla/5.0 (Macintosh)"}}
        reader._check_user_agent(vector, {'agent': "Mozilla/5.0 (Linux; Android)"})
        assert vector['headers']['User-Agent'] == "Mozilla/5.0 (Linux; Android)"

    def test_check_user_agent_without_header(self, reader):
        # without configs without header
        vector = {'headers': {}}
        reader._check_user_agent(vector, {'agent': ""})
        assert vector['headers']['User-Agent'] == "AVA/1.22.1"

        # without configs without value
        vector = {'headers': {'User-Agent': ""}}
        reader._check_user_agent(vector, {'agent': ""})
        assert vector['headers']['User-Agent'] == "AVA/1.22.1"

        # with configs
        vector = {'headers': {}}
        reader._check_user_agent(vector, {'agent': "Mozilla/5.0 (Linux; Android)"})
        assert vector['headers']['User-Agent'] == "Mozilla/5.0 (Linux; Android)"

    def test_check_content_type_supported(self, reader):
        urlencoded = "application/x-www-form-urlencoded"

        # mime type supported
        request = {'postData': {'mimeType': urlencoded}}
        vector = {'data': {'ava': "avascan"}, 'headers': {}}
        test = reader._check_content_type(vector, request, 1, "file.har")
        assert vector['headers'] == {'Content-Type': urlencoded}
        assert test

        # mime type with charset
        request = {'postData': {'mimeType': urlencoded + ";charset=utf=8"}}
        vector = {'data': {'ava': "avascan"}, 'headers': {}}
        test = reader._check_content_type(vector, request, 1, "file.har")
        assert vector['headers'] == {'Content-Type': urlencoded + ";charset=utf=8"}
        assert test

        # content type supported
        request = {'postData': {'mimeType': ""}}
        vector = {'data': {'ava': "avascan"}, 'headers': {'Content-Type': urlencoded}}
        test = reader._check_content_type(vector, request, 1, "file.har")
        assert vector['headers'] == {'Content-Type': urlencoded}
        assert test

    def test_check_content_type_not_supported(self, reader):
        # mime type not supported
        request = {'postData': {'mimeType': "unsupported"}}
        vector = {'data': {'ava': "avascan"}, 'headers': {}}
        test = reader._check_content_type(vector, request, 1, "file.har")
        assert not test

        # content type not supported
        request = {'postData': {'mimeType': ""}}
        vector = {'data': {'ava': "avascan"}, 'headers': {'Content-Type': "unsupported"}}
        test = reader._check_content_type(vector, request, 1, "file.har")
        assert not test

        # content-type missing
        request = {'postData': {'mimeType': ""}}
        vector = {'data': '{"json": "data"}', 'headers': {'Content-Type': ""}}
        test = reader._check_content_type(vector, request, 1, "file.har")
        assert not test

    def test_check_content_type_without_data(self, reader):
        # non-post request
        request = {'postData': {'mimeType': ""}}
        vector = {'data': {}, 'headers': {}}
        test = reader._check_content_type(vector, request, 1, "file.har")
        assert vector['headers'] == {}
        assert test

    def test_parse_post_data_positive(self, reader):
        # valid json object
        vector = {'headers': {'Content-Type': "application/json"}, 'data': '{"test": "token"}'}
        test = reader._parse_post_data(vector, 1, "file.har")
        assert test

        # valid json list
        vector = {'headers': {'Content-Type': "application/json"}, 'data': '["test", "token"]'}
        test = reader._parse_post_data(vector, 1, "file.har")
        assert test

        # valid multipart data
        multipart_data = '--boundary\r\nContent-Disposition: form-data; name="ava"\r\n\r\navascan\r\n--boundary--\r\n'
        vector = {'headers': {'Content-Type': "multipart/form-data; boundary=boundary"}, 'data': multipart_data}
        test = reader._parse_post_data(vector, 1, "file.har")
        assert test

    def test_parse_post_data_negative(self, reader):
        # without data
        vector = {'headers': {'Content-Type': "application/json"}, 'data': {}}
        test = reader._parse_post_data(vector, 1, "file.har")
        assert test

        # invalid json object
        vector = {'headers': {'Content-Type': "application/json"}, 'data': '{"test": "token"'}
        test = reader._parse_post_data(vector, 1, "file.har")
        assert not test

        # invalid json list
        vector = {'headers': {'Content-Type': "application/json"}, 'data': '["test", "token"'}
        test = reader._parse_post_data(vector, 1, "file.har")
        assert not test

        # invalid multipart data
        multipart_data = '--boundary\r\navascan\r\n--boundary--\r\n'
        vector = {'headers': {'Content-Type': "multipart/form-data; boundary=boundary"}, 'data': multipart_data}
        test = reader._parse_post_data(vector, 1, "file.har")
        assert not test

    def test_parse_requests_positive(self, reader, requests, vectors):
        configs = {'cookies': {}, 'headers': {}, 'parameters': {}, 'value': "avascan",
                'excludes': ["/admin"], 'domain': ".example.com", 'agent': "", 'url': ""}

        # multiple requests
        test = reader._parse_requests(requests, configs, "file.har")
        assert test == vectors

        # empty fields
        requests[0]['cookies'] = []
        requests[0]['headers'] = []
        requests[1]['cookies'] = []
        vectors[0]['cookies'] = {}
        vectors[0]['headers'] = {'User-Agent': "AVA/1.22.1"}
        vectors[1]['cookies'] = {}
        test = reader._parse_requests(requests, configs, "file.har")
        assert test == vectors

    def test_parse_requests_negative(self, reader, requests, vectors):
        configs = {'cookies': {}, 'headers': {}, 'parameters': {}, 'value': "avascan",
                'excludes': [], 'domain': "", 'agent': "", 'url': "127.0.0.1"}

        # missing method
        requests[0]['method'] = ""
        test = reader._parse_requests(requests[0:1], configs, "file.har")
        assert test == []

        # missing url
        requests[0]['url'] = ""
        test = reader._parse_requests(requests[0:1], configs, "file.har")
        assert test == []

        # unsupported content-type
        requests[0]['url'] = "https://www.example.com"
        requests[0]['method'] = "POST"
        requests[0]['postData'] = {'mimeType': "application/x-text", 'text': "{}"}
        test = reader._parse_requests(requests[0:1], configs, "file.har")
        assert test == []

        # invalid post data
        requests[0]['postData'] = {'mimeType': "application/json", 'text': '{"test": "token"'}
        test = reader._parse_requests(requests[0:1], configs, "file.har")
        assert test == []

    def test_parse_positive(self, requests, vectors, mocker):
        configs = {'cookies': {}, 'headers': {}, 'parameters': {}, 'value': "avascan",
                   'excludes': [], 'domain': ""}
        har = {'log': {'entries': [{'request': requests[0]}, {'request': requests[1]}]}}

        # mock
        mocker.patch("builtins.open")
        mocker.patch("json.load", return_value=har)
        mocker.patch("ava.readers.vector.HarReader._parse_requests", return_value=vectors)

        # reader
        reader = HarReader(["test.json", "file.json"])

        # vectors
        test = reader.parse(configs)
        assert test == vectors + vectors

        # empty fields
        har['log']['entries'][0]['request']['cookies'] = []
        har['log']['entries'][0]['request']['headers'] = []
        har['log']['entries'][0]['request']['postData']['params'] = []
        har['log']['entries'][0]['request']['postData']['mimeType'] = ""
        vectors[0]['cookies'] = {}
        vectors[0]['headers'] = {}
        vectors[0]['data'] = {}
        test = reader.parse(configs)
        assert test == vectors + vectors

    def test_parse_negative(self, reader, requests, mocker):
        configs = {'cookies': {}, 'headers': {}, 'parameters': {}, 'value': "avascan",
                   'excludes': ["/admin"], 'domain': "example.com"}

        har = {
            'log': {
                'entries': [
                    {
                        'request': requests[0]
                    }
                ]
            }
        }

        # missing har request
        mocker.patch("builtins.open")
        mocker.patch("json.load", return_value=har)
        del har['log']['entries'][0]['request']
        with pytest.raises(InvalidFormatException):
            reader.parse(configs)

        # invalid har log
        mocker.patch("json.load", return_value={'log': {'creator': {}}})
        with pytest.raises(InvalidFormatException):
            reader.parse(configs)

        # invalid json
        mocker.patch("json.load", side_effect=JSONDecodeError("", "", 0))
        with pytest.raises(InvalidFormatException):
            reader.parse(configs)
