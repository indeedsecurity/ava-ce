import json
import logging
from urllib import parse
from requests_toolbelt import MultipartDecoder, ImproperBodyPartContentException
from json.decoder import JSONDecodeError
from http.cookies import SimpleCookie
from ava.common.constant import HTTP
from ava.common.exception import InvalidFormatException


# configure logging
logger = logging.getLogger(__name__)


class HarReader:
    def __init__(self, sources):
        """Sets the reader's data source"""
        self._sources = sources

    def _convert_elements(self, elements):
        """
        Converts elements from a list of dictionaries to a single dictionary. This is used for cookies, headers,
        query string, and post data.
        :param elements: list of dictionaries
        :return: converted dictionary
        """
        # convert to dictionary
        converted = {element['name']: element['value'] for element in elements}
        return converted

    def _convert_post_data(self, post_data):
        """
        Extracts post data and converts parameters to a dictionary. Post data parameters are checked before text. An
        empty string is returned as default.
        :param post_data: post data dictionary
        :return: data as dictionary or string
        """
        # check params
        if post_data.get('params'):
            return self._convert_elements(post_data['params'])

        # check text
        if post_data.get('text'):
            return post_data['text']

        # default
        return {}

    def _convert_request(self, request):
        """
        Converts HAR format to the requests library format. This includes url, method, cookies, headers, and params.
        Missing elements default to an empty list or dictionary.
        :param request: request object
        :return: vector dictionary
        """
        # extract elements
        cookies = request.get('cookies', [])
        headers = request.get('headers', [])
        params = request.get('queryString', [])
        data = request.get('postData', {})

        # convert elements
        vector = {
            'url': request.get('url'),
            'method': request.get('method'),
            'cookies': self._convert_elements(cookies),
            'headers': self._convert_elements(headers),
            'params': self._convert_elements(params),
            'data': self._convert_post_data(data)
        }

        return vector

    def _check_url(self, vector, num, name):
        """
        Checks the vector's URL.  URL must have a value, hostname, and a scheme of 'http' or 'https'. If the path
        is not specified, a default of '/' is added. Query string is dropped from the URL.
        :param vector: request object
        :param num: index number
        :param name: file name
        :return: True or False
        """
        # check url
        if not vector['url']:
            logger.warning("'url' missing for vector #%d in '%s'. Ignoring.", num, name)
            return False

        # parse url
        parsed = parse.urlparse(vector['url'])

        # check scheme
        if parsed.scheme not in ["http", "https"]:
            logger.warning("'url' must be 'http' or 'https' for vector #%d in '%s'. Ignoring.", num, name)
            return False

        # check netloc
        if not parsed.netloc:
            logger.warning("'url' missing hostname for vector #%d in '%s'. Ignoring.", num, name)
            return False

        # check path
        path = parsed.path or '/'

        # add back
        vector['url'] = parsed.scheme + '://' + parsed.netloc + path

        # default
        return True

    def _change_hostname(self, vector, url):
        """
        Change the hostname in request url.
        :param vector: vector dictionary
        :param url: url string
        """
        # parse url in vector
        parsed = parse.urlparse(vector['url'])

        if url.startswith("http"):
            # parse url in configs
            parsed_in_configs = parse.urlparse(url)

            # use specified scheme
            scheme = parsed_in_configs.scheme
            netloc = parsed_in_configs.netloc
        else:
            # use original scheme
            scheme = parsed.scheme
            netloc = url

        # change request url
        vector['url'] = scheme + "://" + netloc + parsed.path

    def _check_domain(self, vector, configs, num, name):
        """
        Checks if the url's hostname is within the domain. Returns the result of the check.
        :param vector: vector dictionary
        :param configs: AVA configs
        :param num: index number
        :param name: file name
        :return: True or False
        """
        url = vector['url']

        # check domain
        if not configs['domain']:
            return True

        # parse url
        parsed = parse.urlparse(url)

        # check hostname
        # duplicated in utility._check_http_redirect()
        if not parsed.hostname.endswith(configs['domain']):
            logger.debug("'url' outside of domain for vector #%d in '%s'. Ignoring.", num, name)
            return False

        # default
        return True

    def _check_excludes(self, vector, configs, num, name):
        """
        Checks if the url's path starts with any of the excludes. Returns the result of the check.
        :param vector: vector dictionary
        :param configs: AVA configs
        :param num: index number
        :param name: file name
        :return: True or False
        """
        url = vector['url']

        # check excludes
        if not configs['excludes']:
            return False

        # parse url manually due to regex characters
        parsed = parse.urlparse(url)
        root = parsed.scheme + "://" + parsed.netloc
        path = url[len(root):]

        # check path
        # duplicated in utility._check_http_redirect()
        if any(path.startswith(p) for p in configs['excludes']):
            logger.debug("'url' matched excludes for vector #%d in '%s'. Ignoring.", num, name)
            return True

        # default
        return False

    def _check_method(self, vector, num, name):
        """
        Checks the vector's method. If the method is missing, it is set to GET. Supported methods are those available
        in the requests library, namely HEAD, GET, POST, PUT, PATCH, and DELETE. Method is canonicalized to uppercase.
        :param vector: vector dictionary
        :param num: index number
        :param name: file name
        :return: True or False
        """
        supported = list(HTTP.METHOD)
        method = vector['method']

        # check empty
        if not method:
            logger.warning("'method' missing for vector #%d in '%s'. Ignoring.", num, name)
            return False

        # check supported
        if method.upper() not in supported:
            logger.warning("'method' not supported for vector #%d in '%s'. Ignoring.", num, name)
            return False

        # canonicalize and add back
        vector['method'] = method.upper()

        # default
        return True

    def _check_cookies(self, vector, configs):
        """
        Checks the vector's cookies. If values were not specified in the cookies object, then the 'Cookies' header
        is checked. Each cookie in the header is parsed manually.
        :param vector: vector dictionary
        :param configs: AVA configs
        """
        cookies = vector['cookies']

        # check headers if not cookies
        if not cookies and 'Cookie' in vector['headers']:
            header = vector['headers']['Cookie']
            simple = SimpleCookie()

            # convert from 'key=value; key=value'
            simple.load(header)
            for morsel in simple.values():
                cookies[morsel.key] = morsel.value

        # add configs
        cookies.update(configs['cookies'])

    def _check_headers(self, vector, configs):
        """
        Checks the vector's headers. Headers in the blacklist are removed. Header names are canonicalized to
        title case.
        :param vector: vector dictionary
        :param configs: AVA configs
        """
        blacklist = ["Host", "Cookie", "Accept", "Accept-Encoding", "Connection", "Content-Length"]
        headers = vector['headers']
        filtered = {}

        # filter and canonicalize headers
        for name, value in headers.items():
            if name.title() not in blacklist:
                name = name.title()
                filtered[name] = value

        # update headers
        headers.clear()
        headers.update(filtered)

        # add configs
        headers.update(configs['headers'])

    def _check_query_string(self, vector, request, configs):
        """
        Checks the vector's query string. If values were not specified in the query string list, then the URL is
        checked. Default values are added to empty parameters.
        :param vector: vector dictionary
        :param request: request object
        :param configs: AVA configs
        """
        url = parse.urlparse(request['url'])
        query_string = vector['params']

        # check url if not query string
        if not query_string and url.query:
            parsed = parse.parse_qsl(url.query, keep_blank_values=True)
            query_string.update(parsed)

        # add value if missing
        for name, value in query_string.items():
            if not value and configs['value']:
                query_string[name] = configs['value']

        # add configs
        if vector['method'] == HTTP.METHOD.GET:
            query_string.update(configs['parameters'])

    def _check_post_data(self, vector, configs):
        """
        Checks the vector's post data. Default values are added to empty parameters.
        :param vector: vector dictionary
        :param configs: AVA configs
        """
        headers = vector['headers']
        post_data = vector['data']

        # check if parameters
        if not isinstance(post_data, dict):
            return

        # add value if missing
        for name, value in post_data.items():
            if not value and configs['value']:
                post_data[name] = configs['value']

        # add configs and content-type
        if vector['method'] in [HTTP.METHOD.POST, HTTP.METHOD.PUT, HTTP.METHOD.PATCH]:
            post_data.update(configs['parameters'])

            if configs['parameters'] and not headers.get('Content-Type'):
                headers['Content-Type'] = HTTP.CONTENT_TYPE.FORM

    def _check_user_agent(self, vector, configs):
        """
        Checks the vector's user-agent. If config is set, it is used for the vector. Otherwise, if user-agent is
        missing, it is set to a default value.
        :param vector: vector dictionary
        :param configs: AVA configs
        """
        headers = vector['headers']

        # set with configs
        if configs['agent']:
            headers['User-Agent'] = configs['agent']

        # set to default
        if not headers.get('User-Agent'):
            headers['User-Agent'] = "AVA/1.22.1"

    def _check_content_type(self, vector, request, num, name):
        """
        Checks the request's content-type. Supported content-type is x-www-form-urlencoded.
        :param vector: vector dictionary
        :param request: request object
        :param num: index number
        :param name: file name
        :return: True or False
        """
        # must be fingerprinted in utility.fingerprint_vector()
        supported = [HTTP.CONTENT_TYPE.FORM, HTTP.CONTENT_TYPE.JSON, HTTP.CONTENT_TYPE.MULTIPART, HTTP.CONTENT_TYPE.TEXT]
        headers = vector['headers']

        # check data
        if not vector['data']:
            return True

        # default to mime type
        if request['postData'].get('mimeType'):
            logger.debug("'postData' contains 'mimeType' for vector #%d in '%s'. Setting 'Content-Type'.", num, name)
            headers['Content-Type'] = request['postData']['mimeType']

        # check missing
        if not headers.get('Content-Type'):
            logger.warning("'postData' missing 'Content-Type' for vector #%d in '%s'. Ignoring.", num, name)
            return False

        # check supported
        if not any(headers['Content-Type'].startswith(s) for s in supported):
            logger.warning("'Content-Type' not supported for vector #%d in '%s'. Ignoring.", num, name)
            return False

        # default
        return True

    def _parse_post_data(self, vector, num, name):
        """
        Parse post data to verify it can be converted into an object by the auditors. This prevents conversion errors
        for each check and vector combination during the scan.
        :param vector: vector dictionary
        :param num: index number
        :param name: file name
        :return: True or False
        """
        headers = vector['headers']
        post_data = vector['data']

        # check data
        # content-type checked in self._check_content_type()
        if not post_data:
            return True

        # check json
        if headers['Content-Type'].startswith(HTTP.CONTENT_TYPE.JSON):
            try:
                json.loads(post_data)
            except JSONDecodeError:
                logger.warning("'postData' is not valid JSON for vector #%d in '%s'. Ignoring.", num, name)
                return False

        # check multipart
        if headers['Content-Type'].startswith(HTTP.CONTENT_TYPE.MULTIPART):
            try:
                MultipartDecoder(post_data.encode(), headers['Content-Type'])
            except (ImproperBodyPartContentException, AttributeError):
                logger.warning("'postData' is not valid multipart data for vector #%d in '%s'. Ignoring.", num, name)
                return False

        # default
        return True

    def _parse_requests(self, requests, configs, name):
        """
        Parses HAR request entries and returns vectors in requests library format. Vector must have a URL. If a method
        is not provided, it defaults to GET. Parameters, cookies, and headers are generated based on AVA configs.
        :param requests: list of requests
        :param configs: AVA configs
        :param name: vector file name
        :return: list of vectors as dictionaries
        """
        vectors = []

        # parse requests
        for i, request in enumerate(requests):
            # convert har
            vector = self._convert_request(request)

            # check url
            if not self._check_url(vector, i+1, name):
                continue

            # change host
            if configs['url']:
                self._change_hostname(vector, configs['url'])

            # check domain
            if not self._check_domain(vector, configs, i+1, name):
                continue

            # check excludes
            if self._check_excludes(vector, configs, i+1, name):
                continue

            # check method
            if not self._check_method(vector, i+1, name):
                continue

            # check cookies and headers
            # must check cookies first
            self._check_cookies(vector, configs)
            self._check_headers(vector, configs)

            # check query string and post data
            self._check_query_string(vector, request, configs)
            self._check_post_data(vector, configs)

            # check user-agent
            self._check_user_agent(vector, configs)

            # check content-type
            if not self._check_content_type(vector, request, i+1, name):
                continue

            # parse post data
            if not self._parse_post_data(vector, i+1, name):
                continue

            vectors.append(vector)

        return vectors

    def parse(self, configs):
        """
        Parses a list of HAR files. Vectors from each HAR file are combined and returned as a list.
        :param configs: AVA configs
        :return: list of vectors as dictionaries
        """
        combined = []

        # parse each vector file in list
        for name in self._sources:
            logger.debug("Reading vectors from '%s'.", name)

            try:
                # load HAR as json
                with open(name) as f:
                    har = json.load(f)

                # get requests
                requests = [entry['request'] for entry in har['log']['entries']]

                # parse requests
                vectors = self._parse_requests(requests, configs, name)

                # combine
                combined.extend(vectors)
            except JSONDecodeError as e:
                raise InvalidFormatException(e)
            except KeyError as e:
                raise InvalidFormatException("{} missing in '{}'".format(e, name))

        return combined
