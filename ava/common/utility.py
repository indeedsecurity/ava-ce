import inspect
import logging
import os
import random
import sys
import urllib3
import string
from urllib import parse
from ava.common.constant import HTTP
from ava.common.exception import InvalidFormatException, UnknownKeyException
from ava.parsers.cookie import SimpleCookie, ComplexCookie
from ava.parsers.javascript import JavaScriptParser
from ava.parsers.json import JsonObject
from ava.parsers.multipart import MultipartForm
from ava.parsers.xml import XmlDocument

# configure logging
logger = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)


def generate_random(sequence, size=7):
    """
    Generates a random value based on the given sequence and size. Sequence can be letters or character classes, such
    as string.ascii_lowercase or string.digits.
    :param sequence: sequence as string
    :param size: size as integer
    :return: random value as string
    """
    # check sequence
    if not sequence:
        return ''

    # set generator
    generator = random.SystemRandom()

    # choose random for each index
    choices = [generator.choice(sequence) for i in range(size)]

    return ''.join(choices)


def fingerprint_vector(vector):
    """
    Fingerprint a vector. Fingerprint takes into account the URL, method, query string, and post data. Post data is
    parsed into name-value pairs for injection points. Cookies and headers are omitted from fingerprints to remove
    browser and session variances.
    :param vector: vector dictionary
    :return: fingerprint dictionary
    """
    content_type = vector['headers'].get('Content-Type')
    data = vector['data']

    # parse data
    if data and content_type:
        # form
        if content_type.startswith(HTTP.CONTENT_TYPE.FORM):
            pass
        # json
        elif content_type.startswith(HTTP.CONTENT_TYPE.JSON):
            data = parse_json(data).literals()
        # multipart
        elif content_type.startswith(HTTP.CONTENT_TYPE.MULTIPART):
            data = parse_multipart(data, content_type).names()
        # text
        elif content_type.startswith(HTTP.CONTENT_TYPE.TEXT):
            data = data.strip()
        # unknown
        else:
            raise UnknownKeyException("Fingerprint missing for Content-Type '{}'".format(content_type))

    # fingerprint
    fingerprint = {
        'url': vector['url'],
        'method': vector['method'],
        'params': vector['params'],
        'data': data
    }

    return fingerprint


def get_package_classes(package, includes=None):
    """
    Loads all available classes for a given package, unless 'includes' is specified. Classes starting with '_'
    indicate parent classes that are not intended to be instantiated. These are not considered to be available
    for loading and are ignored.
    :param package: package name
    :param includes: list of modules
    :return: set of available classes from package
    """
    classes = set()
    modules = set()

    # convert package name
    package = "ava." + package

    # get child classes
    if includes:
        # add modules from package directory
        home = os.path.realpath(os.path.join(__file__, '..', '..', '..'))
        directory = os.path.join(home, package.replace('.', os.sep))
        for name in os.listdir(directory):
            if name.endswith(".py") and name != "__init__.py":
                mod = package + '.' + name[:-3]
                modules.add(mod)

        # import classes which are defined within module and have keys in includes
        for mod in modules:
            imported = __import__(mod, fromlist=[package])
            for name, clazz in inspect.getmembers(imported, inspect.isclass):
                if clazz.__module__ == mod and not name.startswith('_') and clazz.key in includes:
                    classes.add(clazz)

    modules = set()

    # get list of modules
    if includes:
        # add modules from includes
        mods = [package + '.' + name for name in includes if '.' not in name]
        modules.update(mods)
    elif len(classes) == 0:
        # add modules from package directory
        home = os.path.realpath(os.path.join(__file__, '..', '..', '..'))
        directory = os.path.join(home, package.replace('.', os.sep))
        for name in os.listdir(directory):
            if name.endswith(".py") and name != "__init__.py":
                mod = package + '.' + name[:-3]
                modules.add(mod)

    # import classes defined within module
    for mod in modules:
        imported = __import__(mod, fromlist=[package])
        for name, clazz in inspect.getmembers(imported, inspect.isclass):
            if clazz.__module__ == mod and not name.startswith('_'):
                classes.add(clazz)

    return classes


def get_package_info(package):
    """
    Gets names and descriptions of modules within a given package. Uses load_classes() to get modules.
    :param package: package name
    :return: list of module name/description as tuple
    """
    modules = set()
    info = {}

    # load classes for package
    classes = get_package_classes(package)

    # get module names, descriptions, class keys and description
    for clazz in classes:
        name = clazz.__module__.split('.')[-1]
        if name not in info:
            module = sys.modules[clazz.__module__]
            description = module.description
            info[name] = (description, [])
        info[name][1].append((clazz.key, clazz.description))

    return sorted(map(lambda x: (x[0],) + x[1], info.items()))


def parse_cookie(cookie):
    """
    Utility function to deconstruct cookie strings. It could be simple or complex. Simple cookie strings are single
    values, while complex cookie strings are lists of key/value pairs delimited by &, :, and =. Values can be replaced
    by payloads. Attempt to detect base64 values, as they contain equals signs but are not complex.
    :param cookie: cookie string
    :return: SimpleCookie or ComplexCookie
    """
    # check empty or single char
    if len(cookie) < 2:
        return SimpleCookie(cookie)

    # base64
    if _check_base64(cookie):
        return SimpleCookie(cookie)

    # complex
    if any(delim in cookie for delim in ['&', ':', '=']):
        return ComplexCookie(cookie)

    # default
    return SimpleCookie(cookie)


def _check_base64(cookie):
    """
    Check if the cookie string is a base64 value. Check if its length is a multiple of 4 and ends in an equals sign.
    Base64 values that do not end in equals sign will not be categories as complex cookies, so they are ignored.
    :param cookie: cookie string
    :return: True or False
    """
    # remove quotes
    value = cookie
    if value[0] == '"' and value[-1] == '"':
        value = value[1:-1]

    # F5 remove '!'
    if value[0] == '!':
        value = value[1:]

    # check if length is multiple of 4 and ends with = or ==
    if len(value) % 4 == 0 and value.count('=') == 1 and value[-1] == '=':
        return True
    if len(value) % 4 == 0 and value.count('=') == 2 and value[-2:] == "==":
        return True

    # default
    return False


def parse_xml(xml_string):
    """
    Utility function to deconstruct XML strings. Text elements can be replaced by payloads.
    :param xml_string: xml string
    :return: XmlDocument or None
    """
    # parse xml
    try:
        parsed = XmlDocument(xml_string)
    except InvalidFormatException:
        parsed = None

    # return
    return parsed


def parse_javascript(text):
    """
    Utility function to parse JavaScript and remove strings and comments. This allows for the detection of XSS
    vulnerabilities within a JavaScript context.
    :param text: text as string
    :return: stripped text as string
    """
    parser = JavaScriptParser(text)
    return parser.strip()


def parse_json(json_string):
    """
    Utility function to parse JSON strings. Literals can be replaced by payloads. InvalidFormatException is raised
    for invalid JSON.
    :param json_string: json as string
    :return: JsonObject
    """
    return JsonObject(json_string)


def parse_multipart(multipart_string, content_type):
    """
    Utility function to parse Multipart data strings. Parts can be replaced by payloads. InvalidFormatException is
    raised for invalid data or content-type.
    :param multipart_string: multipart data as string
    :param content_type: content_type as string
    :return: MultipartForm
    """
    return MultipartForm(multipart_string, content_type)


def _check_http_redirect(response, configs):
    """
    Checks if a HTTP redirect should be followed. If a domain is configured, the hostname of the redirection should be
    within the domain. If the domain is not configured, the network location of the request and redirection should
    match. If a list of excludes is configured, the path should not start with any of the excluded paths.
    :param response: response object
    :param configs: AVA configs
    :return: True or False
    """
    # check if redirect
    if not response.is_redirect:
        return False

    # parse urls
    request = parse.urlparse(response.request.url)
    redirect = parse.urlparse(response.next.url)

    # check domain
    if configs['domain'] and not redirect.hostname.endswith(configs['domain']):
        logger.debug("Redirect '%s' outside of domain. Not following.", redirect.hostname)
        return False

    # check netloc
    if not configs['domain'] and request.netloc != redirect.netloc:
        logger.debug("Redirect '%s' has different network location. Not following.", redirect.netloc)
        return False

    # check excludes
    if configs['excludes'] and any(redirect.path.startswith(p) for p in configs['excludes']):
        logger.debug("Redirect '%s' path matches excludes. Not following.", redirect.path)
        return False

    return True


def send_http_request(session, vector, configs):
    """
    Sends a HTTP request for the given vector using the provided session. If follow redirects is configured, the
    requests resolver is used to perform redirections. User agent, timeout, and proxy are set to configurations. The
    request can raise the following: Timeout, ConnectionError, ConnectionResetError, and TooManyRedirects.
    :param session: requests session
    :param vector: vector dictionary
    :param configs: AVA configs
    :return: response object
    """
    # set kwargs
    kwargs = {'timeout': configs['timeout']}

    # set proxy and disable warnings
    if configs['proxy']:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        kwargs['proxies'] = {'http': configs['proxy'], 'https': configs['proxy']}
        kwargs['verify'] = False

    # send request
    response = session.request(**vector, **kwargs, allow_redirects=False)
    logging.debug("%s : %s : %d", response.request.method.capitalize(), response.request.url, response.status_code)

    if configs['follow']:
        history = []

        # get resolver
        resolver = session.resolve_redirects(response, response.request, **kwargs)

        # follow redirects
        while _check_http_redirect(response, configs):
            history.append(response)
            response = next(resolver)
            logging.debug("Redirect : %s : %d", response.request.url, response.status_code)

        # add history
        if history:
            response.history = history

    return response

def replace_with_unicode(data, charset=string.printable):
    """
    Replace ascii with unicode. This encoding enables payloads to bypass checks such as black lists of urls.
    :param data: string
    :param charset: charset which should be replaced
    :return: unicoded string
    """

    encode = {}
    for c in string.printable:
        encode[c] = c

    # numbers
    encode['0'] = '\u24EA'
    for i in range(1, 10):
        encode[chr(ord('0') + i)] = chr(0x245f + i)

    # upper letters
    for i in range(26):
        encode[chr(ord('A') + i)] = chr(0x24B6 + i)

    # lower letters
    for i in range(26):
        encode[chr(ord('a') + i)] = chr(0x24D0 + i)

    # dot
    encode['.'] = '｡'

    return ''.join([encode[c] if c in charset else c for c in data])
