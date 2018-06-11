import re
import string
import warnings
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from ava.common import utility
from ava.common.check import _ValueCheck
from ava.common.constant import HTTP

# ignore URL warnings from BeautifulSoup
warnings.filterwarnings("ignore", category=UserWarning, module="bs4")

# metadata
name = __name__
description = "checks for open redirects"


class OpenRedirectCheck(_ValueCheck):
    """
    Checks for Open Redirects in the response's 'Location' header. The payloads are a URL and variations of the
    http/https schema. The response should be a 302 redirect with the payload as the 'Location'.
    """
    key = "redirect.value.location"
    name = "Open Redirect"
    description = "checks for open redirects in the 'Location' header"

    def __init__(self):
        """Define static payloads"""
        payloads = [
            'http://www.{}.com',
            'https://www.{}.com',
            '//www.{}.com',
            '/\t/www.{}.com',
            '/\\www.{}.com',
            'https:www.{}.com'
        ]

        # generate random and add to payloads
        self._random = utility.generate_random(string.ascii_lowercase)
        self._payloads = [payload.format(self._random) for payload in payloads]

    def payloads(self, url, target, value):
        """
        Generate dynamic payloads that use basic authentication format and similar subdomains to bypass validation.
        Return static and dynamic payloads.
        :param url: url value
        :param target: target name
        :param value: target value
        :return: list of payloads
        """
        # set domain
        domain = "www." + self._random + ".com"

        # parse url
        parsed = urlparse(url)

        # basic auth
        basic_auth = parsed.scheme + "://" + parsed.hostname + ":pass@" + domain

        # starts with
        starts_with = parsed.scheme + "://" + parsed.hostname + "." + domain

        # ends with
        ends_with = parsed.scheme + "://" + domain + "\\" + parsed.netloc

        # contains
        contains = parsed.scheme + "://" + domain + "/" + parsed.netloc

        # spliced
        spliced = domain.split('.')[:2] + parsed.netloc.split('.')[-2:]
        spliced = parsed.scheme + "://" + "{}.{}-{}.{}".format(*spliced)

        # dynamic
        dynamic = [basic_auth, starts_with, ends_with, contains, spliced]

        return self._payloads + dynamic

    def check(self, response, payload):
        """
        Checks for Open Redirects by looking for the payload in the 'Location' header.
        :param response: response object from server
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # get headers
        headers = response.headers

        # check response code
        if response.status_code not in [301, 302, 307, 308]:
            return False

        # check headers
        if 'Location' not in headers:
            return False

        # check Location header
        if headers['Location'] and headers['Location'].startswith(payload):
            return True
        else:
            return False


class OpenRedirectHtmlCheck(OpenRedirectCheck):
    """
    Checks for Open Redirects in anchor tags' 'href' attributes. The payload is a URL and is mangled by creating
    variations of the http/https schema. The response should contain an anchor tag with the payload as the 'href'.
    """
    key = "redirect.value.href"
    name = "Open Redirect HTML Links"
    description = "checks for open redirects in 'href' attributes of '<a>' tags"

    def check(self, response, payload):
        """
        Checks for Open Redirects by looking for the payload in anchor tags' 'href' attributes.
        :param response: response object from server
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # check response body
        if not response.text:
            return False

        # check content-type
        if 'Content-Type' in response.headers and HTTP.CONTENT_TYPE.HTML not in response.headers['Content-Type']:
            return False

        # check <a href="">
        soup = BeautifulSoup(response.text, "html.parser")
        tags = soup.find("a", attrs={"href": lambda x: x and x.startswith(payload)})
        if tags:
            return True
        else:
            return False


class OpenRedirectScriptCheck(OpenRedirectCheck):
    """
    Checks for Open Redirects in window.location statements in script tags. The payload is a URL and is mangled by
    creating variations of the http/https schema. The response should contain a script tag with the payload as the
    literal for an assignment to window.location.
    """
    key = "redirect.value.script"
    name = "Open Redirect HTML Scripts"
    description = "checks for open redirects in 'window.location' statements of script tags"

    def check(self, response, payload):
        """
        Checks for Open Redirects by looking for the payload in window.location statements.
        :param response: response object from server
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # check response body
        if not response.text:
            return False

        # check content-type
        if 'Content-Type' in response.headers and HTTP.CONTENT_TYPE.HTML not in response.headers['Content-Type']:
            return False

        # check scripts for location
        soup = BeautifulSoup(response.text, "html.parser")
        tags = soup.find_all(lambda t: t.name == "script" and ".location" in t.text)

        # compile regex
        regex = re.compile(r"(?:window|document|self)\.location(?:\.href)?\s*=\s*['\"](.+?)['\"]")

        for tag in tags:
            # extract literal
            matches = regex.findall(tag.text)

            # check location
            for match in matches:
                location = match.replace('\\/', '/').replace('\\\\', '\\')
                if location.startswith(payload):
                    return True

        return False
