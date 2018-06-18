import string
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from ava.common import utility
from ava.common.check import _ValueCheck
from ava.common.constant import HTTP
from ava.common.exception import InvalidFormatException

# metadata
name = __name__
description = "checks for cross-site scripting"


class CrossSiteScriptingCheck(_ValueCheck):
    """
    Checks for Cross-Site Scripting by including HTML tags in the response. The payloads are a HTML tag and the tag
    as injected into a HTML attribute.
    """
    key = "xss.value.tag"
    name = "Cross-Site Scripting"
    description = "checks for cross-Site scripting by injecting HTML tags"
    example = "<{}></{}>"

    def __init__(self):
        """Define static payloads"""
        payloads = [
            # two tags
            '<{}></{}>',
            '"><{}></{}><"',
            "'><{}></{}><'",
            ' ><{}></{}>< ',
            # one tag
            '<{} event=()>',
            '"><{} event=()><"',
            "'><{} event=()><'",
            ' ><{} event=()>< ',
            # script tags
            '</script><{}></{}><script>',
            '</script><{} event=()><script>',
            # special characters
            '\\"><{}></{}><\\"',
            '\\"><{} event=()><\\"'
        ]

        # generate random and add to payloads
        self._random = utility.generate_random(string.ascii_lowercase)
        self._payloads = [payload.format(self._random, self._random) for payload in payloads]

    def check(self, response, payload):
        """
        Checks for Cross-Site Scripting by looking for the HTML tag in the response.
        :param response: response object
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # check response body
        if not response.text:
            return False

        # check content-type
        if 'Content-Type' in response.headers and HTTP.CONTENT_TYPE.HTML not in response.headers['Content-Type']:
            return False

        # check tag
        soup = BeautifulSoup(response.text, "html.parser")
        tags = soup.find(self._random)
        if tags:
            return True
        else:
            return False

    def _check_payloads(self, payloads):
        """
        Checks if the payloads are adoptable for this class and modify the payloads to adjust to check function.
        InvalidFormatException is raised, if a payload is not adoptable.
        Children can override.
        :param payloads: list of payloads
        :return: list of modified payloads
        """
        for i, payload in enumerate(payloads):
            if '<{}' not in payload:
                raise InvalidFormatException("Payload of {} must have a tag named '{{}}'".format(self.key))
            payloads[i] = payload.format(self._random, self._random)
        return payloads


class CrossSiteScriptingLinkCheck(_ValueCheck):
    """
    Checks for Cross-Site Scripting by including JavaScript in 'href' attributes of <a> tags. The payload uses the
    'javascript:' schema.
    """
    key = "xss.value.href"
    name = "Cross-Site Scripting HTML Links"
    description = "checks for cross-site scripting in 'href' attributes of '<a>' tags"
    example = "javascript:{}()"

    def __init__(self):
        """Define static payload"""
        payloads = [
            "javascript:{}()"
        ]

        # generate random and add to payloads
        self._random = utility.generate_random(string.ascii_lowercase, size=4)
        self._payloads = [payload.format(self._random) for payload in payloads]

    def check(self, response, payload):
        """
        Checks for Cross-Site Scripting by looking for Javascript in 'href' attributes of <a> tags.
        :param response: response object
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
        tags = soup.find("a", attrs={"href": payload})
        if tags:
            return True
        else:
            return False

    def _check_payloads(self, payloads):
        """
        Checks if the payloads are adoptable for this class and modify the payloads to adjust to check function.
        InvalidFormatException is raised, if a payload is not adoptable.
        Children can override.
        :param payloads: list of payloads
        :return: list of modified payloads
        """
        for i, payload in enumerate(payloads):
            if '{}()' not in payload:
                raise InvalidFormatException("Payload of {} must have a function named '{{}}'".format(self.key))
            payloads[i] = payload.format(self._random)
        return payloads


class CrossSiteScriptingScriptSrcCheck(_ValueCheck):
    """
    Checks for Cross-Site Scripting by including URLs in 'src' attributes of <script> tags. The payloads use variations
    of //www.example.com/example.js.
    """
    key = "xss.value.src"
    name = "Cross-Site Scripting HTML Scripts Source"
    description = "checks for cross-site scripting in 'src' attributes of '<script>' tags"
    example = "//www.{}.com/{}.js"

    def __init__(self):
        """Define static payload"""
        payloads = [
            # within src attribute
            '//www.{}.com/{}.js',
            '\\www.{}.com\\{}.js',
            # add src attribute
            '" src=//www.{}.com/{}.js><"',
            '" src=\\www.{}.com\\{}.js><"',
            "' src=//www.{}.com/{}.js><'",
            "' src=\\www.{}.com\\{}.js><'",
            " src=//www.{}.com/{}.js>< ",
            " src=\\www.{}.com\\{}.js>< "
        ]

        # generate random and add to payloads
        self._random = utility.generate_random(string.ascii_lowercase)
        self._payloads = [payload.format(self._random, self._random[0]) for payload in payloads]

    def check(self, response, payload):
        """
        Checks for Cross-Site Scripting by looking for URLs in 'src' attributes of <script> tags.
        :param response: response object
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # check response body
        if not response.text:
            return False

        # check content-type
        if 'Content-Type' in response.headers and HTTP.CONTENT_TYPE.HTML not in response.headers['Content-Type']:
            return False

        # check <script src="">
        soup = BeautifulSoup(response.text, "html.parser")
        tags = soup.find(lambda t: t.name == "script" and 'src' in t.attrs and self._random in t['src'])
        if not tags:
            return False

        # set domain
        domain = "www.{}.com".format(self._random)

        # check domain
        source = tags['src'].replace('\\', '/')
        parsed = urlparse(source)
        if parsed.hostname and domain in parsed.hostname:
            return True
        else:
            return False

    def _check_payloads(self, payloads):
        """
        Checks if the payloads are adoptable for this class and modify the payloads to adjust to check function.
        InvalidFormatException is raised, if a payload is not adoptable.
        Children can override.
        :param payloads: list of payloads
        :return: list of modified payloads
        """
        for i, payload in enumerate(payloads):
            if 'www.{}.com' not in payload:
                raise InvalidFormatException("Payload of {} must have address of 'www.{{}}.com'".format(self.key))
            payloads[i] = payload.format(self._random)
        return payloads


class CrossSiteScriptingScriptCheck(_ValueCheck):
    """
    Checks for Cross-Site Scripting by including JavaScript in <script> tags. The payloads concatenate strings and
    inject into a string.
    """
    key = "xss.value.script"
    name = "Cross-Site Scripting HTML Scripts"
    description = "checks for cross-site scripting in HTML <script> tags"
    example = "'+{}()+'"

    def __init__(self):
        """Define static payloads"""
        payloads = [
            # single quotes
            "'+{}()+'",
            "';{}();//'",
            # double quotes
            '"+{}()+"',
            '";{}();//"',
            # no quotes
            '{}()',
            # no parentheses
            "'+{}``+'",
            '"+{}``+"',
            "';{}``;//'",
            '";{}``;//"'
        ]

        # generate random and add to payloads
        self._random = utility.generate_random(string.ascii_lowercase, size=5)
        self._payloads = [payload.format(self._random, self._random) for payload in payloads]

    def check(self, response, payload):
        """
        Check for Cross-Site Scripting by looking for unescaped JavaScript in <script> tags. The added single quote
        helps to confirm the payload is not escaped.
        :param response: response object
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # check response body
        if not response.text:
            return False

        # check content-type
        if 'Content-Type' in response.headers and HTTP.CONTENT_TYPE.HTML not in response.headers['Content-Type']:
            return False

        # strip quotes and comments
        code = payload.strip('\'"/')

        # look for code in script text
        soup = BeautifulSoup(response.text, "html.parser")
        tags = soup.find(lambda t: t.name == "script" and code in utility.parse_javascript(t.text))
        if tags:
            return True
        else:
            return False


class CrossSiteScriptingEventCheck(CrossSiteScriptingScriptCheck):
    """
    Checks for Cross-Site Scripting by including JavaScript in HTML events. The payloads concatenate strings and
    inject into a string.
    """
    key = "xss.value.event"
    name = "Cross-Site Scripting HTML Events"
    description = "checks for cross-site scripting in HTML event attributes"

    def check(self, response, payload):
        """
        Checks for Cross-Site Scripting by looking for unescaped JavaScript in HTML events. The added single quote helps
        to confirm the payload is not escaped.
        :param response: response object
        :param payload: payload value
        :return: true if vulnerable, false otherwise
        """
        # define events
        events = ["onload", "onclick", "onmouseover", "onmousedown", "onkeypress", "onerror", "onsubmit"]

        # check response body
        if not response.text:
            return False

        # check content-type
        if 'Content-Type' in response.headers and HTTP.CONTENT_TYPE.HTML not in response.headers['Content-Type']:
            return False

        # strip quotes and comments
        code = payload.strip('\'"/')

        # look for payload in tags with events
        soup = BeautifulSoup(response.text, "html.parser")
        for event in events:
            tags = soup.find(lambda t: event in t.attrs and code in utility.parse_javascript(t[event]))
            if tags:
                return True

        return False
