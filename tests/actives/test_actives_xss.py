import pytest
from ava.actives.xss import CrossSiteScriptingCheck, CrossSiteScriptingLinkCheck, CrossSiteScriptingScriptSrcCheck
from ava.actives.xss import CrossSiteScriptingScriptCheck, CrossSiteScriptingEventCheck


@pytest.fixture
def response():
    return type("Response", (object,), {})


class TestCrossSiteScriptingCheck:
    payloads = [
        '<avascan></avascan>',
        '"><avascan></avascan><"',
        "'><avascan></avascan><'",
        ' ><avascan></avascan>< ',
        '<avascan event=()>',
        '"><avascan event=()><"',
        "'><avascan event=()><'",
        ' ><avascan event=()>< ',
        '</script><avascan></avascan><script>',
        '</script><avascan event=()><script>',
        '\\"><avascan></avascan><\\"',
        '\\"><avascan event=()><\\"',
    ]

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="avascan")
        return CrossSiteScriptingCheck()
    
    def test_init(self, check):
        # init
        assert check._payloads == self.payloads
    
    def test_check_true_positive(self, check, response):
        response.headers = {'Content-Type': ''}
    
        # true positive two tags
        response.text = "<html><head></head><body><avascan></avascan><body></html>"
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[0])
        assert test
    
        # true positive one tag
        response.text = "<html><head></head><body><avascan event=()><body></html>"
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[4])
        assert test

    def test_check_true_negative(self, check, response):
        response.headers = {'Content-Type': ''}
    
        # true negative empty
        response.text = ""
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[0])
        assert not test
    
        # true negative html
        response.text = """<html><head></head><body><body></html>"""
        test = check.check(response, check._payloads[0])
        assert not test
    
        # true negative encoded
        response.text = "<html><head></head><body>&lt;avascan&gt;&lt;/avascan%gt;<body></html>"
        test = check.check(response, check._payloads[0])
        assert not test
    
        # true negative application/json
        response.text = "{<avascan></avascan>}"
        response.headers['Content-Type'] = "application/json"
        test = check.check(response, check._payloads[0])
        assert not test
    
        # true negative text/plain
        response.text = 'error="<avascan></avascan>"'
        response.headers['Content-Type'] = "text/plain"
        test = check.check(response, check._payloads[0])
        assert not test


class TestCrossSiteScriptingLinkCheck:
    payloads = [
        "javascript:avascan()",
        '");avascan();//',
        "%22);avascan();//",
        "');avascan();//",
        "%27);avascan();//"
    ]

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="avascan")
        return CrossSiteScriptingLinkCheck()
    
    def test_init(self, check):
        # init
        assert check._payloads == self.payloads

    def test_check_true_positive(self, check, response):
        response.headers = {'Content-Type': ''}
    
        # true positive
        response.text = '<html><head></head><body><a href="javascript:avascan()">Link</a></body></html>'
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[0])
        assert test

        # true positive
        response.text = '<html><head></head><body><a href=\'javascript:console.log("ava");avascan();//ava\'>Link</a></body></html>'
        test = check.check(response, check._payloads[1])
        assert test

        # true positive urlencode
        response.text = '<html><head></head><body><a href=\'javascript:console.log("ava%22);avascan();//ava\'>Link</a></body></html>'
        test = check.check(response, check._payloads[2])
        assert test

    def test_check_true_negative(self, check, response):
        response.headers = {'Content-Type': ''}

        # true negative empty
        response.text = ""
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[0])
        assert not test
    
        # true negative html
        response.text = "<html><head></head><body></body></html>"
        test = check.check(response, check._payloads[0])
        assert not test
    
        # true negative http
        response.text = '<html><head></head><body><a href="http://javascript:avascan()">Link</a></body></html>'
        test = check.check(response, check._payloads[0])
        assert not test
    
        # true negative escape
        response.text = '<html><head></head><body><a href=\'javascript:console.log("ava\\");avascan();//ava\'>Link</a></body></html>'
        test = check.check(response, check._payloads[1])
        assert not test

        # true negative application/json
        response.text = '{<a href="javascript:avascan()">}'
        response.headers['Content-Type'] = "application/json"
        test = check.check(response, check._payloads[0])
        assert not test
    
        # true negative text/plain
        response.text = 'error="<a href="javascript:avascan()">"'
        response.headers['Content-Type'] = "text/plain"
        test = check.check(response, check._payloads[0])
        assert not test


class TestCrossSiteScriptingScriptSrcCheck:
    payloads = [
        '//www.avascan.com/a.js',
        '\\www.avascan.com\\a.js',
        '" src=//www.avascan.com/a.js><"',
        '" src=\\www.avascan.com\\a.js><"',
        "' src=//www.avascan.com/a.js><'",
        "' src=\\www.avascan.com\\a.js><'",
        " src=//www.avascan.com/a.js>< ",
        " src=\\www.avascan.com\\a.js>< "
    ]

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="avascan")
        return CrossSiteScriptingScriptSrcCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads

    def test_check_true_positive(self, check, response):
        response.headers = {'Content-Type': ''}

        # true positive within src
        response.text = '<html><head></head><body><script src="//www.avascan.com/a.js"></body></html>'
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[0])
        assert test

        # true positive add src
        response.text = '<html><head></head><body><script data-attr="" src="//www.avascan.com/a.js"><""></body></html>'
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[2])
        assert test

    def test_check_true_negative(self, check, response):
        response.headers = {'Content-Type': ''}

        # true negative empty
        response.text = ""
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative html
        response.text = "<html><head></head><body></body></html>"
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative escaped
        response.text = '<html><head></head><body><script src="\/\/www.avascan.com\/a.js"></body></html>'
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative application/json
        response.text = '{<script src="//www.avascan.com/a.js">}'
        response.headers['Content-Type'] = "application/json"
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative text/plain
        response.text = 'error="<script src="//www.avascan.com/a.js">"'
        response.headers['Content-Type'] = "text/plain"
        test = check.check(response, check._payloads[0])
        assert not test


class TestCrossSiteScriptingScriptCheck:
    payloads = [
        "'+avascan()+'",
        "';avascan();//'",
        '"+avascan()+"',
        '";avascan();//"',
        'avascan()',
        "'+avascan``+'",
        '"+avascan``+"',
        "';avascan``;//'",
        '";avascan``;//"'
    ]

    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="avascan")
        return CrossSiteScriptingScriptCheck()

    def test_init(self, check):
        # init
        assert check._payloads == self.payloads

    def test_check_true_positive(self, check, response):
        response.headers = {'Content-Type': ''}

        # true positive single quotes concatenate
        response.text = "<html><head></head><body><script>var s = 'test'+avascan()+'';</script></body></html>"
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[0])
        assert test

        # true positive double quotes concatenate
        response.text = '<html><head></head><body><script>var s = "test"+avascan()+"";</script></body></html>'
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[2])
        assert test

        # true positive single quotes statement
        response.text = "<html><head></head><body><script>var s = 'test';avascan();//'';</script></body></html>"
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[1])
        assert test

        # true positive double quotes statement
        response.text = '<html><head></head><body><script>var s = "test";avascan();//"";</script></body></html>'
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[3])
        assert test

        # true positive no quotes
        response.text = "<html><head></head><body><script>var s = avascan();</script></body></html>"
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[4])
        assert test

    def test_check_true_negative(self, check, response):
        response.headers = {'Content-Type': ''}

        # true negative empty
        response.text = ""
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative html
        response.text = "<html><head></head><body><script>var s = 'test';</script></body></html>"
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative different quotes
        response.text = "<html><head></head><body><script>var s = \"test'+avascan()+'\";</script></body></html>"
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative escaped
        response.text = "<html><head></head><body><script>var s = 'test\\'+avascan()+\\'';</script></body></html>"
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative application/json
        response.text = "{<script>var s = 'test'+avascan()+'';</script>}"
        response.headers['Content-Type'] = "application/json"
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative text/plain
        response.text = "error=\"<script>var s = 'test'+avascan()+'';</script>\""
        response.headers['Content-Type'] = "text/plain"
        test = check.check(response, check._payloads[0])
        assert not test


class TestCrossSiteScriptingEventCheck(TestCrossSiteScriptingScriptCheck):
    @pytest.fixture
    def check(self, mocker):
        mocker.patch("ava.common.utility.generate_random", return_value="avascan")
        return CrossSiteScriptingEventCheck()

    def test_check_true_positive(self, check, response):
        response.headers = {'Content-Type': ''}

        # true positive single quotes concatenate
        response.text = """<html><head></head><body><a href="" onclick="window.location='test'+avascan()+'';">Link</a>
        </body></html>"""
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[0])
        assert test

        # true positive double quotes concatenate
        response.text = """<html><head></head><body><a href='' onclick='window.location="test"+avascan()+"";'>Link</a>
        </body></html>"""
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[2])
        assert test

        # true positive single quotes statement
        response.text = """<html><head></head><body><a href="" onclick="window.location='test';avascan();//'';">Link</a>
        </body></html>"""
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[1])
        assert test

        # true positive double quotes statement
        response.text = """<html><head></head><body><a href='' onclick='window.location="test";avascan();//"";'>Link</a>
        </body></html>"""
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[3])
        assert test

        # true positive no quotes
        response.text = """<html><head></head><body><a href="" onclick="window.location = avascan();">Link</a>
        </body></html>"""
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[4])
        assert test

    def test_check_true_negative(self, check, response):
        response.headers = {'Content-Type': ''}

        # true negative empty
        response.text = ""
        response.headers['Content-Type'] = "text/html"
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative html
        response.text = """<html><head></head><body><a href="" onclick="window.location='test';">Link</a>
        </body></html>"""
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative different quotes
        response.text = """<html><head></head><body><a href='' onclick='window.location="test'+avascan()+'";'>
        Link</a></body></html>"""
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative escaped
        response.text = """<html><head></head><body><a href="" onclick="window.location='test\\'+avascan()+\\'';">
        Link</a></body></html>"""
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative application/json
        response.text = "{<a href=\"\" onclick=\"window.location='test'+avascan()+'';\">}"
        response.headers['Content-Type'] = "application/json"
        test = check.check(response, check._payloads[0])
        assert not test

        # true negative text/plain
        response.text = "error=\"{<a href=\"\" onclick=\"window.location='test'+avascan()+'';\">\""
        response.headers['Content-Type'] = "text/plain"
        test = check.check(response, check._payloads[0])
        assert not test
