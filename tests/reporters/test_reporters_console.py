import pytest
from ava.reporters.console import TableReporter
from ava.auditors.parameter import QueryParameterAuditor
from ava.actives.xss import CrossSiteScriptingCheck


@pytest.fixture
def results():
    # xss
    vector = {
        'url': "http://www.example.com/xss",
        'method': "get",
        'params': {'param': "avascan"},
        'cookies': {},
        'headers': {}
    }

    issue = {
        'auditor': "parameter.query",
        'check': "xss.value.tag",
        'vector': vector,
        'target': "param",
        'value': "<avascan></avascan>",
        'time': "00:00:00.1",
        'http': "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n200 OK\r\n\r\n"
    }

    return [issue]


class TestTableReporter:

    def test_convert_results(self, results):
        generated = [QueryParameterAuditor.name, CrossSiteScriptingCheck.name, "http://www.example.com/xss",
                     "param", "<avascan></avascan>"]

        # with results
        reporter = TableReporter(results, [QueryParameterAuditor], [CrossSiteScriptingCheck])
        test = reporter._convert_results(results)
        assert test == [generated]

        # without results
        reporter = TableReporter([], [QueryParameterAuditor], [CrossSiteScriptingCheck])
        test = reporter._convert_results([])
        assert test == []

    def test_calculate_widths(self, results):
        generated = [QueryParameterAuditor.name, CrossSiteScriptingCheck.name, "http://www.example.com/xss",
                     "param", "<avascan></avascan>"]
        pad = TableReporter._padding

        # with results
        widths = [len(generated[0]) + pad, len(generated[1]) + pad, len(generated[2]) + pad,
                  len(TableReporter._headers[3]) + pad, len(generated[4]) + pad]
        reporter = TableReporter(results, [QueryParameterAuditor], [CrossSiteScriptingCheck])
        test = reporter._calculate_widths()
        assert test == widths

        # without results
        widths = [len(TableReporter._headers[0]) + pad, len(TableReporter._headers[1]) + pad,
                  len(TableReporter._headers[2]) + pad, len(TableReporter._headers[3]) + pad,
                  len(TableReporter._headers[4]) + pad]
        reporter = TableReporter([], [QueryParameterAuditor], [CrossSiteScriptingCheck])
        test = reporter._calculate_widths()
        assert test == widths

    def test_print_separator(self, capsys):
        reporter = TableReporter([], [QueryParameterAuditor], [CrossSiteScriptingCheck])

        # print
        reporter._print_separator()
        captured = capsys.readouterr()
        assert captured.out == "+---------+-------+-----+--------+-------+\n"

    def test_print_row(self, capsys):
        reporter = TableReporter([], [QueryParameterAuditor], [CrossSiteScriptingCheck])

        # print
        reporter._print_row(reporter._headers)
        captured = capsys.readouterr()
        assert captured.out == "| Auditor | Check | URL | Target | Value |\n"

    def test_report(self, results, capsys):
        reporter = TableReporter(results, [QueryParameterAuditor], [CrossSiteScriptingCheck])
        generated = (
            "+------------------+----------------------+----------------------------+--------+---------------------+\n"
            "|     Auditor      |        Check         |            URL             | Target |        Value        |\n"
            "+------------------+----------------------+----------------------------+--------+---------------------+\n"
            "| Query Parameters | Cross-Site Scripting | http://www.example.com/xss | param  | <avascan></avascan> |\n"
            "+------------------+----------------------+----------------------------+--------+---------------------+\n"
        )

        # report
        reporter.report()
        captured = capsys.readouterr()
        assert captured.out == generated
