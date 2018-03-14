import pytest
import base64
import json
from datetime import datetime
from ava.actives.xss import CrossSiteScriptingCheck
from ava.auditors.parameter import QueryParameterAuditor
from ava.common.exception import MissingComponentException
from ava.reporters.file import JsonReporter


@pytest.fixture
def vector():
    vector = {
        'url': "http://www.example.com/",
        'method': "GET",
        'params': {'ava': "avascan"},
        'cookies': {},
        'headers': {}
    }

    return vector


@pytest.fixture
def issue(vector):
    issue = {
            'auditor': QueryParameterAuditor.key,
            'check': CrossSiteScriptingCheck.key,
            'vector': vector,
            'target': "param",
            'value': "<script></script>",
            'time': "00:00:00.1",
            'http': base64.b64encode("<html><script></script></html>".encode()).decode()
        }

    return issue


class TestJsonReporter:

    def test_report(self, issue, vector, mocker, tmpdir):
        configs = {'auditors': ["parameter"], 'actives': ["xss"], 'report': "report.json", 'domain': "www.example.com"}
        auditor = QueryParameterAuditor({}, [], [])
        check = CrossSiteScriptingCheck()
        start = datetime.strptime("12:00:00", "%H:%M:%S")
        end = datetime.strptime("12:10:00", "%H:%M:%S")

        # generated
        generated = {
            "report": {
                'times': {'start': str(start), 'end': str(end), 'duration': "0:10:00"},
                'configs': configs,
                'auditors': [{'key': auditor.key, 'name': auditor.name, 'description': auditor.description}],
                'checks': [{'key': check.key, 'name': check.name, 'description': check.description}],
                'vectors': [vector],
                'results': [issue]
            }
        }

        # temporary file and reporter
        output = tmpdir.join("report.json")
        reporter = JsonReporter([issue], configs, [auditor], [check], [vector])

        # report
        reporter.report(output.strpath, start, end)
        assert json.loads(output.read()) == generated

        # exception
        with pytest.raises(MissingComponentException):
            mocker.patch("builtins.open", side_effect=OSError)
            reporter.report(output.strpath, start, end)
