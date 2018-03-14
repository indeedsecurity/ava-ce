import pytest
from copy import deepcopy
from ava.common.check import _BlindCheck, _PassiveCheck, _ActiveCheck, _ValueCheck, _DifferentialCheck, _TimingCheck


@pytest.fixture
def responses():
    # first
    first_elapsed = type("Elapsed", (object,), {})
    first_response = type("Response", (object,), {'elapsed': first_elapsed})

    # second
    second_elapsed = type("Elapsed", (object,), {})
    second_response = type("Response", (object,), {'elapsed': second_elapsed})

    return first_response, second_response


class TestBlindCheck:
    payloads = []
    
    @pytest.fixture
    def check(self):
        return _BlindCheck()

    def test_payloads(self, check):
        test = check.payloads("", "", "")
        assert test == []


class TestPassiveCheck:
    
    @pytest.fixture
    def check(self):
        return _PassiveCheck()
    
    def test_check(self, check):
        test = check.check(None)
        assert test is None


class TestActiveCheck:
    payloads = []
    
    @pytest.fixture
    def check(self):
        return _ActiveCheck()

    def test_check(self, check):
        test = check.payloads("", "", "")
        assert test == []


class TestValueCheck:
    
    @pytest.fixture
    def check(self):
        return _ValueCheck()

    def test_check(self, check):
        test = check.check(None, "")
        assert test is None


class TestDifferentialCheck:
    
    @pytest.fixture
    def check(self):
        return _DifferentialCheck()

    def test_check_true_positive(self, check, responses):
        html = "<html><head></head><body>{}</body</html>"
        true_response, false_response = responses
    
        # true positive
        true_body = "name: admin\npassword: admin\n\nname: user\npassword: user"
        true_response.status_code = 200
        true_response.text = html.format(true_body)

        false_body = ""
        false_response.status_code = 200
        false_response.text = html.format(false_body)

        test = check.check({'true': true_response, 'false': false_response}, '')
        assert test
    
    def test_check_true_negative(self, check, responses):
        html = "<html><head></head><body>{}</body</html>"
        true_response, false_response = responses

        # true negative same response
        true_response.status_code = 200
        true_response.text = html.format("Not found")

        test = check.check({'true': true_response, 'false': true_response}, '')
        assert not test
    
        # true negative empty true
        true_response.status_code = 200
        true_response.text = ""
        
        false_response.status_code = 200
        false_response.text = html.format("")
        
        test = check.check({'true': true_response, 'false': false_response}, '')
        assert not test
    
        # true negative empty false
        true_response.status_code = 200
        true_response.text = ""
        
        false_response.status_code = 200
        false_response.text = html.format("")
        
        test = check.check({'true': true_response, 'false': false_response}, '')
        assert not test
    
        # true negative different status codes
        true_response.status_code = 400
        true_response.text = html.format("")

        false_response.status_code = 200
        false_response.text = html.format("")
        
        test = check.check({'true': true_response, 'false': false_response}, '')
        assert not test


class TestTimingCheck:
    
    @pytest.fixture
    def check(self):
        return _TimingCheck()

    def test_check_true_positive(self, check, responses):
        original_response, timing_response = responses
    
        # true positive slower response
        original_response.elapsed.seconds = 0
        original_response.elapsed.microseconds = 987654

        timing_response.elapsed.seconds = 12
        timing_response.elapsed.microseconds = 123456

        test = check.check({'original': original_response, 'timing': timing_response}, '', 9.00)
        assert test
    
        # true positive faster response
        original_response.elapsed.seconds = 0
        original_response.elapsed.microseconds = 987654
        
        timing_response.elapsed.seconds = 9
        timing_response.elapsed.microseconds = 567890

        test = check.check({'original': original_response, 'timing': timing_response}, '', 9.00)
        assert test
    
    def test_check_true_negative(self, check, responses):
        original_response, timing_response = responses

        # true negative fast response
        original_response.elapsed.seconds = 0
        original_response.elapsed.microseconds = 987654
        
        timing_response.elapsed.seconds = 1
        timing_response.elapsed.microseconds = 987654
        
        test = check.check({'original': original_response, 'timing': timing_response}, '', 9.00)
        assert not test
    
        # true negative slow response
        original_response.elapsed.seconds = 7
        original_response.elapsed.microseconds = 987654
        
        timing_response.elapsed.seconds = 10
        timing_response.elapsed.microseconds = 123456

        test = check.check({'original': original_response, 'timing': timing_response}, '', 9.00)
        assert not test
