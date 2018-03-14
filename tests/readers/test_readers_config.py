import pytest
from ava.common.exception import InvalidFormatException, UnknownKeyException
from ava.readers.config import YamlReader


class TestConfigReader:

    @pytest.fixture
    def reader(self):
        return YamlReader("test.yml")

    def test_config_parse_positive(self, reader, mocker):
        # auditors
        mocker.patch("builtins.open", mocker.mock_open(read_data='auditors: \n - parameters\n - cookies'))
        test = reader.parse()
        assert test == {'auditors': ["parameters", "cookies"]}

        # actives
        mocker.patch("builtins.open", mocker.mock_open(read_data='actives: \n - xss\n - open_redirect'))
        test = reader.parse()
        assert test == {'actives': ["xss", "open_redirect"]}

        # cookies
        mocker.patch("builtins.open", mocker.mock_open(read_data='cookies: \n ava: avascan'))
        test = reader.parse()
        assert test == {'cookies': {'ava': "avascan"}}

        # parameters
        mocker.patch("builtins.open", mocker.mock_open(read_data='parameters: \n ava: avascan'))
        test = reader.parse()
        assert test == {'parameters': {'ava': "avascan"}}

        # agent
        mocker.patch("builtins.open", mocker.mock_open(read_data='agent: "Mozilla/5.0"'))
        test = reader.parse()
        assert test == {'agent': "Mozilla/5.0"}

        # domain
        mocker.patch("builtins.open", mocker.mock_open(read_data='domain: "www.example.com"'))
        test = reader.parse()
        assert test == {'domain': "www.example.com"}

        # excludes
        mocker.patch("builtins.open", mocker.mock_open(read_data='excludes: \n - test\n - token'))
        test = reader.parse()
        assert test == {'excludes': ["test", "token"]}

        # skips
        mocker.patch("builtins.open", mocker.mock_open(read_data='skips: \n - test\n - token'))
        test = reader.parse()
        assert test == {'skips': ["test", "token"]}

        # processes
        mocker.patch("builtins.open", mocker.mock_open(read_data='processes: 2'))
        test = reader.parse()
        assert test == {'processes': 2}

        # report
        mocker.patch("builtins.open", mocker.mock_open(read_data='report: "report.json"'))
        test = reader.parse()
        assert test == {'report': "report.json"}

    def test_config_parse_negative(self, reader, mocker):
        # None value in dictionary
        mocker.patch("builtins.open", mocker.mock_open(read_data='value:'))
        test = reader.parse()
        assert test == {'value': None}

        # None value in lists
        mocker.patch("builtins.open", mocker.mock_open(read_data='auditors: \n - '))
        test = reader.parse()
        assert test == {'auditors': []}

        # empty yaml
        mocker.patch("builtins.open", mocker.mock_open(read_data=''))
        test = reader.parse()
        assert test == {}

        # invalid format yaml scanner error
        with pytest.raises(InvalidFormatException):
            mocker.patch("builtins.open", mocker.mock_open(read_data='auditors: \n -parameters'))
            reader.parse()

        # invalid format yaml parser error
        with pytest.raises(InvalidFormatException):
            mocker.patch("builtins.open", mocker.mock_open(read_data='auditors: \n : parameters, cookies'))
            reader.parse()

        # unknown key
        with pytest.raises(UnknownKeyException):
            mocker.patch("builtins.open", mocker.mock_open(read_data='params: \n ava: avascan'))
            reader.parse()

        # invalid format schema
        with pytest.raises(InvalidFormatException):
            mocker.patch("builtins.open", mocker.mock_open(read_data='parameters: \n - ava=avascan'))
            reader.parse()
