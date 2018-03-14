import pytest
from ava.readers.argument import ArgumentReader, _ArgumentHelpFormatter


class TestArgumentHelpFormatter:

    def test_format_action_invocation(self, mocker):
        action = type("Action", (object,), {'dest': "", 'option_strings': [], 'nargs': 0})()
        formatter = _ArgumentHelpFormatter('ava')

        # positional argument
        action.dest = "hars"
        test = formatter._format_action_invocation(action)
        assert test == "hars"

        # long optional argument
        action.option_strings = ["--long"]
        test = formatter._format_action_invocation(action)
        assert test == "--long"

        # short and long optional argument
        action.dest = "long"
        action.option_strings = ["-l", "--long"]
        action.nargs = 1
        test = formatter._format_action_invocation(action)
        assert test == "-l, --long LONG"


class TestArgumentReader:
    @pytest.fixture
    def reader(self):
        return ArgumentReader([])

    def test_csv_with_values(self, reader):
        # one value
        test = reader.csv("one")
        assert test == ["one"]

        # multiple values
        test = reader.csv("one, two, three")
        assert test == ["one", "two", "three"]

    def test_csv_with_none(self, reader):
        # only empty
        test = reader.csv(",")
        assert test == []

        # values and empty
        test = reader.csv("one,,two")
        assert test == ["one", "two"]

    def test_dict_positive(self, reader):
        # with value
        test = reader.dict("key=value")
        assert test == ["key", "value"]

        # value with equals sign
        test = reader.dict("key=token==")
        assert test == ["key", "token=="]

        # without value
        test = reader.dict("key=")
        assert test == ["key", ""]

    def test_dict_negative(self, reader):
        # without value
        with pytest.raises(ValueError):
            reader.dict("key_value")

    def test_parse(self):
        # vector file
        reader = ArgumentReader(["test.har", "dump.har"])
        test = reader.parse()
        assert test['hars'] == ["test.har", "dump.har"]

        # actives
        reader = ArgumentReader(['-e', "xss, open_redirect"])
        test = reader.parse()
        assert sorted(test['actives']) == ["open_redirect", "xss"]

        # auditors
        reader = ArgumentReader(['-a', "parameters, cookies"])
        test = reader.parse()
        assert sorted(test['auditors']) == ["cookies", "parameters"]

        # cookies
        reader = ArgumentReader(['--cookies', "session=value", '--cookies', "token=value"])
        test = reader.parse()
        assert test['cookies'] == {'session': "value", 'token': "value"}

        # skips
        reader = ArgumentReader(['-s', "session", '-s', "token"])
        test = reader.parse()
        assert sorted(test['skips']) == ["session", "token"]

        # proxy
        reader = ArgumentReader(['-p', "127.0.0.1:8080"])
        test = reader.parse()
        assert test['proxy'] == "127.0.0.1:8080"

        # follow
        reader = ArgumentReader(['-f'])
        test = reader.parse()
        assert test['follow']

        # reduce
        reader = ArgumentReader(['-r'])
        test = reader.parse()
        assert test['reduce']

        # summary
        reader = ArgumentReader(['--summary'])
        test = reader.parse()
        assert test['summary']
