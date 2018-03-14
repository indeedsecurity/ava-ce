import pytest
import json
from ava.common.exception import InvalidFormatException
from ava.parsers.json import JsonObject


class TestJsonObject:
    @pytest.fixture
    def jsons(self):
        jsons = [
            '"text"',
            '{"test": "token", "ava": "avascan"}',
            '["test", 1, 2, "token"]',
            '[{"test": "token"}, {"ava": "avascan"}, {"count": 3}]',
            '{"list": [{"test": "token"}, [true, false], {"ava": "avascan"}, ["text", null, 6]]}',
        ]

        return jsons

    def test_init(self, jsons):
        # string
        test = JsonObject(jsons[0])
        assert test._literals == {'0': "text"}

        # object
        test = JsonObject(jsons[1])
        assert test._literals == {'test': "token", 'ava': "avascan"}

        # list
        test = JsonObject(jsons[2])
        assert test._literals == {'0': "test", '1': 1, '2': 2, '3': "token"}

        # list with objects
        test = JsonObject(jsons[3])
        assert test._literals == {'0.test': "token", '1.ava': "avascan", '2.count': 3}

        # object with lists
        test = JsonObject(jsons[4])
        assert test._literals == {'list.0.test': "token", 'list.1.0': True, 'list.1.1': False, 'list.2.ava': "avascan",
                                  'list.3.0': "text", 'list.3.1': None, 'list.3.2': 6}

    def test_parse_json_positive(self, jsons):
        # object
        parsed = JsonObject(jsons[1])
        test = parsed._parse_json(jsons[1])
        assert test == {'test': "token", 'ava': "avascan"}

        # list
        parsed = JsonObject(jsons[2])
        test = parsed._parse_json(jsons[2])
        assert test == ["test", 1, 2, "token"]

    def test_parse_json_negative(self):
        # invalid json
        with pytest.raises(InvalidFormatException):
            JsonObject('{"test": "token"')

    def test_replace_at_list(self, jsons):
        parsed = JsonObject(jsons[3])

        # list with objects
        test = parsed._replace_at('0.test', "replaced")
        assert test == [{'test': "replaced"}, {'ava': "avascan"}, {'count': 3}]

        test = parsed._replace_at('1.ava', "replaced")
        assert test == [{'test': "token"}, {'ava': "replaced"}, {'count': 3}]

        test = parsed._replace_at('2.count', "replaced")
        assert test == [{'test': "token"}, {'ava': "avascan"}, {'count': "replaced"}]

    def test_replace_at_object(self, jsons):
        parsed = JsonObject(jsons[4])

        # object with lists
        test = parsed._replace_at('list.0.test', "replaced")
        assert test == {'list': [{'test': "replaced"}, [True, False], {'ava': "avascan"}, ["text", None, 6]]}

        test = parsed._replace_at('list.1.0', "replaced")
        assert test == {'list': [{'test': "token"}, ["replaced", False], {'ava': "avascan"}, ["text", None, 6]]}

        test = parsed._replace_at('list.1.1', "replaced")
        assert test == {'list': [{'test': "token"}, [True, "replaced"], {'ava': "avascan"}, ["text", None, 6]]}

        test = parsed._replace_at('list.2.ava', "replaced")
        assert test == {'list': [{'test': "token"}, [True, False], {'ava': "replaced"}, ["text", None, 6]]}

        test = parsed._replace_at('list.3.0', "replaced")
        assert test == {'list': [{'test': "token"}, [True, False], {'ava': "avascan"}, ["replaced", None, 6]]}

        test = parsed._replace_at('list.3.1', "replaced")
        assert test == {'list': [{'test': "token"}, [True, False], {'ava': "avascan"}, ["text", "replaced", 6]]}

        test = parsed._replace_at('list.3.2', "replaced")
        assert test == {'list': [{'test': "token"}, [True, False], {'ava': "avascan"}, ["text", None, "replaced"]]}

    def test_replace_positive(self, jsons):
        # string
        parsed = JsonObject(jsons[0])
        test = parsed.replace('0', "replaced")
        assert test == '"replaced"'

        # object
        parsed = JsonObject(jsons[1])

        test = parsed.replace('test', "replaced")
        assert json.loads(test) == {"test": "replaced", "ava": "avascan"}

        test = parsed.replace('ava', "replaced")
        assert json.loads(test) == {"test": "token", "ava": "replaced"}

        # list
        parsed = JsonObject(jsons[2])

        test = parsed.replace('0', "replaced")
        assert test == '["replaced", 1, 2, "token"]'

        test = parsed.replace('1', "replaced")
        assert test == '["test", "replaced", 2, "token"]'

        test = parsed.replace('2', "replaced")
        assert test == '["test", 1, "replaced", "token"]'

        test = parsed.replace('3', "replaced")
        assert test == '["test", 1, 2, "replaced"]'

    def test_replace_negative(self, jsons):
        # invalid literal
        with pytest.raises(KeyError):
            parsed = JsonObject(jsons[1])
            parsed.replace('invalid', "replaced")

    def test_literals(self, jsons):
        # object
        parsed = JsonObject(jsons[1])
        test = parsed.literals()
        assert test == parsed._literals

        # list
        parsed = JsonObject(jsons[2])
        test = parsed.literals()
        assert test == parsed._literals
