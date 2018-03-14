import json
from copy import deepcopy
from json.decoder import JSONDecodeError
from ava.common.exception import InvalidFormatException


class JsonObject:
    """
    Parser to unmarshal JSON objects and replace literals with a given value. Each literal is assigned a key. This key
    can be used to replace an given literal with a payload. A default key of '0' is used for literal only strings.
    """
    def __init__(self, json_string):
        """Parse and collect literals"""
        self._literals = {}
        self._object = self._parse_json(json_string)

        # update literals
        if isinstance(self._object, (dict, list)):
            self._update_literals(self._object)
        else:
            self._literals['0'] = self._object

    def _parse_json(self, json_string):
        """
        Parse JSON string and return object.
        :param json_string: JSON as string
        :return: JSON as object
        """
        # parse
        try:
            loaded = json.loads(json_string)
        except JSONDecodeError:
            raise InvalidFormatException("Unable to parse JSON")

        return loaded

    def _update_literals(self, elements, schema=""):
        """
        Recursively traverse the JSON object and collect literals. Dictionary and lists are traversed recursively for
        literals of string, number, boolean, and null.
        :param elements: element object
        :param schema: literal key schema as string
        """
        # get keys or indices
        keys = elements.keys() if isinstance(elements, dict) else range(len(elements))

        for k in keys:
            # set current
            current = schema + str(k) if schema else str(k)

            # add each string, number, boolean, null
            if isinstance(elements[k], (dict, list)):
                self._update_literals(elements[k], current + '.')
            else:
                self._literals[current] = elements[k]

    def _replace_at(self, literal, value):
        """
        Traverse the JSON object and replace the literal at the given key with the given value.
        :param literal: literal key
        :param value: replacement value
        """
        # copy
        replacement = deepcopy(self._object)

        # split key
        splits = [int(key) if key.isdigit() else key for key in literal.split('.')]

        # traverse object
        reference = replacement
        for key in splits[:-1]:
            reference = reference[key]

        # replace value
        key = splits[-1]
        reference[key] = value

        return replacement

    def replace(self, literal, value):
        """
        Replace the literal at the given key with the given value and return the replaced JSON string. The original
        object is not changed as a deep copy is used in replace_at().
        :param literal: literal key
        :param value: value string
        :return: JSON string
        """
        # check literal
        if literal not in self._literals:
            raise KeyError

        # replace literal
        if isinstance(self._object, (dict, list)):
            replacement = self._replace_at(literal, value)
        else:
            replacement = value

        return json.dumps(replacement)

    def literals(self):
        """
        Return a copy of the JSON literals as key-value pairs. Keys can be used to reference literals when calling
        replace().
        :return: literals as dictionary
        """
        # return copy
        return self._literals.copy()
