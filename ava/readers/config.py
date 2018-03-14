import logging
import yaml
from ava.common import config
from yaml.parser import ParserError
from yaml.scanner import ScannerError
from ava.common.exception import InvalidFormatException, UnknownKeyException


# configure logging
logger = logging.getLogger(__name__)


class YamlReader:

    def __init__(self, source):
        """Sets the reader's data source"""
        self._source = source
        self._schema = {key: type(value) for key, value in config.defaults.items()}

    def parse(self):
        """
        Parses YAML configuration file and creates configs in the same format as default configs. Default configs
        is checked to verify data types. None values are filtered from lists to prevent evaluating to True later.
        :return: dictionary of configs
        """
        try:
            # read yaml
            with open(self._source) as f:
                configs = yaml.safe_load(f)
        except (ParserError, ScannerError) as e:
            raise InvalidFormatException("{} on line {}".format(e.problem.capitalize(), e.problem_mark.line))

        # check configs
        if not configs:
            logger.debug("Configuration file '%s' is empty. Ignoring.", self._source)
            return {}

        for key, values in configs.items():
            # check key
            if key not in self._schema:
                raise UnknownKeyException("'{}' is not a valid configuration".format(key))

            # check values
            if values is None:
                continue

            # check type
            if not isinstance(values, self._schema[key]):
                raise InvalidFormatException("'{}' must be a {}".format(key, self._schema[key].__name__))

            # filter none from lists
            if isinstance(values, list):
                configs[key] = list(filter(None, values))

        return configs
