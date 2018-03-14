import json
import logging
from ava.common.exception import MissingComponentException


# configure logging
logger = logging.getLogger(__name__)


class JsonReporter:
    """
    Reports issues in JSON format to a given file. This is used to save results at the end of a scan.
    """
    def __init__(self, results, configs, auditors, checks, vectors):
        """Sets the reporter's collection of results, configs, vectors, checks, and auditors"""
        self._results = results
        self._configs = configs
        self._auditors = auditors
        self._checks = checks
        self._vectors = vectors

    def report(self, filename, start_time, end_time):
        """
        Saves results to a given file in JSON format.
        :param filename: file name
        :param start_time: start datetime
        :param end_time: end datetime
        """
        # calculate times
        times = {'start': str(start_time), 'end': str(end_time), 'duration': str(end_time - start_time)}

        # list auditors
        auditors = [{'key': a.key, 'name': a.name, 'description': a.description} for a in self._auditors]

        # list checks
        checks = [{'key': c.key, 'name': c.name, 'description': c.description} for c in self._checks]

        # generate output
        output = {
            'times': times,
            'configs': self._configs,
            'auditors': auditors,
            'checks': checks,
            'vectors': self._vectors,
            'results': self._results
        }

        try:
            # dump to file
            with open(filename, 'w') as f:
                json.dump({"report": output}, f, indent=1)
        except OSError as e:
            raise MissingComponentException("{} '{}'".format(e.strerror, e.filename))
