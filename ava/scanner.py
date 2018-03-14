import json
import logging
import os
import sys
import time
from copy import copy
from datetime import datetime, timezone
from ava.common import config
from ava.common import utility
from ava.common.exception import InvalidValueException, UnknownKeyException, InvalidFormatException
from ava.common.exception import MissingComponentException
from ava.readers.argument import ArgumentReader
from ava.readers.config import YamlReader
from ava.readers.vector import HarReader
from ava.reporters.console import TableReporter
from ava.reporters.file import JsonReporter


# configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s : %(levelname)s : %(message)s", datefmt="%Y-%m-%d %H:%M:%SZ")
logging.Formatter.converter = time.gmtime
logger = logging.getLogger(__name__)


def info():
    """
    Gathers and returns information about AVA, including available auditors/checks and default configurations. Intended
    for use by scripts that dynamically call AVA.
    :return: dictionary of configs in config.defaults format
    """
    packages = ['auditors', 'actives', 'blinds', 'passives']

    # get defaults
    defaults = copy(config.defaults)

    # merge auditors and checks
    for package in packages:
        modules = utility.get_package_info(package)
        defaults[package] = modules

    return defaults


def _print_modules():
    """
    Prints available module names and descriptions. Uses _get_module_info() to get names and descriptions.
    """
    packages = ['auditors', 'actives', 'blinds', 'passives']

    # print names and descriptions
    for package in packages:
        print(package + ':')
        for name, description in utility.get_package_info(package):
            print("  {:21s} {}".format(name, description))

        if package != packages[-1]:
            print('')


def _check_vectors(vectors):
    """
    Checks vector files are present and files exist. MissingComponentException is thrown if a file does not exist.
    :param vectors: list of vector files
    """
    # check vectors
    if not vectors:
        raise MissingComponentException("Vector files are required")

    # check each exists
    for name in vectors:
        if not os.path.isfile(name):
            raise MissingComponentException("Vector file '{}' not found".format(name))


def _parse_yaml(config_file):
    """
    Checks the file exists and reads YAML configs. MissingComponentException is thrown if file does not exist.
    :param config_file: file name
    :return: ini args
    """
    # check file exists
    if not os.path.isfile(config_file):
        raise MissingComponentException("Configuration file '{}' not found".format(config_file))

    # read ini configs
    logger.info("Loading configs.")
    reader = YamlReader(config_file)
    yaml_args = reader.parse()

    return yaml_args


def _set_logging(sys_args):
    """
    Sets the logging level based on system arguments. Debug flag overrides quiet flag.
    :param sys_args: system args dictionary
    """
    if sys_args['debug']:
        logger.info("Increasing output level. Debugging.")
        logging.getLogger().setLevel(logging.DEBUG)
    elif sys_args['quiet']:
        logger.info("Decreasing output level. Quieting.")
        logging.getLogger().setLevel(logging.WARNING)


def _reduce_vectors(vectors):
    """
    Reduces duplicate vectors by comparing fingerprints. A hashable string of the fingerprint is used as the
    comparison key.
    :param vectors: vectors list
    :return: reduced vectors list
    """
    cache = {}

    for vector in vectors:
        # fingerprint
        fingerprint = utility.fingerprint_vector(vector)
        key = json.dumps(fingerprint, sort_keys=True)

        # check cache
        if key not in cache:
            cache[key] = vector

    # reduced
    return list(cache.values())


def _load_checks(configs):
    """
    Loads and instantiates active, blind, and/or passive checks. Blind checks are loaded with their listener configs.
    :param configs: AVA configs
    :return: checks as list
    """
    checks = []

    # active checks
    if configs['actives']:
        logger.debug("Loading active checks.")
        actives = utility.get_package_classes('actives', configs['actives'])
        checks += [clazz() for clazz in actives]

    # blind checks
    if configs['blinds']:
        logger.debug("Loading blind checks.")
        listeners = configs['blinds']
        blinds = utility.get_package_classes('blinds', list(listeners))
        checks += [clazz(listeners[clazz.__module__.split('.')[-1]]) for clazz in blinds]

    # passive checks
    if configs['passives']:
        logger.debug("Loading passive checks.")
        passives = utility.get_package_classes('passives', configs['passives'])
        checks += [clazz() for clazz in passives]

    return checks


def _run_scanner(configs):
    """
    Loads vectors, checks, and auditors. Then runs audits and prints results. Results can be saved to a report.
    :param configs: AVA configs
    """
    results = []

    # read vectors
    logger.info("Loading vectors.")
    reader = HarReader(configs['hars'])
    vectors = reader.parse(configs)

    # reduce duplicates
    if configs['reduce']:
        logger.debug("Reducing vectors.")
        vectors = _reduce_vectors(vectors)

    # check vectors
    if not vectors:
        raise MissingComponentException("Vector list is empty")

    # load and instantiate checks
    logger.info("Loading scanner.")
    checks = _load_checks(configs)

    # if no checks, default to active checks
    if not checks:
        logger.debug("No checks loaded. Loading all active checks.")
        actives = utility.get_package_classes('actives')
        checks += [clazz() for clazz in actives]

    # load and instantiate auditors
    logger.debug("Loading auditors.")
    auditors = utility.get_package_classes('auditors', configs['auditors'])
    auditors = [auditor(configs, checks, vectors) for auditor in auditors]

    # start time
    start_time = datetime.now(timezone.utc)

    # run checks
    logger.debug("Running auditors and checks.")
    for auditor in auditors:
        issues = auditor.run()
        results.extend(issues)

    # end time
    end_time = datetime.now(timezone.utc)

    # print metrics
    elapsed = str(end_time - start_time).partition('.')[0]
    logger.info("Found %d %s in %s.", len(results), 'issue' if len(results) == 1 else 'issues', elapsed)

    # save report
    if configs['report']:
        logger.info("Saving report.")
        reporter = JsonReporter(results, configs, auditors, checks, vectors)
        reporter.report(configs['report'], start_time, end_time)

    # print summary
    if configs['summary']:
        print('')
        reporter = TableReporter(results, auditors, checks)
        reporter.report()


def main(args):
    """
    Gets configurations from command line and AVA configuration file. Optionally, prints available modules and
    sets logging level. Auditors and checks are comma-separated strings. Cookies, headers, and parameters are lists
    of key/value delimited strings. Entry point for other scripts.
    :param args: list of system arguments
    :return: integer for success or failure
    """
    # get system args
    reader = ArgumentReader(args)
    sys_args = reader.parse()

    # list modules
    if sys_args['list']:
        _print_modules()
        return 0

    try:
        # check required vectors argument
        _check_vectors(sys_args['hars'])
    except MissingComponentException as e:
        logger.error("%s. Quitting.", e)
        return 2

    # set logging
    if sys_args['debug'] or sys_args['quiet']:
        _set_logging(sys_args)

    try:
        # parse optional yaml args
        yaml_args = _parse_yaml(sys_args['config']) if sys_args['config'] else {}
    except (MissingComponentException, InvalidFormatException, UnknownKeyException) as e:
        logger.error("%s. Quitting.", e)
        return 2

    try:
        # generate configs from sys and yaml args
        configs = config.generate(sys_args, yaml_args)
    except (InvalidValueException, UnknownKeyException) as e:
        logger.error("%s. Quitting.", e)
        return 2

    try:
        # run scanner
        _run_scanner(configs)
    except (InvalidFormatException, MissingComponentException) as e:
        logger.error("%s. Quitting.", e)
        return 2

    # exit
    return 0


def console():
    """
    Entry point for setup.py
    :return: return value from main
    """
    # pass system args
    args = sys.argv[1:]
    status = main(args)

    # return
    return status
