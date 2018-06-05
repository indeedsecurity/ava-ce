import logging
import os
import socket
import re
from copy import copy
from urllib.parse import urlparse
from ava.common.exception import InvalidValueException, UnknownKeyException

# configure logging
logger = logging.getLogger(__name__)

# default config values
defaults = {
    'auditors': [],
    'actives': [],
    'blinds': {},
    'passives': [],
    'report': "",
    'cookies': {},
    'headers': {},
    'parameters': {},
    'excludes': [],
    'skips': [],
    'ignores': [],
    'domain': "",
    'agent': "",
    'timeout': 30,
    'proxy': "",
    'processes': 4,
    'threads': 4,
    'value': "",
    'url': "",
    'follow': False,
    'reduce': False,
    'summary': False
}


def _check_modules(package, modules):
    """
    Splits module string and checks each module exists in the given package. InvalidValueException is raised,
    if a module does not exist.
    :param package: package name
    :param modules: list of modules
    :return: list of modules
    """
    # get package contents
    home = os.path.realpath(os.path.join(__file__, '..', '..', '..'))
    contents = os.listdir(os.path.join(home, "ava", package))

    # filter by modules
    contents = [name for name in contents if name.endswith(".py") and name != "__init__.py"]

    # verify each module exists
    for mod in modules:
        if mod + ".py" not in contents:
            raise InvalidValueException("Module '{}' not found".format(package + '.' + mod))

    return modules


def _check_url(url):
    """
    Checks the URL is in scheme://hostname/path format. InvalidValidException is raised, if scheme or
    network_location are missing. Default path of '/' is added, if path is missing.
    :param url: url string
    :return: url string
    """
    # extract parts
    parsed = urlparse(url)

    # check format
    if not parsed.scheme or not parsed.netloc:
        raise InvalidValueException("URL must be in the form 'scheme://hostname/path'")

    # check path
    if not parsed.path:
        url += '/'

    return url


def _check_modules_and_urls(package, configs):
    """
    Checks configurations for a list of modules and Urls. Configurations are specified as a string of key-value pairs.
    Modules are verified to exist, and URLs are verified to have schemes and hostnames. InvalidValueException is raised,
    if a module does not exist or a URL is not formatted.
    :param package: package name
    :param configs: dictionary of module configurations
    :return: configurations dictionary
    """
    # check modules and urls
    for name, url in configs.items():
        configs[name] = _check_url(url)
        _check_modules(package, [name])

    return configs


def _check_dict(values):
    """
    Checks if dictionary's value is set to None and replaces it with an empty string. None values cannot be appended to
    in auditors.
    :param values: dictionary of key-values
    :return: configurations dictionary
    """
    # check if value is None
    for key in values:
        if values[key] is None:
            values[key] = str()

    return values


def _check_int(name, value):
    """
    Checks the value is greater than one. InvalidValueException is raised, if it is not.
    :param name: configuration name
    :param value: value as integer
    :return: integer value
    """
    # check value
    if value < 1:
        raise InvalidValueException("Configuration '{}' must be greater than 0".format(name))

    return value


def _check_proxy(proxy):
    """
    Checks the proxy is in ip:port format and the IP and port are valid. InvalidValueException is raised, if wrong
    format or IP/port are not valid.
    :param proxy: proxy string
    :return: proxy string
    """
    # extract parts
    url = proxy if proxy.startswith("http") else "http://" + proxy
    parsed = urlparse(url)

    # check ip
    try:
        ip = parsed.hostname
        socket.inet_aton(ip)
    except socket.error:
        raise InvalidValueException("Proxy IP must be valid")

    # check port
    try:
        port = parsed.port
    except ValueError:
        raise InvalidValueException("Proxy port must be an integer")

    # check format
    if not ip or not port:
        raise InvalidValueException("Proxy must be in the form 'ip:port'")

    return proxy

def _check_alternative_url(alternative):
    """
    Checks the url is in {http|https}://hostname[:port] format or hostname[:port]. InvalidValueException is raised, if it is not
    :param url: url string
    :return: url string
    """
    # extract parts
    url = alternative if alternative.startswith("http") else "http://" + alternative
    parsed = urlparse(url)

    # check port
    try:
        parsed.port
    except ValueError:
        raise InvalidValueException("URL port must be an integer")

    # check hostname exists and path doesn't exists
    if not parsed.hostname or parsed.path:
        raise InvalidValueException("URL must be in {http|https}://hostname[:port] format or hostname[:port]")

    return alternative


def generate(sys_args, yaml_args):
    """
    Generates AVA configs based on defaults, command-line arguments, and ini configurations. Order of precedence:
    command-line arguments, yaml configurations, and defaults. Defaults are copied over, then user configurations are
    created from yaml configurations and command-line arguments.  Defaults then are overridden from user configurations.
    :param sys_args: dictionary of command-line arguments
    :param yaml_args: dictionary of yaml configurations
    :return: AVA configs as dictionary
    """
    # copy defaults
    configs = copy(defaults)

    # copy yaml
    users = copy(yaml_args)

    # replace yaml with args
    for key in sys_args:
        # skip empty args
        if sys_args[key]:
            users[key] = sys_args[key]

    # replace defaults with users
    for key, values in users.items():
        # skip empty args
        if not values:
            continue

        # modules
        if key in ['auditors', 'actives', 'passives']:
            configs[key] = _check_modules(key, values)
        # modules and urls
        elif key == 'blinds':
            configs[key] = _check_modules_and_urls(key, values)
        # dictionaries
        elif key in ['cookies', 'headers', 'parameters']:
            configs[key] = _check_dict(values)
        # lists
        elif key in ['excludes', 'skips', 'ignores']:
            configs[key] = values
        # strings
        elif key in ['report', 'domain', 'agent', 'value']:
            configs[key] = values
        # integers
        elif key in ['timeout', 'processes', 'threads']:
            configs[key] = _check_int(key, values)
        # booleans
        elif key in ['follow', 'reduce', 'summary']:
            configs[key] = values
        # proxy
        elif key == 'proxy':
            configs[key] = _check_proxy(values)
        # url
        elif key == 'url':
            configs[key] = _check_alternative_url(values)
        # hars
        elif key == 'hars':
            configs[key] = values
        # ignore
        elif key in ['config', 'quiet', 'debug']:
            pass
        # unknown
        else:
            raise UnknownKeyException("'{}' is not a valid configuration".format(key))

    return configs
