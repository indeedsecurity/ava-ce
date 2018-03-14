import pytest
import logging
import sys
import ava.scanner
import ava.common.config
import ava.common.utility
from copy import copy
from ava.actives.xss import CrossSiteScriptingCheck
from ava.blinds.xss import CrossSiteScriptingBlindCheck
from ava.passives.pii import PersonallyIdentifiableInformationCheck
from ava.common.exception import InvalidValueException, UnknownKeyException, InvalidFormatException
from ava.common.exception import MissingComponentException


def test_info(mocker):
    package_info = [("name", "description")]
    generated = copy(ava.common.config.defaults)

    # test
    generated['auditors'] = package_info
    generated['actives'] = package_info
    generated['blinds'] = package_info
    generated['passives'] = package_info
    mocker.patch("ava.common.utility.get_package_info", return_value=package_info)
    test = ava.scanner.info()
    assert test == generated


def test_check_vectors_positive(mocker):
    mocker.patch("os.path.isfile", return_value=True)

    # single file
    vectors = ["file1.har"]
    test = ava.scanner._check_vectors(vectors)
    assert not test

    # multiple files
    vectors = ["file1.har", "file2.har", "file3.har"]
    test = ava.scanner._check_vectors(vectors)
    assert not test


def test_check_vectors_negative(mocker):
    mocker.patch("os.path.isfile", return_value=False)

    # missing vectors
    with pytest.raises(MissingComponentException):
        ava.scanner._check_vectors([])

    # file not found
    with pytest.raises(MissingComponentException):
        ava.scanner._check_vectors(["file1.har"])


def test_parse_ini_positive(mocker):
    # with ini
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.readers.config.YamlReader.parse", return_value={'actives': "xss"})
    test = ava.scanner._parse_yaml('config.ini')
    assert test == {'actives': "xss"}

    # without ini
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.readers.config.YamlReader.parse", return_value={})
    test = ava.scanner._parse_yaml('config.ini')
    assert test == {}


def test_parse_ini_negative(mocker):
    # raise missing component
    with pytest.raises(MissingComponentException):
        mocker.patch("os.path.isfile", return_value=False)
        ava.scanner._parse_yaml('config.ini')


def test_set_logging():
    # quiet
    args = {'quiet': "test.json", 'debug': None}
    ava.scanner._set_logging(args)
    assert logging.getLogger().getEffectiveLevel() == logging.WARNING

    # debug
    args = {'quiet': None, 'debug': "test.json"}
    ava.scanner._set_logging(args)
    assert logging.getLogger().getEffectiveLevel() == logging.DEBUG


def test_reduce_vectors():
    vectors = [
        {
            'url': "https://www.example.com/one", 'method': "GET", 'headers': {'User-Agent': "Mozilla/5.0"},
            'cookies': {"session": "identifier"}, 'params': {'ava': "avascan"}, 'data': {}
        },
        {
            'url': "https://www.example.com/two", 'method': "GET", 'headers': {'User-Agent': "Mozilla/5.0"},
            'cookies': {"session": "identifier"}, 'params': {'ava': "avascan"}, 'data': {}
        },
        {
            'url': "https://www.example.com/one", 'method': "POST", 'headers': {'User-Agent': "Mozilla/5.0"},
            'cookies': {"session": "identifier"}, 'params': {}, 'data': {'ava': "avascan"}
        },
        {
            'url': "https://www.example.com/one", 'method': "GET", 'headers': {'User-Agent': "Mozilla/5.0"},
            'cookies': {"session": "identifier"}, 'params': {'ava': "token"}, 'data': {}
        },
        {
            'url': "https://www.example.com/one", 'method': "GET", 'headers': {'User-Agent': "Mozilla/5.0"},
            'cookies': {"session": "identifier"}, 'params': {'ava': "avascan", 'test': "token"}, 'data': {}
        },
        {
            'url': "https://www.example.com/three", 'method': "POST", 'headers': {'Content-Type': "application/json"},
            'cookies': {"session": "identifier"}, 'params': {}, 'data': '{"ava": "avascan", "test": "token"}'
        },
        {
            'url': "https://www.example.com/one", 'method': "GET", 'headers': {'User-Agent': "Mozilla/5.0"},
            'cookies': {"session": "identifier"}, 'params': {'ava': "avascan"}, 'data': {}
        },
        {
            'url': "https://www.example.com/one", 'method': "GET", 'headers': {'User-Agent': "AVA/1.22.1"},
            'cookies': {"session": "identifier"}, 'params': {'ava': "avascan"}, 'data': {}
        },
        {
            'url': "https://www.example.com/one", 'method': "GET", 'headers': {'User-Agent': "Mozilla/5.0"},
            'cookies': {"csrf": "token"}, 'params': {'ava': "avascan"}, 'data': {}
        },
        {
            'url': "https://www.example.com/three", 'method': "POST", 'headers': {'Content-Type': "application/json"},
            'cookies': {"session": "identifier"}, 'params': {}, 'data': '{"test": "token", "ava": "avascan"}'
        }
    ]

    generated = vectors[0:6]

    # reduce
    test = ava.scanner._reduce_vectors(vectors)
    assert len(test) == len(generated)
    assert all(vector in generated for vector in test)


def test_load_checks(mocker):
    # actives
    mocker.patch("ava.common.utility.get_package_classes", return_value=[CrossSiteScriptingCheck])
    configs = {'actives': "xss", 'passives': None, 'blinds': None}
    test = ava.scanner._load_checks(configs)
    assert isinstance(test[0], CrossSiteScriptingCheck)

    # passives
    mocker.patch("ava.common.utility.get_package_classes", return_value=[PersonallyIdentifiableInformationCheck])
    configs = {'actives': None, 'passives': "pii", 'blinds': None}
    test = ava.scanner._load_checks(configs)
    assert isinstance(test[0], PersonallyIdentifiableInformationCheck)

    # blinds
    mocker.patch("ava.common.utility.get_package_classes", return_value=[CrossSiteScriptingBlindCheck])
    configs = {'actives': None, 'passives': None, 'blinds': {'xss': "http://localhost:8080/"}}
    test = ava.scanner._load_checks(configs)
    assert isinstance(test[0], CrossSiteScriptingBlindCheck)

    # no checks
    configs = {'actives': None, 'passives': None, 'blinds': None}
    test = ava.scanner._load_checks(configs)
    assert test == []


def test_run_scanner_positive(mocker):
    configs = {"hars": ["test.har"],
               "report": None,
               "auditors": [],
               "actives": [], "blinds": {}, "passives": [],
               "reduce": False, "summary": False}
    vector = {
        "url": "http://www.avascan.com/",
        "method": "get",
        "params": {"param": "avascan"},
        "cookies": {},
        "headers": {}
    }

    # mock
    mocker.patch("ava.readers.vector.HarReader.parse", return_value=[vector])
    mocker.patch("ava.common.auditor._Auditor.run", return_value=[])
    mocker.patch("ava.reporters.file.JsonReporter.report")
    mocker.patch("ava.reporters.console.TableReporter.report")

    # no checks
    test = ava.scanner._run_scanner(configs)
    assert not test

    # summary
    configs['blinds'] = {}
    configs['summary'] = True
    test = ava.scanner._run_scanner(configs)
    assert not test

    # with report
    configs['report'] = "report.json"
    configs['summary'] = False
    test = ava.scanner._run_scanner(configs)
    assert not test


def test_run_scanner_negative(mocker):
    configs = {"hars": ["test.har"],
               "report": None,
               "auditors": [],
               "actives": [], "blinds": {}, "passives": [],
               "reduce": True, "summary": False}

    # empty vectors
    mocker.patch("ava.readers.vector.HarReader.parse", return_value=[])
    with pytest.raises(MissingComponentException):
        ava.scanner._run_scanner(configs)


def test_main_positive(mocker):
    # list
    args = ["-l", "test.json"]
    test = ava.scanner.main(args)
    assert test == 0

    # empty run scanner
    args = ["--quiet", "test.json"]
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.common.config.generate")
    mocker.patch("ava.scanner._run_scanner")
    test = ava.scanner.main(args)
    assert test == 0


def test_main_negative(mocker):
    # missing vector file
    args = []
    test = ava.scanner.main(args)
    assert test == 2

    # vector file not exists
    args = ["test.json"]
    mocker.patch("os.path.isfile", return_value=False)
    test = ava.scanner.main(args)
    assert test == 2

    # config reader missing component
    args = ["-c", "config.yml", "test.json"]
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.scanner._parse_yaml", side_effect=MissingComponentException("Missing config file"))
    test = ava.scanner.main(args)
    assert test == 2

    # config reader invalid format
    args = ["-c", "config.yml", "test.json"]
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.scanner._parse_yaml", side_effect=InvalidFormatException("Invalid config file format"))
    test = ava.scanner.main(args)
    assert test == 2

    # config reader unknown key
    args = ["-c", "config.yml", "test.json"]
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.scanner._parse_yaml", side_effect=UnknownKeyException("Unknown config file key"))
    test = ava.scanner.main(args)
    assert test == 2

    # config generate invalid value
    args = ["test.json"]
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.common.config.generate", side_effect=InvalidValueException("Config invalid value"))
    test = ava.scanner.main(args)
    assert test == 2

    # config generate unknown key
    args = ["test.json"]
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.common.config.generate", side_effect=UnknownKeyException("Config unknown key"))
    test = ava.scanner.main(args)
    assert test == 2

    # run scanner missing component
    args = ["test.json"]
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.common.config.generate")
    mocker.patch("ava.scanner._run_scanner", side_effect=MissingComponentException("Run missing component"))
    test = ava.scanner.main(args)
    assert test == 2

    # run scanner invalid format
    args = ["test.json"]
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.common.config.generate")
    mocker.patch("ava.scanner._run_scanner", side_effect=InvalidFormatException("Invalid JSON format"))
    test = ava.scanner.main(args)
    assert test == 2


def test_console(mocker):
    # empty run
    sys.argv = ["ava.py", "test.json"]
    mocker.patch("os.path.isfile", return_value=True)
    mocker.patch("ava.common.config.generate")
    mocker.patch("ava.scanner._run_scanner")
    test = ava.scanner.console()
    assert test == 0
