#!/usr/bin/env pytest

# -*- coding: utf-8 -*-

"""test_functional.py

Testing for kpk. Uses pytest.
"""


__author__ = "Kris Amundson"
__copyright__ = "Copyright (C) 2021 Kris Amundson"
__version__ = "0.2"

from unittest import mock
from click.testing import CliRunner
from cryptography.fernet import Fernet
from loguru import logger
import json
import os
import pathlib
import pytest
import sys
import tempfile
import kpk


@pytest.fixture(autouse=True)
def _loguru_safe_remove():
    """Prevent loguru ValueError when cli() calls logger.remove(0) repeatedly."""
    original = logger.remove
    def safe_remove(handler_id=None):
        try:
            original(handler_id)
        except ValueError:
            pass
    with mock.patch("kpk.logger.remove", safe_remove):
        yield


def test_python_version():
    """Set our minimum python version."""
    assert sys.version_info >= (3, 6, 0)


# --- check_path tests ---


def test_check_path_default():
    path = str(kpk.check_path())
    home = os.environ.get("HOME")
    assert path == home + "/.kpk/secrets.json"


@mock.patch.dict(os.environ, {"KPK_DBDIR": "/tmp"})
def test_check_path_valid_environment_variable():
    assert kpk.check_path() == pathlib.PosixPath('/tmp/secrets.json')


@mock.patch.dict(os.environ, {"KPK_DBDIR": "/tmp/39a12f8d-506b-41f3-9184-4f956d860b52"})
def test_check_path_invalid_environment_variable():
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        kpk.check_path()

    assert os.environ.get('KPK_DBDIR') == "/tmp/39a12f8d-506b-41f3-9184-4f956d860b52"
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1


def test_check_path_directory_argument():
    """check_path with explicit directory argument."""
    assert kpk.check_path("/tmp") == pathlib.PosixPath('/tmp/secrets.json')


def test_check_path_invalid_directory_argument():
    """check_path with non-existent directory argument exits."""
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        kpk.check_path("/nonexistent/path")
    assert pytest_wrapped_e.value.code == 1


# --- good_password tests ---


def test_good_passwords():
    """Good encryption passwords."""
    passwords = [
        '72ebc541-ac9a-4d97-a6fe-d2b9ccd6190c',
        'welcome.TO.the19.jungle',
        'rtsJP5IEWyDTvnKtDgo1+Twuhqd1cnf/az0V8grI/1M=',
        '4850a0ccc6f567cc0ebe7060d20ffd4258b8210efadc259da62dc6ed9c65',
        '3nZNtSu4yWMntxZBzogAQ4kbpu2j/IWPpCBizKtjFGw=',
        '.IZ.THere9.A.WAY-'
    ]

    for password in passwords:
        assert kpk.good_password(password) is True


def test_none_and_empty_passwords():
    """Empty and None passwords. Called without parameter."""

    # Called with no parameter.
    assert kpk.good_password() is False

    passwords = [ None, '' ]
    for password in passwords:
        assert kpk.good_password(password) is False


def test_bad_passwords():
    """Weak encryption passwords."""
    passwords = [
        'TULIP337-491',
        'this is weak',
        'welcomeTOwelcomeTO',
        'rtsJP5IEWyDTvnKtDgo1rtsJP5IEWyDTvnKtDgo1',
    ]

    for password in passwords:
        assert kpk.good_password(password) is False


def test_bad_nist100_passwords():
    """Bad encryption passwords. NIST top 100 bad passwords."""
    passwords = [
        '123456',
        'password',
        '12345678',
        'qwerty',
        '123456789',
        '12345',
        '1234',
        '111111',
        '1234567',
        'dragon',
        '123123',
        'baseball',
        'abc123',
        'football',
        'monkey',
        'letmein',
        '696969',
        'shadow',
        'master',
        '666666',
        'qwertyuiop',
        '123321',
        'mustang',
        '1234567890',
        'michael',
        '654321',
        'pussy',
        'superman',
        '1qaz2wsx',
        '7777777',
        'fuckyou',
        '121212',
        '000000',
        'qazwsx',
        '123qwe',
        'killer',
        'trustno1',
        'jordan',
        'jennifer',
        'zxcvbnm',
        'asdfgh',
        'hunter',
        'buster',
        'soccer',
        'harley',
        'batman',
        'andrew',
        'tigger',
        'sunshine',
        'iloveyou',
        'fuckme',
        '2000',
        'charlie',
        'robert',
        'thomas',
        'hockey',
        'ranger',
        'daniel',
        'starwars',
        'klaster',
        '112233',
        'george',
        'asshole',
        'computer',
        'michelle',
        'jessica',
        'pepper',
        '1111',
        'zxcvbn',
        '555555',
        '11111111',
        '131313',
        'freedom',
        '777777',
        'pass',
        'fuck',
        'maggie',
        '159753',
        'aaaaaa',
        'ginger',
        'princess',
        'joshua',
        'cheese',
        'amanda',
        'summer',
        'love',
        'ashley',
        '6969',
        'nicole',
        'chelsea',
        'biteme',
        'matthew',
        'access',
        'yankees',
        '987654321',
        'dallas',
        'austin',
        'thunder',
        'taylor',
        'matrix',
    ]

    for password in passwords:
        assert kpk.good_password(password) is False


# --- password_to_key tests ---


def test_password_to_key_returns_valid_fernet_key():
    """password_to_key produces a key that Fernet accepts."""
    key = kpk.password_to_key(b"strong-test-password-1234!")
    Fernet(key)


def test_password_to_key_deterministic():
    """Same password always produces the same key."""
    key1 = kpk.password_to_key(b"strong-test-password-1234!")
    key2 = kpk.password_to_key(b"strong-test-password-1234!")
    assert key1 == key2


def test_password_to_key_empty():
    """Empty or None password exits."""
    with pytest.raises(SystemExit):
        kpk.password_to_key(None)

    with pytest.raises(SystemExit):
        kpk.password_to_key(b"")


# --- db_setup tests ---


def test_db_setup_loads_existing_db():
    """db_setup loads an existing JSON database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dbpath = pathlib.Path(tmpdir) / "secrets.json"
        data = {"__version__": "2", "testkey": "testval"}
        json.dump(data, dbpath.open(mode="w"))

        db = kpk.db_setup(dbpath)
        assert db["__version__"] == "2"
        assert db["testkey"] == "testval"
        assert db["__path__"] == str(dbpath)


def test_db_setup_creates_new_db():
    """db_setup creates a new db file and exits when none exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dbpath = pathlib.Path(tmpdir) / "secrets.json"

        with pytest.raises(SystemExit):
            kpk.db_setup(dbpath)

        assert dbpath.exists()
        data = json.load(dbpath.open())
        assert data["__version__"] == "2"


def test_db_setup_invalid_json():
    """db_setup reinitializes when existing file has invalid JSON."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dbpath = pathlib.Path(tmpdir) / "secrets.json"
        dbpath.write_text("not valid json{{{")

        with pytest.raises(SystemExit):
            kpk.db_setup(dbpath)

        data = json.load(dbpath.open())
        assert data["__version__"] == "2"


# --- Import class tests ---


def test_import_valid_yaml():
    """Import reads a valid YAML file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("key: value\nother: 123\n")
        f.flush()
        try:
            imp = kpk.Import(path=f.name)
            assert imp.data == [{"key": "value", "other": 123}]
        finally:
            os.unlink(f.name)


def test_import_missing_file():
    """Import raises FileNotFoundError for missing files."""
    with pytest.raises(FileNotFoundError):
        kpk.Import(path="/nonexistent/file.yaml")


# --- CLI tests ---


@pytest.fixture
def kpk_env(tmp_path):
    """Temporary kpk environment with a pre-populated encrypted DB."""
    password = b"72ebc541-ac9a-4d97-a6fe-d2b9ccd6190c"
    key = kpk.password_to_key(password)
    ciphersuite = Fernet(key)

    clearvalue = "supersecret"
    ciphertext = ciphersuite.encrypt(clearvalue.encode()).decode("utf-8")
    db = {"__version__": "2", "mykey": ciphertext}
    dbpath = tmp_path / "secrets.json"
    json.dump(db, dbpath.open(mode="w"), sort_keys=True, indent=4)

    return {
        "dbpath": dbpath,
        "password": password,
    }


def test_cli_ls(kpk_env):
    """ls command lists keys."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]):
        result = runner.invoke(kpk.main, ["ls"])
    assert result.exit_code == 0
    assert "mykey" in result.output


def test_cli_get_out(kpk_env):
    """get --out prints decrypted value to stdout."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["get", "--out", "mykey"])
    assert result.exit_code == 0
    assert "supersecret" in result.output


def test_cli_get_missing_key(kpk_env):
    """get with nonexistent key exits with code 2."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["get", "--out", "noexist"])
    assert result.exit_code == 2


def test_cli_set_and_get_roundtrip(kpk_env):
    """set a value then get it back."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["set", "newkey", "newvalue"])
        assert result.exit_code == 0

        result = runner.invoke(kpk.main, ["get", "--out", "newkey"])
        assert result.exit_code == 0
        assert "newvalue" in result.output


def test_cli_set_no_value(kpk_env):
    """set with no value and no --prompt exits with error."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]):
        result = runner.invoke(kpk.main, ["set", "newkey"])
    assert result.exit_code == 1


def test_cli_set_value_and_prompt_conflict(kpk_env):
    """set with both value and --prompt exits with error."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]):
        result = runner.invoke(kpk.main, ["set", "newkey", "val", "--prompt"])
    assert result.exit_code == 1


def test_cli_delete(kpk_env):
    """delete removes a key from the store."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]):
        result = runner.invoke(kpk.main, ["delete", "mykey"])
    assert result.exit_code == 0

    db = json.load(kpk_env["dbpath"].open())
    assert "mykey" not in db


def test_cli_delete_missing_key(kpk_env):
    """delete with nonexistent key exits with code 2."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]):
        result = runner.invoke(kpk.main, ["delete", "noexist"])
    assert result.exit_code == 2
