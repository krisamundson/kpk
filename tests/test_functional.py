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
import re
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
        data = {"__version__": "3", "testkey": "testval"}
        json.dump(data, dbpath.open(mode="w"))

        db = kpk.db_setup(dbpath)
        assert db["__version__"] == "3"
        assert db["testkey"] == "testval"
        assert db["__path__"] == str(dbpath)


def test_db_setup_rejects_old_version():
    """db_setup rejects a v2 database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dbpath = pathlib.Path(tmpdir) / "secrets.json"
        json.dump({"__version__": "2"}, dbpath.open(mode="w"))

        with pytest.raises(SystemExit) as pytest_wrapped_e:
            kpk.db_setup(dbpath)
        assert pytest_wrapped_e.value.code == 1


def test_db_setup_creates_new_db():
    """db_setup creates a new db file and exits when none exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dbpath = pathlib.Path(tmpdir) / "secrets.json"

        with pytest.raises(SystemExit):
            kpk.db_setup(dbpath)

        assert dbpath.exists()
        data = json.load(dbpath.open())
        assert data["__version__"] == "3"


def test_db_setup_invalid_json():
    """db_setup reinitializes when existing file has invalid JSON."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dbpath = pathlib.Path(tmpdir) / "secrets.json"
        dbpath.write_text("not valid json{{{")

        with pytest.raises(SystemExit):
            kpk.db_setup(dbpath)

        data = json.load(dbpath.open())
        assert data["__version__"] == "3"


def test_db_setup_rejects_unsupported_version():
    """db_setup rejects a DB with an unsupported version."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dbpath = pathlib.Path(tmpdir) / "secrets.json"
        json.dump({"__version__": "99"}, dbpath.open(mode="w"))

        with pytest.raises(SystemExit) as pytest_wrapped_e:
            kpk.db_setup(dbpath)
        assert pytest_wrapped_e.value.code == 1


def test_db_setup_migrate_v2_to_v3():
    """db_setup with migrate=True upgrades a v2 DB to v3."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dbpath = pathlib.Path(tmpdir) / "secrets.json"
        json.dump({"__version__": "2", "mykey": "ciphertext"}, dbpath.open(mode="w"))

        db = kpk.db_setup(dbpath, migrate=True)
        assert db["__version__"] == "3"
        assert db["mykey"] == "ciphertext"


def test_db_setup_migrate_false_rejects_v2():
    """db_setup without migrate rejects a v2 DB."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dbpath = pathlib.Path(tmpdir) / "secrets.json"
        json.dump({"__version__": "2"}, dbpath.open(mode="w"))

        with pytest.raises(SystemExit) as pytest_wrapped_e:
            kpk.db_setup(dbpath)
        assert pytest_wrapped_e.value.code == 1


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


# --- entry helper tests ---


def test_now_iso_format():
    """now_iso returns a valid ISO 8601 UTC timestamp."""
    ts = kpk.now_iso()
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", ts)


def test_entry_get_value_string():
    """entry_get_value returns the string itself for old-format entries."""
    assert kpk.entry_get_value("ciphertext") == "ciphertext"


def test_entry_get_value_dict():
    """entry_get_value extracts the value field from new-format entries."""
    entry = {"value": "ciphertext", "updated": "2026-01-01T00:00:00Z"}
    assert kpk.entry_get_value(entry) == "ciphertext"


def test_entry_get_updated_string():
    """entry_get_updated returns None for old-format entries."""
    assert kpk.entry_get_updated("ciphertext") is None


def test_entry_get_updated_dict():
    """entry_get_updated returns the timestamp for new-format entries."""
    entry = {"value": "ciphertext", "updated": "2026-01-01T00:00:00Z"}
    assert kpk.entry_get_updated(entry) == "2026-01-01T00:00:00Z"


def test_entry_make():
    """entry_make creates a dict with value and updated keys."""
    entry = kpk.entry_make("ciphertext")
    assert entry["value"] == "ciphertext"
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", entry["updated"])


# --- CLI tests ---


@pytest.fixture
def kpk_env(tmp_path):
    """Temporary kpk environment with a pre-populated encrypted DB.

    Contains both old-format (bare string) and new-format (dict with timestamp) entries.
    """
    password = b"72ebc541-ac9a-4d97-a6fe-d2b9ccd6190c"
    key = kpk.password_to_key(password)
    ciphersuite = Fernet(key)

    clearvalue = "supersecret"
    ciphertext = ciphersuite.encrypt(clearvalue.encode()).decode("utf-8")

    ts_clearvalue = "timestamped_secret"
    ts_ciphertext = ciphersuite.encrypt(ts_clearvalue.encode()).decode("utf-8")

    db = {
        "__version__": "3",
        "mykey": ciphertext,
        "tskey": {"value": ts_ciphertext, "updated": "2026-01-01T00:00:00Z"},
    }
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


# --- export tests ---


EXPORT_CONFIRMATION = "EXPORT ALL MY SECRETS IN THE CLEAR"


def test_cli_export_to_stdout(kpk_env):
    """export prints decrypted JSON to stdout."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["export"], input=EXPORT_CONFIRMATION)
    assert result.exit_code == 0
    assert '"mykey": "supersecret"' in result.output


def test_cli_export_to_file(kpk_env, tmp_path):
    """export --file writes decrypted JSON to a file."""
    outfile = tmp_path / "export.json"
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["export", "--file", str(outfile)], input=EXPORT_CONFIRMATION)
    assert result.exit_code == 0
    data = json.loads(outfile.read_text())
    assert data["mykey"] == "supersecret"


def test_cli_export_includes_version(kpk_env, tmp_path):
    """export includes __version__ but not __path__."""
    outfile = tmp_path / "export.json"
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["export", "--file", str(outfile)], input=EXPORT_CONFIRMATION)
    assert result.exit_code == 0
    data = json.loads(outfile.read_text())
    assert data["__version__"] == "3"
    assert "__path__" not in data


def test_cli_export_aborted(kpk_env):
    """export aborts when confirmation doesn't match."""
    runner = CliRunner()
    result = runner.invoke(kpk.main, ["export"], input="no")
    assert result.exit_code == 1


# --- import tests ---


def test_cli_import_from_file(kpk_env, tmp_path):
    """import from file adds new keys."""
    import_data = {"newkey": "newvalue", "another": "secret"}
    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps(import_data))

    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["import", "-f", str(import_file)])
    assert result.exit_code == 0
    assert "Imported 2 key(s)" in result.output

    # verify the values were encrypted and stored
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["get", "--out", "newkey"])
    assert result.exit_code == 0
    assert "newvalue" in result.output


def test_cli_import_from_stdin(kpk_env):
    """import from stdin adds new keys."""
    import_data = json.dumps({"stdinkey": "stdinval"})

    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["import"], input=import_data)
    assert result.exit_code == 0
    assert "Imported 1 key(s)" in result.output


def test_cli_import_invalid_json(kpk_env):
    """import rejects invalid JSON."""
    runner = CliRunner()
    result = runner.invoke(kpk.main, ["import"], input="not json{{{")
    assert result.exit_code == 1
    assert "Invalid JSON" in result.output


def test_cli_import_not_a_dict(kpk_env):
    """import rejects JSON that is not an object."""
    runner = CliRunner()
    result = runner.invoke(kpk.main, ["import"], input='["a", "b"]')
    assert result.exit_code == 1
    assert "Expected a JSON object" in result.output


def test_cli_import_non_string_value(kpk_env):
    """import rejects values that are not strings."""
    runner = CliRunner()
    result = runner.invoke(kpk.main, ["import"], input='{"key": 123}')
    assert result.exit_code == 1
    assert "not a string" in result.output


def test_cli_import_empty_object(kpk_env):
    """import rejects empty JSON object."""
    runner = CliRunner()
    result = runner.invoke(kpk.main, ["import"], input='{}')
    assert result.exit_code == 1
    assert "Nothing to import" in result.output


def test_cli_import_overwrite_confirmed(kpk_env, tmp_path):
    """import with overlapping keys proceeds when user confirms."""
    import_data = {"mykey": "updated_secret"}
    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps(import_data))

    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["import", "-f", str(import_file)], input="y")
    assert result.exit_code == 0
    assert "mykey" in result.output
    assert "overwritten" in result.output.lower() or "Imported" in result.output

    # verify the value was updated
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["get", "--out", "mykey"])
    assert result.exit_code == 0
    assert "updated_secret" in result.output


def test_cli_import_overwrite_aborted(kpk_env, tmp_path):
    """import with overlapping keys aborts when user declines."""
    import_data = {"mykey": "updated_secret"}
    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps(import_data))

    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["import", "-f", str(import_file)], input="n")
    assert result.exit_code == 1


def test_cli_import_migrates_v2_db(tmp_path):
    """import into a v2 DB migrates it to v3."""
    password = b"72ebc541-ac9a-4d97-a6fe-d2b9ccd6190c"
    key = kpk.password_to_key(password)
    ciphersuite = Fernet(key)

    ciphertext = ciphersuite.encrypt(b"oldval").decode("utf-8")
    db = {"__version__": "2", "oldkey": ciphertext}
    dbpath = tmp_path / "secrets.json"
    json.dump(db, dbpath.open(mode="w"), sort_keys=True, indent=4)

    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps({"newkey": "newvalue"}))

    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=dbpath), \
         mock.patch("kpk.obtain_password", return_value=password):
        result = runner.invoke(kpk.main, ["import", "-f", str(import_file)])
    assert result.exit_code == 0
    assert "Migrating" in result.output

    db = json.load(dbpath.open())
    assert db["__version__"] == "3"
    assert "newkey" in db
    assert "oldkey" in db


# --- timestamp tests ---


def test_cli_get_with_timestamp(kpk_env):
    """get works on a new-format entry with timestamp."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["get", "--out", "tskey"])
    assert result.exit_code == 0
    assert "timestamped_secret" in result.output


def test_cli_set_creates_timestamp(kpk_env):
    """set stores an entry with a timestamp."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["set", "newkey", "newvalue"])
    assert result.exit_code == 0

    db = json.load(kpk_env["dbpath"].open())
    entry = db["newkey"]
    assert isinstance(entry, dict)
    assert "value" in entry
    assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", entry["updated"])


def test_cli_ls_shows_timestamps(kpk_env):
    """ls shows timestamps for entries that have them."""
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]):
        result = runner.invoke(kpk.main, ["ls"])
    assert result.exit_code == 0
    assert "tskey" in result.output
    assert "2026-01-01T00:00:00Z" in result.output
    assert "mykey" in result.output


def test_cli_export_includes_timestamps(kpk_env, tmp_path):
    """export includes timestamps for new-format entries."""
    outfile = tmp_path / "export.json"
    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["export", "--file", str(outfile)], input=EXPORT_CONFIRMATION)
    assert result.exit_code == 0
    data = json.loads(outfile.read_text())
    # old-format entry exports as bare string
    assert data["mykey"] == "supersecret"
    # new-format entry exports with timestamp
    assert data["tskey"]["value"] == "timestamped_secret"
    assert data["tskey"]["updated"] == "2026-01-01T00:00:00Z"


def test_cli_import_timestamped_format(kpk_env, tmp_path):
    """import accepts the timestamped entry format."""
    import_data = {"newkey": {"value": "imported_val", "updated": "2026-06-01T00:00:00Z"}}
    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps(import_data))

    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["import", "-f", str(import_file)])
    assert result.exit_code == 0

    # verify the timestamp was preserved
    db = json.load(kpk_env["dbpath"].open())
    assert db["newkey"]["updated"] == "2026-06-01T00:00:00Z"

    # verify the value decrypts
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["get", "--out", "newkey"])
    assert result.exit_code == 0
    assert "imported_val" in result.output


def test_cli_import_newer_wins(kpk_env, tmp_path):
    """import auto-resolves: newer import entry overwrites older existing."""
    import_data = {"tskey": {"value": "newer_val", "updated": "2027-01-01T00:00:00Z"}}
    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps(import_data))

    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["import", "-f", str(import_file)])
    assert result.exit_code == 0
    assert "updating from import" in result.output

    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["get", "--out", "tskey"])
    assert result.exit_code == 0
    assert "newer_val" in result.output


def test_cli_import_existing_wins(kpk_env, tmp_path):
    """import auto-resolves: older import entry is skipped."""
    import_data = {"tskey": {"value": "older_val", "updated": "2025-01-01T00:00:00Z"}}
    import_file = tmp_path / "import.json"
    import_file.write_text(json.dumps(import_data))

    runner = CliRunner()
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["import", "-f", str(import_file)])
    assert result.exit_code == 0
    assert "keeping existing" in result.output

    # original value is preserved
    with mock.patch("kpk.check_path", return_value=kpk_env["dbpath"]), \
         mock.patch("kpk.obtain_password", return_value=kpk_env["password"]):
        result = runner.invoke(kpk.main, ["get", "--out", "tskey"])
    assert result.exit_code == 0
    assert "timestamped_secret" in result.output
