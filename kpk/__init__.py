#!/usr/bin/env python


__author__ = "Kris Amundson"
__copyright__ = "Copyright (C) 2024 Kris Amundson"
__license__ = "GPL-3.0-or-later"
__version__ = "2.3.3"

import base64
import clipboard
import click
import fcntl
import json
import logging
import os
import password_strength
import pathlib
import yaml
import subprocess
import sys
from datetime import datetime, timezone
from loguru import logger
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import InvalidToken
from getpass import getpass


class KpkError(Exception):
    pass


class Import:
    """Imported YAML file."""

    def __init__(self, path=None):
        self.src = pathlib.Path(path)
        self.data = None

        if not self.src.is_file():
            raise FileNotFoundError("Import file not found.")

        self.data = list(yaml.safe_load_all(self.src.read_text()))


DB_VERSION = "3"


def now_iso():
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entry_get_value(entry):
    """Extract ciphertext from a DB entry (string or dict)."""
    if isinstance(entry, dict):
        return entry["value"]
    return entry


def entry_get_updated(entry):
    """Extract updated timestamp from a DB entry, or None."""
    if isinstance(entry, dict):
        return entry.get("updated")
    return None


def entry_make(ciphertext):
    """Create a DB entry with the current timestamp."""
    return {"value": ciphertext, "updated": now_iso()}


def db_write(dbpath, db):
    """Write db to disk with an exclusive file lock."""
    with open(dbpath, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        json.dump(db, f, sort_keys=True, indent=4)


def db_setup(dbpath, migrate=False):
    """Setup db -- load existing or create new.

    If migrate=True, upgrade older DB versions to the current version.
    """

    try:
        db = json.load(dbpath.open(mode="r"))
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        # DB does not exist or is not JSON, we create a new one.
        try:
            db = {"__version__": DB_VERSION}
            dbpath.parent.mkdir(parents=False, exist_ok=True)
            db_write(dbpath, db)
        except FileNotFoundError as _e:
            # TODO: make this more useful
            logger.error(f"Problem creating db. {_e}")

        logger.info(f"Initialized new db: {dbpath}")
        logger.info("Create a password.gpg in this directory to use as encryption key.")
        sys.exit()

    db_ver = db.get("__version__")
    if db_ver != DB_VERSION:
        if migrate and (db_ver in ("2",) or not isinstance(db_ver, str)):
            logger.info(f"Migrating DB to version {DB_VERSION}.")
            db["__version__"] = DB_VERSION
        else:
            logger.error(f"Unsupported DB version: {db_ver}. Expected {DB_VERSION}.")
            sys.exit(1)

    db["__path__"] = str(dbpath)

    return db


def good_password(password=None):
    """Check the strength of the encryption password."""

    if password is None or password == "":
        logger.error("Password empty or None.")
        return False

    policy = password_strength.PasswordPolicy.from_names(strength=0.66)
    check = policy.test(password)

    if check:
        strength = password_strength.PasswordStats(password).strength()
        logger.error(
            "Password strength does not meet policy.\n"
            f" Strength: {strength}\n"
            f" Policy:   {check[0].strength}\n"
            f" Details:  https://pypi.org/project/password-strength/"
        )
        return False

    return True


def obtain_password():
    """Obtain decryption password from a GPG file."""
    passwordfile = pathlib.Path.home() / ".kpk" / "password.gpg"
    try:
        cleartext = subprocess.run(
            ["gpg", "-d", passwordfile], capture_output=True, check=True
        ).stdout
    except subprocess.CalledProcessError:
        logger.error(f"Problem decrypting password.gpg.")
        sys.exit(1)

    cleantext = cleartext.rstrip()
    if not good_password(cleantext):
        sys.exit(1)

    return cleantext


def password_to_key(password=None):
    """Convert string password to 32-byte url-safe base64 type."""

    if not password:
        logger.error("Password empty. Aborting encryption key creation.")
        sys.exit(1)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
        backend=default_backend(),
    )

    key = base64.urlsafe_b64encode(hkdf.derive(password))

    return key



def check_path(directory=None):
    """Check for valid db path, including KPK_DBDIR envvar and default. Returns Path object."""

    default_path = pathlib.Path.home() / ".kpk"

    if not directory:
        directory = os.environ.get("KPK_DBDIR")

    if directory:
        directory_path = pathlib.Path(directory)

        if directory_path.is_dir():
            return directory_path / "secrets.json"
        else:
            logger.error(f"Error: Check path failed, {directory} invalid DB directory.")
            sys.exit(1)
    else:
        # Return default path.
        directory_path = default_path

        if directory_path.is_dir():
            return directory_path / "secrets.json"
        else:
            logger.error(f"Error: Check path failed, {directory} invalid DB directory.")
            sys.exit(1)


# @logger.catch
@click.group()
@click.option("--debug", "-d", is_flag=True, default=False)
@click.version_option(__version__, "--version", "-V")
def main(debug: bool):
    # Logging Config
    logger.remove(0)
    if not debug:
        logger.add(sys.stdout, level="INFO")
    else:
        logger.add(sys.stderr, level="DEBUG")
        logger.debug("Debug logging enabled")
        logging.basicConfig(level=logging.DEBUG)

@click.command()
@click.argument("key", type=str, required=True)
def delete(key):
    """Delete a value from the database."""
    if key.startswith("__"):
        logger.error(f"Key '{key}' is reserved.")
        sys.exit(1)

    db_path = check_path()
    db = db_setup(db_path)

    try:
        logger.debug(f"Cypher Value: {entry_get_value(db[key])}")
        del db[key]
    except KeyError:
        logger.warning("Value not in db.")
        sys.exit(2)

    try:
        db_write(db_path, db)
    except FileNotFoundError:
        logger.error("DB open failed due to file not existing.")
        sys.exit(1)

    logger.info("OK")


@click.command()
@click.argument("key", type=str, required=True)
@click.option("--out", "-o", is_flag=True, default=False, help="Print to screen")
def get(key, out):
    """Given a key, get the value."""
    db_path = check_path()
    db = db_setup(db_path)

    password = obtain_password()
    cryptokey = password_to_key(password)
    ciphersuite = Fernet(cryptokey)

    logger.debug(f"Password: {password}")
    logger.debug(f"Cryptokey: {cryptokey}")

    try:
        cyphervalue = entry_get_value(db[key]).encode("utf-8")
        logger.debug(f"Cypher Value: {cyphervalue}")
    except KeyError:
        logger.warning(f"Key '{key}' not found.")
        sys.exit(2)

    try:
        clearvalue = ciphersuite.decrypt(cyphervalue).decode("utf-8")
        logger.debug(f"Clear Value: {clearvalue}")
    except InvalidToken:
        logger.error("Decryption failed, likely due to incorrect password.")
        sys.exit(1)

    if not out:
        logger.debug("Copying to clipboard")
        clipboard.copy(clearvalue)
        logger.info("COPIED")
    else:
        print(clearvalue)


@click.command()
def ls():
    """Print keys in current kpk database."""
    db_path = check_path()
    db = db_setup(db_path)

    logger.debug(f"db_path: {db_path}\n")

    keys = "\n═════════════════════ KEYS ══════════════════════\n"
    for k, v in db.items():
        if k.startswith("__"):
            continue
        ts = entry_get_updated(v)
        if ts:
            keys += f"{k:<65}{ts}\n"
        else:
            keys += f"{k}\n"

    logger.info(keys)


@click.command()
@click.argument("key", type=str, required=True)
@click.argument("value", type=str, required=False)
@click.option("--prompt", "-p", is_flag=True, default=False, help="Prompt for value.")
def set(key, value, prompt):
    """Given a key, write the value."""
    if key.startswith("__"):
        logger.error(f"Key '{key}' is reserved.")
        sys.exit(1)

    db_path = check_path()
    db = db_setup(db_path)

    if value and prompt:
        logger.error("Can not ask to prompt AND provide a value.")
        sys.exit(1)

    if prompt:
        value = getpass("Value:")

    if not value:
        logger.error("No value provided. Pass a value argument or use --prompt.")
        sys.exit(1)

    logger.debug(db_path)
    logger.debug(key)
    logger.debug(value)

    password = obtain_password()
    cryptokey = password_to_key(password)
    ciphersuite = Fernet(cryptokey)

    cipherbytes = ciphersuite.encrypt(value.encode())
    db[key] = entry_make(cipherbytes.decode("utf-8"))

    try:
        db_write(db_path, db)
    except FileNotFoundError:
        logger.error("DB open failed, file not found.")
        sys.exit(1)

    logger.info("OK")


@click.command()
@click.option("--file", "-f", type=click.Path(), default=None, help="Export to a file instead of stdout.")
def export(file):
    """Export all keys and decrypted values as JSON."""
    confirmation = "EXPORT ALL MY SECRETS IN THE CLEAR"
    msg = "This exports all your secrets in the CLEAR"
    border = "═" * (len(msg) + 2)
    click.echo(f"\n╔{border}╗")
    click.echo(f"║ {msg} ║")
    click.echo(f"╚{border}╝\n")
    response = input(f'Type "{confirmation}" to proceed: ')
    if response != confirmation:
        logger.error("Export aborted.")
        sys.exit(1)

    db_path = check_path()
    db = db_setup(db_path)

    password = obtain_password()
    cryptokey = password_to_key(password)
    ciphersuite = Fernet(cryptokey)

    exported = {"__version__": db.get("__version__", DB_VERSION)}
    for k, v in db.items():
        if k.startswith("__"):
            continue
        try:
            cleartext = ciphersuite.decrypt(entry_get_value(v).encode("utf-8")).decode("utf-8")
        except InvalidToken:
            logger.error(f"Decryption failed for key '{k}', skipping.")
            continue
        ts = entry_get_updated(v)
        if ts:
            exported[k] = {"value": cleartext, "updated": ts}
        else:
            exported[k] = cleartext

    output = json.dumps(exported, sort_keys=True, indent=4)

    if file:
        pathlib.Path(file).write_text(output + "\n")
        logger.info(f"Exported to {file}")
    else:
        print(output)


@click.command(name="import")
@click.option("--file", "-f", type=click.Path(exists=True), default=None, help="Import from a file instead of stdin.")
@click.option("--yaml", "use_yaml", is_flag=True, default=False, help="Parse YAML; extract user:/pass: pairs as key/value.")
def import_cmd(file, use_yaml):
    """Import keys and cleartext values from JSON (or YAML with --yaml), encrypting them into the database."""
    if file:
        raw = pathlib.Path(file).read_text()
    else:
        click.echo(f"Reading {'YAML' if use_yaml else 'JSON'} from stdin (Ctrl-D to end):")
        raw = sys.stdin.read()

    if use_yaml:
        docs = list(yaml.safe_load_all(raw))
        data = {}
        for i, doc in enumerate(docs):
            if not isinstance(doc, dict):
                logger.warning(f"YAML document {i + 1}: not a mapping, skipping.")
                continue
            user = doc.get("user")
            passwd = doc.get("pass")
            if not user or not passwd:
                logger.warning(f"YAML document {i + 1}: missing 'user' or 'pass', skipping.")
                continue
            data[str(user)] = str(passwd)
    else:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            sys.exit(1)

        if not isinstance(data, dict):
            logger.error("Expected a JSON object with string keys and string values.")
            sys.exit(1)

    # Pull out __version__ if present; it's metadata, not a secret.
    import_version = data.pop("__version__", None)

    for k, v in data.items():
        if not isinstance(k, str):
            logger.error(f"Key '{k}' is not a string.")
            sys.exit(1)
        if isinstance(v, dict):
            if "value" not in v or not isinstance(v["value"], str):
                logger.error(f"Key '{k}': timestamped entry must have a string 'value' field.")
                sys.exit(1)
        elif not isinstance(v, str):
            logger.error(f"Key '{k}' or its value is not a string. All keys and values must be strings.")
            sys.exit(1)

    if not data:
        logger.error("Nothing to import.")
        sys.exit(1)

    db_path = check_path()
    db = db_setup(db_path, migrate=True)

    internal_keys = {k for k in db if k.startswith("__")}
    existing_keys = {k for k in db if not k.startswith("__")}
    overwritten = sorted(existing_keys & {k for k in data})

    skip_keys = []
    if overwritten:
        auto_kept = []
        auto_updated = []
        needs_prompt = []

        for k in overwritten:
            import_entry = data[k]
            import_ts = import_entry.get("updated") if isinstance(import_entry, dict) else None
            db_ts = entry_get_updated(db[k])

            if import_ts and db_ts:
                if import_ts > db_ts:
                    auto_updated.append(k)
                else:
                    auto_kept.append(k)
                    skip_keys.append(k)
            else:
                needs_prompt.append(k)

        for k in auto_updated:
            logger.info(f"  {k}: updating from import (newer)")
        for k in auto_kept:
            logger.info(f"  {k}: keeping existing (newer)")

        if needs_prompt:
            click.echo(f"\nThe following {len(needs_prompt)} existing key(s) will be overwritten:\n")
            for k in needs_prompt:
                click.echo(f"  - {k}")
            click.echo()
            if not click.confirm("Proceed?"):
                logger.error("Import aborted.")
                sys.exit(1)

    password = obtain_password()
    cryptokey = password_to_key(password)
    ciphersuite = Fernet(cryptokey)

    for k, v in data.items():
        if k.startswith("__") or k in skip_keys:
            continue
        import_cleartext = v["value"] if isinstance(v, dict) else v
        import_ts = v.get("updated") if isinstance(v, dict) else None
        cipherbytes = ciphersuite.encrypt(import_cleartext.encode())
        ciphertext = cipherbytes.decode("utf-8")
        if import_ts:
            db[k] = {"value": ciphertext, "updated": import_ts}
        else:
            db[k] = entry_make(ciphertext)

    db["__version__"] = DB_VERSION

    try:
        db_write(db_path, db)
    except FileNotFoundError:
        logger.error("DB open failed, file not found.")
        sys.exit(1)

    logger.info(f"Imported {len(data)} key(s). OK")


main.add_command(delete)
main.add_command(export)
main.add_command(import_cmd)
main.add_command(ls)
main.add_command(get)
main.add_command(set)

# main = cli

if __name__ == "__main__":
    main()
