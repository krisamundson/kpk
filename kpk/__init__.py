#!/usr/bin/env python

# -*- coding: utf-8 -*-


"""
Kris Password Keystore.

Usage:
    kpk get <key> [options]
    kpk put <key> <value> [options]
    kpk del <key> [options]
    kpk ls [options]
    kpk import <file>
    kpk (-h | --help)
    kpk --version

Options:
    -d <dir>, --dir <dir>  Secret key and db directory (env: KPK_DBDIR).
    -o, --out              Print value to screen.
    -h, --help             This help.
    -v, --verbose          Verbosity.
    --version              Display version.

Defaults:
    * db: ~/.kpk/secrets.json
"""

__author__ = "Kris Amundson"
__copyright__ = "Copyright (C) 2024 Kris Amundson"
__license__ = "GPL-3.0-or-later"
__version__ = "2.2.1"

import base64
import clipboard
import click
import json
import logging
import os
import password_strength
import pathlib
import yaml
import subprocess
import sys
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


def db_setup(dbpath):
    """Setup db -- load existing or create new."""

    try:
        db = json.load(dbpath.open(mode="r"))
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        # DB does not exist or is not JSON, we create a new one.
        try:
            db = {"__version__": "2"}
            dbpath.parent.mkdir(parents=False, exist_ok=True)
            json.dump(db, dbpath.open(mode="w"), sort_keys=True, indent=4)
        except FileNotFoundError as _e:
            # TODO: make this more useful
            logger.error(f"Problem creating db. {_e}")

        logger.info(f"Initialized new db: {dbpath}")
        logger.info("Create a password.gpg in this directory to use as encryption key.")
        sys.exit()

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


def put(db, dbpath, k, v, ciphersuite):
    """Put a value into the database and write it."""

    cipherbytes = ciphersuite.encrypt(v.encode())
    db[k] = cipherbytes.decode("utf-8")

    try:
        json.dump(db, dbpath.open(mode="w"), sort_keys=True, indent=4)
    except FileNotFoundError:
        logger.error("DB open failed, file not found.")
        sys.exit(1)

    return "OK"


def check_path(directory=None):
    """Check for valid db path, including KPK_DBDIR envvar and default. Returns Path object."""

    default_path = pathlib.Path.home() / ".kpk"

    if not directory:
        directory = os.environ.get("KPK_DBDIR")

    if directory:
        directory_path = pathlib.Path(directory)

        if directory_path.is_dir():
            return directory_path
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
def cli(debug):
    # Logging Config
    logger.remove(0)
    if not debug:
        logger.add(sys.stdout, level="INFO")
    else:
        logger.add(sys.stderr, level="DEBUG")
        logger.debug("Debug logging enabled")
        logging.basicConfig(level=logging.DEBUG)
    pass


@click.command()
@click.argument("key", type=str, required=True)
def delete(key):
    """Delete a value from the database."""
    db_path = check_path()
    db = db_setup(db_path)

    try:
        logger.debug(f"Cypher Value: {db[key]}")
        del db[key]
    except KeyError:
        logger.warning("Value not in db.")
        sys.exit(2)

    try:
        json.dump(db, db_path.open(mode="w"), sort_keys=True, indent=4)
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
        cyphervalue = db[key].encode("utf-8")
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

    logger.debug(
        f"db_path: {db_path}\n"
    )

    keys = "\n═════════════════════ KEYS ══════════════════════\n"
    for k in db.keys():
        keys += f"{k}\n"

    logger.info(keys)


@click.command()
@click.argument("key", type=str, required=True)
@click.argument("value", type=str, required=False)
@click.option("--prompt", "-p", is_flag=True, default=False, help="Prompt for value.")
def set(key, value, prompt):
    """Given a key, write the value."""
    db_path = check_path()
    db = db_setup(db_path)

    if value and prompt:
        logger.error("Can not ask to prompt AND provide a value.")
        sys.exit(1)

    if prompt:
        value = getpass("Value:")

    logger.debug(db_path)
    logger.debug(key)
    logger.debug(value)

    password = obtain_password()
    cryptokey = password_to_key(password)
    ciphersuite = Fernet(cryptokey)

    cipherbytes = ciphersuite.encrypt(value.encode())
    db[key] = cipherbytes.decode("utf-8")

    try:
        json.dump(db, db_path.open(mode="w"), sort_keys=True, indent=4)
    except FileNotFoundError:
        logger.error("DB open failed, file not found.")
        sys.exit(1)

    logger.info("OK")


cli.add_command(delete)
cli.add_command(ls)
cli.add_command(get)
cli.add_command(set)


if __name__ == "__main__":
    cli()
