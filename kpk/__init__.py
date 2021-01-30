#!/usr/bin/env python3

# -*- coding: utf-8 -*-


"""
Kris Password Keystore.

Usage:
    kpk get <key> [options]
    kpk put <key> <value> [options]
    kpk del <key> [options]
    kpk ls [options]
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
__copyright__ = "Copyright (C) 2021 Kris Amundson"
__license__ = "GPL-3.0-or-later"
__version__ = "2.0.1"

import base64
import clipboard
import docopt
import json
import os
import password_strength
import pathlib
import subprocess
import sys
from loguru import logger
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import InvalidToken

class KpkError(Exception):
    pass

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

    if password == None or password == "":
        logger.error("Password empty or None.")
        return False

    policy = password_strength.PasswordPolicy.from_names(strength=0.66)
    check = policy.test(password)

    if check:
        strength = password_strength.PasswordStats(password).strength()
        logger.error(
            "Password strength does not meet policy.\n"
            f"Strength: {strength}\n"
            f"Policy:   {check[0].strength}\n"
            f"Details:  https://pypi.org/project/password-strength/"
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


def get(db, key, ciphersuite):
    """Get value from the db given a key."""

    try:
        cyphervalue = db[key].encode("utf-8")
    except KeyError:
        logger.warning(f"Key '{key}' not found.")
        sys.exit(1)

    try:
        clearvalue = ciphersuite.decrypt(cyphervalue)
    except InvalidToken:
        logger.error("Decryption failed, likely due to incorect password.")
        sys.exit(1)

    return clearvalue.decode("utf-8")


def put(db, dbpath, k, v, ciphersuite):
    """Put a value into the database and write it."""

    cipherbytes = ciphersuite.encrypt(v.encode())
    db[k] = cipherbytes.decode("utf-8")

    try:
        json.dump(db, dbpath.open(mode="w"), sort_keys=True, indent=4)
    except FileNotFoundError:
        logger.error("DB open failed due to file not existing.")
        sys.exit(1)

    return "OK"


def delete(db, dbpath, k):
    """Delete a value from the database and write it."""

    try:
        del db[k]
    except KeyError:
        logger.warning("Value not in db.")
        sys.exit(0)

    try:
        json.dump(db, dbpath.open(mode="w"), sort_keys=True, indent=4)
    except FileNotFoundError:
        logger.error("DB open failed due to file not existing.")
        sys.exit(1)

    return "OK"


def ls(db):
    """List db keys and values."""
    print("\n═════════════ KEYS ═════════════")
    for k in db.keys():
        print(k)


def check_path(directory=None):
    """Check for valid db path, including KPK_DBDIR envvar. Returns a default."""

    if not directory:
        directory = os.environ.get("KPK_DBDIR")

    if directory:
        directory_path = pathlib.Path(directory)

        if directory_path.is_dir():
            return directory_path
        else:
            logger.error(f'Error: Check path failed, {directory} invalid DB directory.')
            sys.exit(1)
    else:
        # Return default path.
        directory_path = pathlib.Path.home() / ".kpk"

        if directory_path.is_dir():
            return directory_path / "secrets.json"
        else:
            logger.error(f'Error: Check path failed, {directory} invalid DB directory.')
            sys.exit(1)


@logger.catch
def main():
    """Simple Key/Value Store."""
    args = docopt.docopt(__doc__, version=__version__)

    # For readability below.
    key = args["<key>"]
    put_value = args["<value>"]

    db_path = check_path(args["--dir"])

    db = db_setup(db_path)
    password = obtain_password()
    cryptokey = password_to_key(password)
    ciphersuite = Fernet(cryptokey)

    if args["--verbose"]:
        logger.debug(f"CLI Arguments: {args}")
        logger.debug(f"Decrypted password.gpg: {password}")
        logger.debug(f"Cryptokey: {cryptokey}")

    # 'get' output to clipboard or stdout
    if args["get"]:
        get_v = get(db, key, ciphersuite)
        if not args["--out"]:
            clipboard.copy(get_v)
            print("COPIED")
        else:
            print(get_v)
    elif args["put"]:
        print(put(db, db_path, key, put_value, ciphersuite))
    elif args["del"]:
        print(delete(db, db_path, key))
    elif args["ls"]:
        ls(db)


if __name__ == "__main__":
    main()
