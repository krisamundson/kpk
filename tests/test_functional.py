#!/usr/bin/env pytest

# -*- coding: utf-8 -*-

"""test_round1.py

Testing for kpk. Uses pytest.
"""


__author__ = "Kris Amundson"
__copyright__ = "Copyright (C) 2019 Kris Amundson"
__version__ = "0.1"

import docopt
import sys
import kpk

def test_python_version():
    """Set our minimum python version."""
    assert sys.version_info >= (3, 6, 0)


def test_docopt():
    args = docopt.docopt(kpk.__doc__, argv=["get", "foo"])
    assert args["get"] is True


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

# def test_getbasic():
#     # FIXME: this is all broken
#     args = docopt.docopt(kpk.__doc__, argv=["get", "KEYKEY"])
#     kpk.main()
#     executable = 'cat input_binary | ./seqout.py'
#     input_files = ''

#     out = subprocess.run(['{} {}'.format(executable, input_files)],
#                          capture_output=True,
#                          shell=True)

#     assert out.stderr == b'ERROR: Input not text.\n'
