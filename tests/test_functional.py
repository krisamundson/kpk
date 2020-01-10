#!/usr/bin/env pytest

# -*- coding: utf-8 -*-

"""test_round1.py

Testing for kpk. Uses pytest.
"""


__author__ = "Kris Amundson"
__copyright__ = "Copyright (C) 2019 Kris Amundson"
__version__ = "0.1"

# import os
# import subprocess
import docopt
import sys
import kpk

def test_python_version():
    """Set our minimum python version."""
    assert sys.version_info >= (3, 6, 0)


def test_docopt():
    args = docopt.docopt(kpk.__doc__, argv=["get", "foo"])
    assert args["get"] is True


def test_getbasic():
    # FIXME: this is all broken
    args = docopt.docopt(kpk.__doc__, argv=["get", "KEYKEY"])
    kpk.main()
    executable = 'cat input_binary | ./seqout.py'
    input_files = ''

    out = subprocess.run(['{} {}'.format(executable, input_files)],
                         capture_output=True,
                         shell=True)

    assert out.stderr == b'ERROR: Input not text.\n'
