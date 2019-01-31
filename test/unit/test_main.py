#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pytests for :mod:`dead_sfs.__main__`"""

import argparse
import logging
from unittest.mock import patch

import nacl.secret
import nacl.utils
import pytest

from dead_sfs.__main__ import get_parser, log_level, main


def test_get_parser():
    parser = get_parser()
    assert isinstance(parser, argparse.ArgumentParser)


@pytest.mark.parametrize(
    "log_level_string, expected",
    [
        ("DEBUG", logging.DEBUG),
        ("INFO", logging.INFO),
        ("WARNING", logging.WARNING),
        ("ERROR", logging.ERROR),
        ("CRITICAL", logging.CRITICAL),
    ]
)
def test_log_level(log_level_string, expected):
    assert log_level(log_level_string) == expected


def test_log_level_invalid():
    with pytest.raises(argparse.ArgumentTypeError):
        log_level("nonsuch")


def test_main_missing_key_arg():
    with pytest.raises(SystemExit):
        main([])


@pytest.fixture()
def secret_key_file(tmpdir):
    keyfile = tmpdir.mkdir("keys").join("deadSFS.key")
    with open(str(keyfile), "wb") as f:
        f.write(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE))
    return keyfile


@patch("dead_sfs.shell.DeadSFSShell.cmdloop")
def test_main(mock_dead_sfs_shell_cmdloop, secret_key_file):
    main([str(secret_key_file)])
    mock_dead_sfs_shell_cmdloop.assert_called_once_with()


@patch("dead_sfs.shell.DeadSFSShell.cmdloop")
def test_main_verbose(mock_dead_sfs_shell_cmdloop, secret_key_file):
    main([str(secret_key_file), "-v"])
    mock_dead_sfs_shell_cmdloop.assert_called_once_with()


@patch("dead_sfs.shell.DeadSFSShell.cmdloop")
def test_main_log_dir(mock_dead_sfs_shell_cmdloop, tmpdir, secret_key_file):
    logging_dir = str(tmpdir.mkdir("logs"))
    main([str(secret_key_file), "--log-dir={}".format(logging_dir)])
    mock_dead_sfs_shell_cmdloop.assert_called_once_with()
