#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pytests for :mod:`client.__main__`"""

import argparse
import logging

import pytest

from client.__main__ import get_parser, log_level


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
