#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pytests for :class:`dead_sfs.keygen`"""

import argparse
import os
from tempfile import TemporaryDirectory

import nacl.secret
import pytest

from dead_sfs.keygen import get_parser, main


def test_get_argparser():
    parser = get_parser()
    assert parser
    assert isinstance(parser, argparse.ArgumentParser)


def test_gen_key():
    with TemporaryDirectory() as tempdir:
        output_path = os.path.join(tempdir, "test.key")
        main([output_path])
        with open(output_path, "rb") as f:
            key = f.read()
        assert key
        assert len(key) == nacl.secret.SecretBox.KEY_SIZE
        assert nacl.secret.SecretBox(key)


def test_missing_arg():
    with pytest.raises(SystemExit):
        main([])
