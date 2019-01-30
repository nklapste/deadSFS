#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pytests for :mod:`client.client`"""

import pytest

from client.client import Client


@pytest.fixture(scope='session')
def config_file(tmpdir_factory):
    fn = tmpdir_factory.mktemp('data').join('config.ini')
    fn.write("")
    return fn


def test_connect_fail(config_file):
    client = Client(str(config_file))
    with pytest.raises(ConnectionRefusedError):
        client.connect("127.0.0.1", 1)