#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pytests for :mod:`client.packet`"""

from client.packet import Response, ResponseCode


def test_disconnect_response():
    resp = Response()
    assert resp.type == ResponseCode.DISCONNECTED
    assert resp.raw_data is None
    assert resp.data is None
    assert resp.name is None
    assert resp.message_type is None

    resp = Response(None)
    assert resp.type == ResponseCode.DISCONNECTED
    assert resp.raw_data is None
    assert resp.data is None
    assert resp.name is None
    assert resp.message_type is None
