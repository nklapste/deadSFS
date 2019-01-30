#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""packet definitions for the deadchat client"""

import struct
from enum import Enum


class CommandCode(Enum):
    MSG_ALL = 0
    MSG_TO = 1
    ID = 2
    WHO = 3


class ResponseCode(Enum):
    NOTICE = 4
    MESSAGE = 5
    DISCONNECTED = 6


class MessageCode(Enum):
    REQ_SHAREKEY = 0
    SEND_SHAREKEY = 1
    ENC_SHAREKEY = 2
    REQ_PUBKEY = 3
    SEND_PUBKEY = 4
    ENC_PUBKEY = 5


# [header] [packet len except header (4)] [type (1)] [payload]
def packetize(command: int, payload: bytes) -> bytes:
    packet_length = len(payload) + 1
    return struct.pack("!cIB", b'\xde', packet_length, command) + payload


class Command:
    """Factory class for creating various command packets for deadchat"""

    @staticmethod
    def msg_req_sharekey() -> bytes:
        payload = struct.pack("!B", MessageCode.REQ_SHAREKEY.value)
        return packetize(CommandCode.MSG_ALL.value, payload)

    @staticmethod
    def msg_enc_sharekey(data: bytes) -> bytes:
        payload = struct.pack("!B", MessageCode.ENC_SHAREKEY.value) + data
        return packetize(CommandCode.MSG_ALL.value, payload)

    @staticmethod
    def msg_send_sharekey(recipient: str, data: bytes) -> bytes:
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", MessageCode.SEND_SHAREKEY.value)
        payload += data
        return packetize(CommandCode.MSG_TO.value, payload)

    @staticmethod
    def msg_req_pubkey(recipient: str, mykey: bytes) -> bytes:
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", MessageCode.REQ_PUBKEY.value)
        payload += mykey
        return packetize(CommandCode.MSG_TO.value, payload)

    @staticmethod
    def msg_send_pubkey(recipient: str, data: bytes) -> bytes:
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", MessageCode.SEND_PUBKEY.value)
        payload += data
        return packetize(CommandCode.MSG_TO.value, payload)

    @staticmethod
    def msg_enc_pubkey(recipient: str, data: bytes) -> bytes:
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", MessageCode.ENC_PUBKEY.value)
        payload += data
        return packetize(CommandCode.MSG_TO.value, payload)

    @staticmethod
    def ident(name: str) -> bytes:
        return packetize(CommandCode.ID.value, name.encode('utf-8'))

    @staticmethod
    def who() -> bytes:
        return packetize(CommandCode.WHO.value, b"")


class Response:
    def __init__(self, raw_data: bytes = None):
        self.raw_data = raw_data
        self.type = None

        self.name = None
        self.message_type = None
        self.data = None

        if self.raw_data is not None:
            self._parse_response(self.raw_data)
        else:
            self.type = ResponseCode.DISCONNECTED

    def _parse_response(self, raw_data: bytes):
        self.type = ResponseCode(raw_data[5])
        if self.type == ResponseCode.NOTICE:
            self.data = raw_data[6:]
        elif self.type == ResponseCode.MESSAGE:
            namelen = struct.unpack("!H", raw_data[6:8])[0]
            self.name = self.raw_data[8:8 + namelen]
            if isinstance(self.name, bytes):
                self.name = self.name.decode("utf8")
            self.message_type = MessageCode(raw_data[8 + namelen])

            if self.message_type == MessageCode.REQ_SHAREKEY:
                pass
            elif self.message_type == MessageCode.SEND_SHAREKEY:
                self.data = raw_data[8 + namelen + 1:]
            elif self.message_type == MessageCode.ENC_SHAREKEY:
                self.data = raw_data[8 + namelen + 1:]
            elif self.message_type == MessageCode.REQ_PUBKEY:
                self.data = raw_data[8 + namelen + 1:]
            elif self.message_type == MessageCode.SEND_PUBKEY:
                self.data = raw_data[8 + namelen + 1:]
            elif self.message_type == MessageCode.ENC_PUBKEY:
                self.data = raw_data[8 + namelen + 1:]
