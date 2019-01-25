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


# Packet
# [header] [packet len except header (4)] [type (1)] [payload]
def packetize(command: int, payload: bytes):
    pktlen = len(payload) + 1
    return struct.pack("!cIB", b'\xde', pktlen, command) + payload


class Command:

    @staticmethod
    def msg_req_sharekey():
        payload = struct.pack("!B", MessageCode.REQ_SHAREKEY.value)
        return packetize(CommandCode.MSG_ALL.value, payload)

    @staticmethod
    def msg_enc_sharekey(data):
        payload = struct.pack("!B", MessageCode.ENC_SHAREKEY.value) + data
        return packetize(CommandCode.MSG_ALL.value, payload)

    @staticmethod
    def msg_send_sharekey(recipient, data):
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", MessageCode.SEND_SHAREKEY.value)
        payload += data
        return packetize(CommandCode.MSG_TO.value, payload)

    @staticmethod
    def msg_req_pubkey(recipient, mykey):
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", MessageCode.REQ_PUBKEY.value)
        payload += mykey
        return packetize(CommandCode.MSG_TO.value, payload)

    @staticmethod
    def msg_send_pubkey(recipient, data):
        payload = struct.pack("!H", len(recipient))
        payload += recipient
        payload += struct.pack("!B", MessageCode.SEND_PUBKEY.value)
        payload += data
        return packetize(CommandCode.MSG_TO.value, payload)

    @staticmethod
    def msg_enc_pubkey(recipient, data):
        payload = struct.pack("!H", len(recipient))
        payload += recipient
        payload += struct.pack("!B", MessageCode.ENC_PUBKEY.value)
        payload += data
        return packetize(CommandCode.MSG_TO.value, payload)

    @staticmethod
    def ident(name):
        return packetize(CommandCode.ID.value, name.encode('utf-8'))

    @staticmethod
    def who():
        return packetize(CommandCode.WHO.value, b"")


class Response:
    def __init__(self, rtype, raw_data=None):
        self.type = rtype
        self.raw_data = raw_data

        self.message = None
        self.name = None
        self.message_type = None

        if self.raw_data is not None:
            self.parse_response(self.raw_data)

    def parse_response(self, raw_data):
        self.type = ResponseCode(raw_data[5])
        # SVR_NOTICE
        if self.type == ResponseCode.NOTICE:
            self.message = raw_data[6:]
        # SVR_MSG
        elif self.type == ResponseCode.MESSAGE:
            namelen = struct.unpack("!H", raw_data[6:8])[0]
            self.name = self.raw_data[8:8 + namelen]
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
