#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""packet definitions for the deadchat client"""

import struct
from enum import Enum


class CommandCode(Enum):
    FS = 7
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


class FileSystemCode(Enum):
    LIST_DIR = 8
    MAKE_DIR = 9
    CHANGE_DIR = 10
    WRITE_FILE = 11
    READ_FILE = 12
    DELETE_FILE = 13
    DELETE_DIR = 14  # TODO re-order
    # TODO: more defs


# Packet
# [header] [packet len except header (4)] [type (1)] [payload]
def packetize(command: int, payload: bytes) -> bytes:
    pktlen = len(payload) + 1
    return struct.pack("!cIB", b'\xde', pktlen, command) + payload


class Command:

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

    @staticmethod
    def list_dir(dir_name: bytes) -> bytes:
        payload = struct.pack("!B", FileSystemCode.LIST_DIR.value)
        print(dir_name)
        payload += struct.pack("!H", len(dir_name))
        payload += dir_name
        return packetize(CommandCode.FS.value, payload)

    @staticmethod
    def make_dir(dir_name: bytes) -> bytes:
        payload = struct.pack("!B", FileSystemCode.MAKE_DIR.value)
        payload += struct.pack("!H", len(dir_name))
        payload += dir_name
        return packetize(CommandCode.FS.value, payload)

    @staticmethod
    def delete_dir(dir_name: bytes) -> bytes:
        payload = struct.pack("!B", FileSystemCode.DELETE_DIR.value)
        payload += struct.pack("!H", len(dir_name))
        payload += dir_name
        return packetize(CommandCode.FS.value, payload)

    @staticmethod
    def change_dir(dir_name: bytes) -> bytes:
        payload = struct.pack("!B", FileSystemCode.CHANGE_DIR.value)
        payload += struct.pack("!H", len(dir_name))
        payload += dir_name
        return packetize(CommandCode.FS.value, payload)

    @staticmethod
    def write_file(filename: bytes, content: bytes):
        # TODO: clean
        payload = struct.pack("!B", FileSystemCode.WRITE_FILE.value)
        payload += struct.pack("!H", len(filename))
        payload += filename
        payload += struct.pack("!H", len(content))
        payload += content
        return packetize(CommandCode.FS.value, payload)

    @staticmethod
    def read_file(filename: bytes):
        payload = struct.pack("!B", FileSystemCode.READ_FILE.value)
        payload += struct.pack("!H", len(filename))
        payload += filename
        return packetize(CommandCode.FS.value, payload)

    @staticmethod
    def delete_file(filename: bytes):
        payload = struct.pack("!B", FileSystemCode.DELETE_FILE.value)
        payload += struct.pack("!H", len(filename))
        payload += filename
        return packetize(CommandCode.FS.value, payload)


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
