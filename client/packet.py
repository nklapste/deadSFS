#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""packet definitions for the deadchat client"""

import struct
from enum import Enum


class CommandCode(Enum):
    MSG_TO = 1
    ID = 2
    WHO = 3


class ResponseCode(Enum):
    NOTICE = 4
    MESSAGE = 5
    DISCONNECTED = 6


class MessageCode(Enum):
    SEND_SHARED_FS_KEY = 1
    REQUEST_PUBLIC_ID_KEY = 3
    SEND_PUBLIC_ID_KEY = 4


class Command:
    command_code: CommandCode
    payload: bytes

    def to_packet(self):
        """Convert the command into a packet to send

        The packet format follows:
        [header] [packet len except header (4)] [type (1)] [payload]
        """
        return struct.pack(
            "!cIB",
            b'\xde',
            len(self.payload) + 1,
            self.command_code
        ) + self.payload


class MessageToCommand(Command):
    command_code = CommandCode.MSG_TO
    message_code: MessageCode
    header: str
    content: bytes

    def to_packet(self):
        payload = struct.pack("!H", len(self.header))
        payload += self.header.encode('utf-8')
        payload += struct.pack("!B", self.message_code.value)
        payload += self.content
        self.payload = payload


class SendShareFSKey(MessageToCommand):
    message_code = MessageCode.SEND_SHARED_FS_KEY

    def __init__(self, recipient: str, enc_shared_fs_key: bytes):
        self.header = recipient
        self.content = enc_shared_fs_key


class RequestPublicIDKey(MessageToCommand):
    message_code = MessageCode.REQUEST_PUBLIC_ID_KEY

    def __init__(self, recipient: str, public_id_key: bytes):
        self.header = recipient
        self.content = public_id_key


class SendPublicIDKey(MessageToCommand):
    message_code = MessageCode.SEND_PUBLIC_ID_KEY

    def __init__(self, recipient: str, public_id_key: bytes):
        self.header = recipient
        self.content = public_id_key


class OnlineID(Command):
    command_code = CommandCode.ID

    def __init__(self, name: str):
        self.payload = name.encode('utf-8')


class Who(Command):
    command_code = CommandCode.WHO
    payload = b""


class Response:
    def __init__(self, raw_data: bytes = None):
        self.raw_data = raw_data
        self.type: ResponseCode = None

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

            if self.message_type == MessageCode.SEND_SHARED_FS_KEY:
                self.data = raw_data[8 + namelen + 1:]
            elif self.message_type == MessageCode.REQUEST_PUBLIC_ID_KEY:
                self.data = raw_data[8 + namelen + 1:]
            elif self.message_type == MessageCode.SEND_PUBLIC_ID_KEY:
                self.data = raw_data[8 + namelen + 1:]
