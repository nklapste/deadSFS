#!/usr/bin/env python
# -*- coding: utf-8 -*-

""""""

import struct


# Packet
# [header] [packet len except header (4)] [type (1)] [payload]
class Command():
    CMD_MSGALL, CMD_MSGTO, CMD_IDENT, CMD_WHO = list(range(4))

    MSG_REQ_SHAREKEY, MSG_SEND_SHAREKEY, MSG_ENC_SHAREKEY, \
    MSG_REQ_PUBKEY, MSG_SEND_PUBKEY, MSG_ENC_PUBKEY = list(range(6))

    def __init__(self, txq):
        self.queue = txq

    def packetize(self, command, payload):
        pktlen = len(payload) + 1
        return struct.pack("!cIB", b'\xde', pktlen, command) + payload

    def msg_req_sharekey(self):
        payload = struct.pack("!B", Command.MSG_REQ_SHAREKEY)
        packet = self.packetize(Command.CMD_MSGALL, payload)
        self.queue.put(packet)

    def msg_enc_sharekey(self, data):
        payload = struct.pack("!B", Command.MSG_ENC_SHAREKEY) + data
        packet = self.packetize(Command.CMD_MSGALL, payload)
        self.queue.put(packet)

    def msg_send_sharekey(self, recipient, data):
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", Command.MSG_SEND_SHAREKEY)
        payload += data
        packet = self.packetize(Command.CMD_MSGTO, payload)
        self.queue.put(packet)

    def msg_req_pubkey(self, recipient, mykey):
        payload = struct.pack("!H", len(recipient))
        payload += recipient.encode('utf-8')
        payload += struct.pack("!B", Command.MSG_REQ_PUBKEY)
        payload += mykey
        packet = self.packetize(Command.CMD_MSGTO, payload)
        self.queue.put(packet)

    def msg_send_pubkey(self, recipient, data):
        payload = struct.pack("!H", len(recipient))
        payload += recipient
        payload += struct.pack("!B", Command.MSG_SEND_PUBKEY)
        payload += data
        packet = self.packetize(Command.CMD_MSGTO, payload)
        self.queue.put(packet)

    def msg_enc_pubkey(self, recipient, data):
        payload = struct.pack("!H", len(recipient))
        payload += recipient
        payload += struct.pack("!B", Command.MSG_ENC_PUBKEY)
        payload += data
        packet = self.packetize(Command.CMD_MSGTO, payload)
        self.queue.put(packet)

    def ident(self, name):
        packet = self.packetize(Command.CMD_IDENT, name.encode('utf-8'))
        self.queue.put(packet)

    def who(self):
        packet = self.packetize(Command.CMD_WHO, b"")
        self.queue.put(packet)


class Response():
    SVR_NOTICE, SVR_MSG, DISCONNECTED = list(range(4, 7))

    def __init__(self, rtype):
        self.type = rtype