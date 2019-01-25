#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Client logic for deadchat"""

import base64
import select
import socket
import ssl
import struct
from configparser import ConfigParser
from logging import getLogger

import nacl
import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.utils

from client.packet import Response, ResponseCode, Command, MessageCode

__log__ = getLogger(__name__)


class Client:

    MAX_NAME_LENGTH = 65535

    def __init__(self, config_path: str, ca_certs: str):
        """Init a client to interact with the deadchat server and other
        deadchat clients"""
        self.config_path = config_path
        self.config = ConfigParser()

        self.ca_certs = ca_certs
        self.name = None
        self.id_public_key = None
        self.id_private_key = None

        self.shared_key = None
        self.secretbox = None
        self.boxes = {}

        self.sock: socket = None

    def send_packet(self, packet):
        sent_bytes = 0
        pktlen = len(packet)
        while sent_bytes < pktlen:
            sent_bytes += self.sock.send(packet[sent_bytes:])
        return sent_bytes

    def get_packet(self):
        r, w, e = select.select([self.sock], [], [], 0.125)
        for sock in r:
            if sock == self.sock:
                try:
                    read_bytes = 0
                    packet = b""
                    have_pktlen = False
                    header_index = 0
                    # Receive data until we have length field from packet
                    while not have_pktlen:
                        tmp = sock.read(4096)
                        if not tmp:
                            return Response(ResponseCode.DISCONNECTED)
                        else:
                            packet += tmp
                            read_bytes += len(tmp)
                            header_index = packet.find(b'\xde')
                            if header_index + 4 <= read_bytes:
                                have_pktlen = True

                    # Drop bytes before header
                    packet = packet[header_index:]
                    pktlen = struct.unpack("!I", packet[1:5])[0]
                    read_bytes = len(packet) - 1
                    while read_bytes < pktlen:
                        tmp = sock.read(4096)
                        if not tmp:
                            return Response(ResponseCode.DISCONNECTED)
                        else:
                            packet.append(tmp)
                            read_bytes += len(tmp)
                    return Response(None, packet)
                except socket.error:
                    return
        return

    def user_connect(self, host: str, port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.ca_certs is not None:
                self.sock = ssl.wrap_socket(
                    s,
                    ca_certs=self.ca_certs,
                    cert_reqs=ssl.CERT_REQUIRED
                )
            else:
                self.sock = ssl.wrap_socket(s)
            self.sock.connect((host, port))

            __log__.info("Connected to {} on port {}".format(host, port))

            self.config.read(self.config_path)
            if not self.config.has_section("server"):
                self.config.add_section("server")
            self.config.set("server", "host", str(host))
            self.config.set("server", "port", str(port))
            self.save_config()
        except Exception:
            __log__.exception(
                "Unable to connect to {} on port {}".format(host, port))

    def user_createid(self, name: str):
        if len(name) > Client.MAX_NAME_LENGTH:
            __log__.error("Name: {} is too long".format(name))
            return

        self.name = name
        key = nacl.public.PrivateKey.generate()
        self.id_private_key = key
        self.id_public_key = key.public_key

        # Reset existing public key box instances
        self.boxes = {}

        __log__.info("Created identity {}".format(self.name))
        if not self.config.has_section("id"):
            self.config.add_section("id")
        self.config.set("id", "id_private_key",
                        base64.b64encode(self.id_private_key.encode()).decode(
                            "utf8"))
        self.config.set("id", "id_public_key",
                        base64.b64encode(self.id_public_key.encode()).decode(
                            "utf8"))
        self.config.set("id", "name", self.name.encode('utf-8').decode("utf8"))
        self.save_config()

    def user_idexch(self, name: str):
        key = self.id_public_key.encode()
        self.send_packet(Command.msg_req_pubkey(name, key))
        __log__.info("Requested room key from {}".format(name))

    def user_msg(self, name: str, msg: str):
        if self.init_pubkey(name):
            nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
            enc = self.boxes[name].encrypt(msg.encode('utf-8'), nonce)
            self.send_packet(Command.msg_enc_pubkey(name.encode('utf8'), enc))
            __log__.info("[{} => {}] {}".format(self.name, name, msg))
        else:
            __log__.error(
                "No key for user, run \"/idexch {}\" first to "
                "exchange keys".format(name)
            )

    def load_config(self):
        self.config.read(self.config_path)
        if self.config.has_section("id"):
            try:
                self.id_private_key = nacl.public.PrivateKey(
                    base64.b64decode(self.config.get("id", "id_private_key")))
                self.id_public_key = nacl.public.PublicKey(
                    base64.b64decode(self.config.get("id", "id_public_key")))
                self.name = self.config.get("id", "name")
                __log__.info("Name set to {}".format(self.name))
            except Exception:
                __log__.exception("error accessing Keys")

        if self.config.has_section("room"):
            try:
                self.shared_key = base64.b64decode(
                    self.config.get("room", "room_key"))
                self.secretbox = nacl.secret.SecretBox(self.shared_key)
            except Exception:
                __log__.exception("error accessing SecretBox")

    def handle_response(self, resp: Response):
        if resp.type == ResponseCode.DISCONNECTED:
            self.close()
        elif resp.type == ResponseCode.NOTICE:
            __log__.info("Server notice: {}".format(resp.message))
        elif resp.type == ResponseCode.MESSAGE:
            if resp.message_type == MessageCode.REQ_SHAREKEY:
                self.svr_msg_request_sharekey(resp.name)
            elif resp.message_type == MessageCode.SEND_SHAREKEY:
                self.svr_msg_send_sharekey(resp.name, resp.data)
            elif resp.message_type == MessageCode.ENC_SHAREKEY:
                self.svr_msg_encrypted_sharekey(resp.name, resp.data)
            elif resp.message_type == MessageCode.REQ_PUBKEY:
                self.svr_msg_request_pubkey(resp.name, resp.data)
            elif resp.message_type == MessageCode.SEND_PUBKEY:
                self.svr_msg_send_pubkey(resp.name, resp.data)
            elif resp.message_type == MessageCode.ENC_PUBKEY:
                self.svr_msg_encrypted_pubkey(resp.name, resp.data)

    def svr_msg_request_sharekey(self, sender: str):
        __log__.info("{} requests the room key".format(sender))

    def svr_msg_send_sharekey(self, sender: str, data: bytes):
        if self.init_pubkey(sender):
            try:
                nonce = data[0:nacl.public.Box.NONCE_SIZE]
                enc = data[nacl.public.Box.NONCE_SIZE:]
                self.shared_key = self.boxes[sender].decrypt(enc, nonce)
                self.secretbox = nacl.secret.SecretBox(self.shared_key)
                if not self.config.has_section("room"):
                    self.config.add_section("room")
                self.config.set("room", "room_key",
                                base64.b64encode(self.shared_key).decode(
                                    "utf8"))
                self.save_config()
                __log__.info("{} has sent you the room key".format(sender))
                return
            except nacl.exceptions.CryptoError:
                __log__.exception(
                    "error decrypting given room sent from: {}".format(sender))
        __log__.error("Received room key from {} but unable to decrypt, "
                      "run /idexch".format(sender))

    def svr_msg_encrypted_sharekey(self, sender: str, data: bytes):
        nonce = data[0:nacl.secret.SecretBox.NONCE_SIZE]
        enc = data[nacl.secret.SecretBox.NONCE_SIZE:]
        if self.secretbox:
            try:
                msg = self.secretbox.decrypt(enc, nonce)
                __log__.info("<{}> {}".format(sender, msg))
                return
            except nacl.exceptions.CryptoError:
                __log__.exception("<{}> (ERROR: decrypting message)")
        __log__.error("<{}> (encrypted)".format(sender))

    def svr_msg_request_pubkey(self, sender: str, data: bytes):
        """Handle a request for my public key"""
        __log__.info("Received id key request from {}".format(sender))

        # store key from sender
        if not self.config.has_section("keys"):
            self.config.add_section("keys")
        self.config.set("keys", sender, base64.b64encode(data).decode("utf8"))
        self.save_config()

        # TODO: handle if public_key not set
        key = self.id_public_key.encode()
        self.send_packet(Command.msg_send_pubkey(sender.encode("utf8"), key))

        # Delete existing box
        if sender in self.boxes:
            self.boxes.pop(sender)

    def svr_msg_send_pubkey(self, sender: str, data: bytes):
        """Handle receiving a requested public key from sender"""
        # save key to config file
        if not self.config.has_section("keys"):
            self.config.add_section("keys")
        self.config.set("keys", sender, base64.b64encode(data).decode("utf8"))
        self.save_config()
        __log__.info(
            "id key exchange with {} complete".format(sender))

        # Delete existing box
        if sender in self.boxes:
            self.boxes.pop(sender)

    def svr_msg_encrypted_pubkey(self, sender: str, data: bytes):
        if self.init_pubkey(sender):
            try:
                nonce = data[0:nacl.public.Box.NONCE_SIZE]
                enc = data[nacl.public.Box.NONCE_SIZE:]
                msg = self.boxes[sender].decrypt(enc, nonce)
                __log__.info("[{} => {}] {}".format(sender, self.name, msg))
                return
            except nacl.exceptions.CryptoError:
                __log__.exception(
                    "[{} => {}] ( WARNING: Unable to decrypt. One of you "
                    "may have changed keys or might be an imposter. )".format(
                        sender, self.name))
        else:
            __log__.error(
                "[{} => {}] ( Message from unknown user, run \"/idexch {}\" "
                "to exchange keys )".format(sender, self.name, sender))

    def save_config(self):
        with open(self.config_path, "w") as configfile:
            self.config.write(configfile)

    def close(self):
        self.sock.close()
        self.sock = None
        __log__.info("disconnected from server")

    def user_genroomkey(self):
        self.shared_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self.secretbox = nacl.secret.SecretBox(self.shared_key)
        if not self.config.has_section("room"):
            self.config.add_section("room")
        self.config.set("room", "room_key",
                        base64.b64encode(self.shared_key).decode("utf8"))
        self.save_config()
        __log__.info("Room key generated")

    def user_sendroomkey(self, name: str):
        if self.init_pubkey(name):
            nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
            enc = self.boxes[name].encrypt(self.shared_key, nonce)
            self.send_packet(Command.msg_send_sharekey(name, enc))
            __log__.info("Sent room key to {}".format(name))
        else:
            __log__.error("No key for user, run \"/idexch {}\" first "
                          "to exchange keys".format(name))

    def init_pubkey(self, name):
        if name in self.boxes:
            return True

        self.config.read(self.config_path)
        if self.config.has_section("keys"):
            try:
                # TODO: make name one type
                if isinstance(name, str):
                    b64key = self.config.get("keys", name)
                else:
                    b64key = self.config.get("keys", name.decode('utf8'))

                key = nacl.public.PublicKey(base64.b64decode(b64key))
                self.boxes[name] = nacl.public.Box(self.id_private_key, key)
                return True
            except Exception:
                __log__.exception("error init_pubkey")
        return False
