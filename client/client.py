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
from typing import Optional

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
        self.name: str = None
        self.id_public_key: nacl.public.PublicKey = None
        self.id_private_key: nacl.public.PrivateKey = None

        self.shared_key: bytes = None
        self.secretbox: nacl.secret.SecretBox = None
        self.boxes = {}

        self.sock: socket.socket = None
        self.connected: bool = False
        self._load_config()

    def connect(self, host: str, port: int):
        """Connect to a deadchat server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.ca_certs is not None:
                self.sock = ssl.wrap_socket(
                    sock,
                    ca_certs=self.ca_certs,
                    cert_reqs=ssl.CERT_REQUIRED
                )
            else:
                self.sock = ssl.wrap_socket(sock)
            self.sock.connect((host, port))
        except Exception:
            __log__.exception(
                "unable to connect to {} on port {}".format(host, port))
        else:
            __log__.info("connected to {} on port {}".format(host, port))
            self.connected = True
            self.config.read(self.config_path)
            if not self.config.has_section("server"):
                self.config.add_section("server")
            self.config.set("server", "host", str(host))
            self.config.set("server", "port", str(port))
            self._save_config()

    def close(self):
        """Disconnect from the deadchat server"""
        self.sock.close()
        self.sock = None
        self.connected = False
        __log__.info("disconnected from server")

    def create_room_key(self):
        self.shared_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self.secretbox = nacl.secret.SecretBox(self.shared_key)
        if not self.config.has_section("room"):
            self.config.add_section("room")
        self.config.set("room", "room_key",
                        base64.b64encode(self.shared_key).decode("utf8"))
        self._save_config()
        __log__.info("created room key")

    def send_room_key(self, target_user: str):
        if self.check_public_key(target_user):
            nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
            enc = self.boxes[target_user].encrypt(self.shared_key, nonce)
            self.send_packet(Command.msg_send_sharekey(target_user, enc))
            __log__.info("sent room key to {}".format(target_user))

    def check_public_key(self, target_user: str) -> bool:
        if target_user in self.boxes:
            return True

        self.config.read(self.config_path)
        if self.config.has_section("keys"):
            try:
                b64key = self.config.get("keys", target_user)
                key = nacl.public.PublicKey(base64.b64decode(b64key))
                self.boxes[target_user] = \
                    nacl.public.Box(self.id_private_key, key)
                return True
            except Exception:
                __log__.exception("error init_pubkey")
        __log__.error("packet from unknown user {} exchange id keys "
                      "before interacting".format(target_user))
        return False

    def create_id_key(self, name: str):
        if len(name) > Client.MAX_NAME_LENGTH:
            __log__.error("user name {} is too long".format(name))
            return

        self.name = name
        key = nacl.public.PrivateKey.generate()
        self.id_private_key = key
        self.id_public_key = key.public_key

        # Reset existing public key box instances
        self.boxes = {}

        __log__.info("created id key for user name {}".format(self.name))
        if not self.config.has_section("id"):
            self.config.add_section("id")
        self.config.set(
            "id", "id_private_key",
            base64.b64encode(self.id_private_key.encode()).decode("utf8"))
        self.config.set(
            "id", "id_public_key",
            base64.b64encode(self.id_public_key.encode()).decode("utf8"))
        self.config.set("id", "name", self.name.encode('utf8').decode("utf8"))
        self._save_config()

    def exchange_id_key(self, target_user: str):
        key = self.id_public_key.encode()
        self.send_packet(Command.msg_req_pubkey(target_user, key))
        __log__.info("exchanging id keys with user {}".format(target_user))

    def message(self, target_user: str, msg: str):
        if self.check_public_key(target_user):
            nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
            enc = self.boxes[target_user].encrypt(msg.encode('utf8'), nonce)
            self.send_packet(Command.msg_enc_pubkey(target_user, enc))
            __log__.info("[{} => {}] {}".format(self.name, target_user, msg))

    def handle_response(self, resp: Response):
        if resp.type == ResponseCode.DISCONNECTED:
            self.close()
        elif resp.type == ResponseCode.NOTICE:
            self._receive_server_notice(resp.data)
        elif resp.type == ResponseCode.MESSAGE:
            if resp.message_type == MessageCode.REQ_SHAREKEY:
                self._receive_request_share_key(resp.name)
            elif resp.message_type == MessageCode.SEND_SHAREKEY:
                self._receive_send_share_key(resp.name, resp.data)
            elif resp.message_type == MessageCode.ENC_SHAREKEY:
                self._receive_encrypted_share_key(resp.name, resp.data)
            elif resp.message_type == MessageCode.REQ_PUBKEY:
                self._receive_request_public_key(resp.name, resp.data)
            elif resp.message_type == MessageCode.SEND_PUBKEY:
                self._receive_send_public_key(resp.name, resp.data)
            elif resp.message_type == MessageCode.ENC_PUBKEY:
                self._receive_encrypted_public_key(resp.name, resp.data)

    def _receive_server_notice(self, data: bytes):
        __log__.info("[server notice] {}".format(data))
        # TODO: expirementing
        try:
            nonce = data[0:nacl.secret.SecretBox.NONCE_SIZE]
            enc = data[nacl.secret.SecretBox.NONCE_SIZE:]
            if self.secretbox:
                try:
                    msg = self.secretbox.decrypt(enc, nonce)
                    __log__.info("[test] {}".format(msg))
                    return
                except nacl.exceptions.CryptoError:
                    __log__.exception("unable to decrypt message")
        except Exception:
            __log__.exception("testing")

    def _receive_request_share_key(self, sender: str):
        __log__.info("user {} requests the room key".format(sender))

    def _receive_send_share_key(self, sender: str, data: bytes):
        if self.check_public_key(sender):
            try:
                nonce = data[0:nacl.public.Box.NONCE_SIZE]
                enc = data[nacl.public.Box.NONCE_SIZE:]
                self.shared_key = self.boxes[sender].decrypt(enc, nonce)
                self.secretbox = nacl.secret.SecretBox(self.shared_key)
                if not self.config.has_section("room"):
                    self.config.add_section("room")
                self.config.set(
                    "room", "room_key",
                    base64.b64encode(self.shared_key).decode("utf8"))
                self._save_config()
                __log__.info("user {} sent you the room key".format(sender))
                return
            except nacl.exceptions.CryptoError:
                __log__.exception("error decrypting given room sent "
                                  "from user {}".format(sender))

    def _receive_encrypted_share_key(self, sender: str, data: bytes):
        nonce = data[0:nacl.secret.SecretBox.NONCE_SIZE]
        enc = data[nacl.secret.SecretBox.NONCE_SIZE:]
        if self.secretbox:
            try:
                msg = self.secretbox.decrypt(enc, nonce)
                __log__.info("[{} => all] {}".format(sender, msg))
                return
            except nacl.exceptions.CryptoError:
                __log__.exception("unable to decrypt message")
        __log__.error("[{} => all] (encrypted)".format(sender))

    def _receive_request_public_key(self, sender: str, data: bytes):
        """Handle a request for my public key"""
        __log__.info("received id key request from user {}".format(sender))

        # store key from sender
        if not self.config.has_section("keys"):
            self.config.add_section("keys")
        self.config.set("keys", sender, base64.b64encode(data).decode("utf8"))
        self._save_config()

        # TODO: handle if public_key not set
        key = self.id_public_key.encode()
        self.send_packet(Command.msg_send_pubkey(sender, key))

        # Delete existing box
        if sender in self.boxes:
            self.boxes.pop(sender)

    def _receive_send_public_key(self, sender: str, data: bytes):
        """Handle receiving a requested public key from sender"""
        # save key to config file
        if not self.config.has_section("keys"):
            self.config.add_section("keys")
        self.config.set("keys", sender, base64.b64encode(data).decode("utf8"))
        self._save_config()
        __log__.info("id key exchange with user {} complete".format(sender))

        # Delete existing box
        if sender in self.boxes:
            self.boxes.pop(sender)

    def _receive_encrypted_public_key(self, sender: str, data: bytes):
        if self.check_public_key(sender):
            try:
                nonce = data[0:nacl.public.Box.NONCE_SIZE]
                enc = data[nacl.public.Box.NONCE_SIZE:]
                msg = self.boxes[sender].decrypt(enc, nonce)
                __log__.info("[{} => {}] {}".format(sender, self.name, msg))
                return
            except nacl.exceptions.CryptoError:
                __log__.exception("[{} => {}] (WARNING: unable to decrypt. "
                                  "One of you may have changed keys or might "
                                  "be an imposter)".format(sender, self.name))

    def send_packet(self, packet: bytes) -> int:
        sent_bytes = 0
        while sent_bytes < len(packet):
            sent_bytes += self.sock.send(packet[sent_bytes:])
        return sent_bytes

    def get_packet(self) -> Optional[Response]:
        r, w, e = select.select([self.sock], [], [], 0.125)
        for sock in r:
            if sock == self.sock:
                try:
                    read_bytes = 0
                    packet = b""
                    packet_complete = False
                    header_index = 0
                    # Receive data until we have length field from packet
                    while not packet_complete:
                        tmp = sock.read(4096)
                        if not tmp:
                            return Response()
                        else:
                            packet += tmp
                            read_bytes += len(tmp)
                            header_index = packet.find(b'\xde')
                            if header_index + 4 <= read_bytes:
                                packet_complete = True

                    # Drop bytes before header
                    packet = packet[header_index:]
                    packet_length = struct.unpack("!I", packet[1:5])[0]
                    read_bytes = len(packet) - 1
                    while read_bytes < packet_length:
                        tmp = sock.read(4096)
                        if not tmp:
                            return Response()
                        else:
                            packet.append(tmp)
                            read_bytes += len(tmp)
                    return Response(packet)
                except socket.error:
                    return
        return

    def _load_config(self):
        self.config.read(self.config_path)
        if self.config.has_section("id"):
            try:
                self.id_private_key = nacl.public.PrivateKey(
                    base64.b64decode(self.config.get("id", "id_private_key")))
                self.id_public_key = nacl.public.PublicKey(
                    base64.b64decode(self.config.get("id", "id_public_key")))
                self.name = self.config.get("id", "name")
                __log__.info("set user name to {}".format(self.name))
            except Exception:
                __log__.exception("error accessing Keys")

        if self.config.has_section("room"):
            try:
                self.shared_key = base64.b64decode(
                    self.config.get("room", "room_key"))
                self.secretbox = nacl.secret.SecretBox(self.shared_key)
            except Exception:
                __log__.exception("error accessing SecretBox")

    def _save_config(self):
        with open(self.config_path, "w") as configfile:
            self.config.write(configfile)
