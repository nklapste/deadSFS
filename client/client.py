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
    """client that handles key generation and sharing to establish the
    proper keys to use the :class:`client.ftp_client.EncryptedFTPClient`
    effectively."""

    MAX_NAME_LENGTH = 65535

    def __init__(self, config_path: str, ca_certs: str = None):
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
            raise
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

    def create_shared_fs_key(self):
        """Create a **private key** to be shared with users that are
        **authorized** to access the remote filesystem"""
        self.shared_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self.secretbox = nacl.secret.SecretBox(self.shared_key)
        if not self.config.has_section("room"):
            self.config.add_section("room")
        self.config.set("room", "room_key",
                        base64.b64encode(self.shared_key).decode("utf8"))
        self._save_config()
        __log__.info("created room key")

    def send_shared_fs_key(self, target_user: str):
        """Sent the **private key** for the remote filesystem to the
        specified user"""
        if self.check_public_id_key(target_user):
            nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
            enc = self.boxes[target_user].encrypt(self.shared_key, nonce)
            self.send_packet(Command.send_shared_fs_key(target_user, enc))
            __log__.info("sent room key to {}".format(target_user))

    def check_public_id_key(self, target_user: str) -> bool:
        """Check if a public id key exists for the target user

        This tests if the client "knows" this user.
        """
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
        """Create a public and private id key for this client"""
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

    def exchange_public_id_key(self, target_user: str):
        """Make a request for exchanging public id keys between this client
        and the target user"""
        key = self.id_public_key.encode()
        self.send_packet(Command.request_public_id_key(target_user, key))
        __log__.info("exchanging public id keys with user {}".format(
            target_user))

    def handle_response(self, resp: Response):
        if resp.type == ResponseCode.DISCONNECTED:
            self.close()
        elif resp.type == ResponseCode.NOTICE:
            self._receive_server_notice(resp.data)
        elif resp.type == ResponseCode.MESSAGE:
            if resp.message_type == MessageCode.SEND_SHARED_FS_KEY:
                self._receive_send_shared_fs_key(resp.name, resp.data)
            elif resp.message_type == MessageCode.REQUEST_PUBLIC_ID_KEY:
                self._receive_request_public_id_key(resp.name, resp.data)
            elif resp.message_type == MessageCode.SEND_PUBLIC_ID_KEY:
                self._receive_send_public_id_key(resp.name, resp.data)

    def _receive_server_notice(self, data: bytes):
        """Handle receiving a plain text message from the server"""
        __log__.info("[server notice] {}".format(data))

    def _receive_send_shared_fs_key(self, sender: str, data: bytes):
        """Handle receiving the shared filesystem private key"""
        if self.check_public_id_key(sender):
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
            except nacl.exceptions.CryptoError:
                __log__.exception("error decrypting given room sent "
                                  "from user {}".format(sender))

    def _receive_request_public_id_key(self, sender: str, data: bytes):
        """Handle a request for this client's public id key"""
        __log__.info("received id key request from user {}".format(sender))

        # store key from sender
        if not self.config.has_section("keys"):
            self.config.add_section("keys")
        self.config.set("keys", sender, base64.b64encode(data).decode("utf8"))
        self._save_config()

        # TODO: handle if public_key not set
        key = self.id_public_key.encode()
        self.send_packet(Command.send_public_id_key(sender, key))

        # Delete existing box
        if sender in self.boxes:
            self.boxes.pop(sender)

    # TODO: inspect security on this method
    def _receive_send_public_id_key(self, sender: str, data: bytes):
        """Handle receiving a public id key from the sender"""
        # save key to config file
        if not self.config.has_section("keys"):
            self.config.add_section("keys")
        # TODO: check if the user is already present
        # could be attack to override past accepted user
        self.config.set("keys", sender, base64.b64encode(data).decode("utf8"))
        self._save_config()
        __log__.info("id key exchange with user {} complete".format(sender))

        # Delete existing box
        if sender in self.boxes:
            self.boxes.pop(sender)

    def send_packet(self, packet: bytes) -> int:
        """Send a packet to the server"""
        sent_bytes = 0
        while sent_bytes < len(packet):
            sent_bytes += self.sock.send(packet[sent_bytes:])
        return sent_bytes

    def get_packet(self) -> Optional[Response]:
        """Receive a packet from the server"""
        r, _, _ = select.select([self.sock], [], [], 0.125)
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
