#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""command shell for the deadchat client"""

import base64
import cmd
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

from client.packet import Command, Response, MessageCode, ResponseCode

__log__ = getLogger(__name__)


def connected(f):
    """Annotation to check if someone is connected before attempting a
    command in :class:`DeadChatShell`"""

    def wrapper(*args):
        if args[0].connected:
            return f(*args)
        else:
            __log__.error(
                "you must be connected to a deadchat server to use this function")

    return wrapper


class DeadChatShell(cmd.Cmd):
    """Main shell for the deadchat client"""
    intro = \
        "Welcome to deadchat client shell. Type help or ? to list commands\n"
    prompt = "deadchat>"

    MAX_NAME_LENGTH = 65535

    def __init__(self, config_path: str):
        """Initialize the deadchat client shell"""
        super().__init__()

        self.config_path = config_path
        self.config = ConfigParser()

        self.name = None
        self.id_public_key = None
        self.id_private_key = None

        self.shared_key = None
        self.secretbox = None
        self.boxes = {}

        self.sock = None
        self.connected = False

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
                    return None
        return None

    def preloop(self):
        self.load_config()

    def print_all_packets(self):
        if self.sock:
            while True:
                packet = self.get_packet()
                if packet:
                    self.handle_response(packet)
                else:
                    break

    def precmd(self, line):
        self.print_all_packets()
        return super().precmd(line)

    def postcmd(self, stop, line):
        self.print_all_packets()
        return super().postcmd(stop, line)

    def postloop(self):
        """"""
        if self.connected:
            self.user_disconnect()

    def do_exit(self, arg):
        """exit out of the deadchat client shell"""
        __log__.info("exiting deadchat client shell")
        if self.connected:
            self.user_disconnect()
        return True

    def do_connect(self, arg):
        """Connect to a deadchat server"""
        if self.connected:
            __log__.error("Already connected")
            return
        if not self.name:
            __log__.error("Missing name, set using /createid")
            return
        # TODO: argument argparsing
        host = "localhost"
        port = 6150
        self.user_connect(host, port)
        self.send_packet(Command.ident(self.name))

    @connected
    def do_disconnect(self, arg):
        """Disconnect from a deadchat server"""
        self.user_disconnect()

    @connected
    def do_who(self, arg):
        """Get a list of users connected to the server"""
        self.send_packet(Command.who())

    def do_create_id_key(self, arg):
        """Create your own identity and associated keys"""
        if self.connected:
            __log__.error("Disconnect prior to changing id")
        else:
            self.user_createid(arg)

    @connected
    def do_exchange_id_keys(self, arg):
        """Exchange identity keys with another deadchat user"""
        self.user_idexch(arg)

    def do_create_fs_key(self, arg):
        """Create a secret key for a shared remote filesystem"""
        self.user_genroomkey()

    @connected
    def do_send_fs_key(self, arg):
        """Send a secret key for a shared remote filesystem securely"""
        self.user_sendroomkey(arg)

    @connected
    def do_msg(self, arg):
        """Privately message one user"""
        user, msg = arg.split(" ", 1)
        self.user_msg(user, msg)

    @connected
    def do_msg_all(self, arg):
        """Message all users with the room key"""
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc = self.secretbox.encrypt(arg.encode('utf-8'), nonce)
        self.send_packet(Command.msg_enc_sharekey(enc))

    ###########################################
    ###
    ###########################################

    def save_config(self):
        with open(self.config_path, "w") as configfile:
            self.config.write(configfile)

    def user_disconnect(self):
        self.connected = False
        self.sock.close()
        __log__.info("disconnected from server")

    def user_genroomkey(self):
        self.shared_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self.secretbox = nacl.secret.SecretBox(self.shared_key)
        if not self.config.has_section("room"):
            self.config.add_section("room")
        self.config.set("room", "room_key",
                        base64.b64encode(self.shared_key).decode("utf8"))
        with open(self.config_path, "w") as configfile:
            self.config.write(configfile)
        __log__.info("Room key generated")

    def user_sendroomkey(self, name):
        if self.init_pubkey(name):
            # TODO: look into nonce prefix
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

    def user_connect(self, host: str, port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock = ssl.wrap_socket(
                s,
                # ca_certs = "",
                # cert_reqs=ssl.CERT_REQUIRED
            )
            self.sock.connect((host, port))

            self.connected = True
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

    def user_createid(self, name):
        if len(name) > DeadChatShell.MAX_NAME_LENGTH:
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

    def user_idexch(self, name):
        key = self.id_public_key.encode()
        self.send_packet(Command.msg_req_pubkey(name, key))
        __log__.info("Requested room key from {}".format(name))

    def user_msg(self, name, msg):
        if self.init_pubkey(name):
            nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
            enc = self.boxes[name].encrypt(msg.encode('utf-8'), nonce)
            self.send_packet(Command.msg_enc_pubkey(name.encode('utf8'), enc))
            print("[{} => {}] {}".format(self.name, name, msg))
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
            self.user_disconnect()
        elif resp.type == ResponseCode.NOTICE:
            print("Server notice: {}".format(resp.message))
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

    def svr_msg_request_sharekey(self, sender):
        __log__.info("{} requests the room key".format(sender))

    def svr_msg_send_sharekey(self, sender, data):
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
                print("{} has sent you the room key".format(sender))
                return
            except nacl.exceptions.CryptoError:
                __log__.exception(
                    "error decrypting given room sent from: {}".format(sender))
        __log__.error("Received room key from {} but unable to decrypt, "
                      "run /idexch".format(sender))

    def svr_msg_encrypted_sharekey(self, sender, data):
        nonce = data[0:nacl.secret.SecretBox.NONCE_SIZE]
        enc = data[nacl.secret.SecretBox.NONCE_SIZE:]
        if self.secretbox:
            try:
                msg = self.secretbox.decrypt(enc, nonce)
                print("<{}> {}".format(sender, msg))
                return
            except nacl.exceptions.CryptoError as e:
                __log__.exception("<{}> (ERROR: decrypting message)")
        __log__.error("<{}> (encrypted)".format(sender))

    # Received request for my public key
    def svr_msg_request_pubkey(self, sender, data):
        print("Received id key request from {}".format(sender))

        # store key from sender
        if not self.config.has_section("keys"):
            self.config.add_section("keys")
        self.config.set("keys", sender.decode("utf8"),
                        base64.b64encode(data).decode("utf8"))
        self.save_config()

        # TODO: handle if public_key not set
        key = self.id_public_key.encode()
        self.send_packet(Command.msg_send_pubkey(sender, key))

        # Delete existing box
        if sender in self.boxes:
            self.boxes.pop(sender)

    # Received requested public key from sender
    # TODO: sanitize data
    def svr_msg_send_pubkey(self, sender, data):
        # save key to config file
        if not self.config.has_section("keys"):
            self.config.add_section("keys")
        self.config.set("keys", sender.decode('utf8'),
                        base64.b64encode(data).decode("utf8"))
        self.save_config()
        print("id key exchange with {} complete".format(sender.decode("utf8")))

        # Delete existing box
        if sender in self.boxes:
            self.boxes.pop(sender)

    def svr_msg_encrypted_pubkey(self, sender, data):
        if self.init_pubkey(sender.decode('utf-8')):
            try:
                nonce = data[0:nacl.public.Box.NONCE_SIZE]
                enc = data[nacl.public.Box.NONCE_SIZE:]
                msg = self.boxes[sender.decode('utf8')].decrypt(enc, nonce)
                print("[{} => {}] {}".format(sender, self.name, msg))
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
