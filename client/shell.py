#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""command shell for the deadchat client"""

import cmd
from logging import getLogger

import nacl
import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.utils

from client.client import Client
from client.packet import Command

__log__ = getLogger(__name__)


def connected(f):
    """Annotation to check if someone is connected before attempting a
    command in :class:`DeadChatShell`"""

    def wrapper(*args):
        if args[0].connected:
            return f(*args)
        else:
            __log__.error(
                "you must be connected to a deadchat server to "
                "use this function"
            )

    return wrapper


class DeadChatShell(cmd.Cmd):
    """Main shell for the deadchat client"""
    intro = "Welcome to deadchat client shell. " \
            "Type help or ? to list commands"
    prompt = "deadchat>"

    def __init__(self, client: Client):
        """Initialize the deadchat client shell"""
        super().__init__()

        self.client = client
        self.connected = False

    def preloop(self):
        self.client.load_config()

    def print_all_packets(self):
        if self.client.sock:
            while True:
                packet = self.client.get_packet()
                if packet:
                    self.client.handle_response(packet)
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
            self.client.close()

    def do_exit(self, arg):
        """exit out of the deadchat client shell"""
        __log__.info("exiting deadchat client shell")
        if self.connected:
            self.client.close()
        return True

    def do_connect(self, arg):
        """Connect to a deadchat server"""
        if self.connected:
            __log__.error("Already connected")
            return
        if not self.client.name:
            __log__.error("Missing name, set using `create_id_key`")
            return
        # TODO: argument argparsing
        host = "localhost"
        port = 6150
        self.client.user_connect(host, port)
        self.client.send_packet(Command.ident(self.client.name))
        self.connected = True

    @connected
    def do_disconnect(self, arg):
        """Disconnect from a deadchat server"""
        self.client.close()
        self.connected = False

    @connected
    def do_who(self, arg):
        """Get a list of users connected to the server"""
        self.client.send_packet(Command.who())

    def do_create_id_key(self, arg):
        """Create your own identity and associated keys"""
        if self.connected:
            __log__.error("Disconnect prior to changing id")
        else:
            self.client.user_createid(arg)

    @connected
    def do_exchange_id_keys(self, arg):
        """Exchange identity keys with another deadchat user"""
        self.client.user_idexch(arg)

    def do_create_fs_key(self, arg):
        """Create a secret key for a shared remote filesystem"""
        self.client.user_genroomkey()

    @connected
    def do_send_fs_key(self, arg):
        """Send a secret key for a shared remote filesystem securely"""
        self.client.user_sendroomkey(arg)

    @connected
    def do_msg(self, arg):
        """Privately message one user"""
        user, msg = arg.split(" ", 1)
        self.client.user_msg(user, msg)

    @connected
    def do_msg_all(self, arg):
        """Message all users with the room key"""
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc = self.client.secretbox.encrypt(arg.encode('utf-8'), nonce)
        self.client.send_packet(Command.msg_enc_sharekey(enc))
