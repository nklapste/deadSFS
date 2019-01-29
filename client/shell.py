#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""command shell for the deadchat client"""

import cmd
import getpass
from ftplib import FTP
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
        if args[0].client.connected:
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
        self.ftp = FTP()

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
        if self.client.connected:
            self.client.close()

    def do_exit(self, arg):
        """exit out of the deadchat client shell"""
        __log__.info("exiting deadchat client shell")
        if self.client.connected:
            self.client.close()
        self.ftp.close()
        return True

    def do_connect(self, arg):
        """Connect to a deadchat server"""
        if self.client.connected:
            __log__.error("Already connected")
            return
        if not self.client.name:
            __log__.error("Missing name, set using `create_id_key`")
            return
        # TODO: argument argparsing
        host = "localhost"
        port = 6150
        self.client.connect(host, port)
        self.client.send_packet(Command.ident(self.client.name))

    @connected
    def do_disconnect(self, arg):
        """Disconnect from a deadchat server"""
        self.client.close()

    @connected
    def do_who(self, arg):
        """Get a list of users connected to the server"""
        self.client.send_packet(Command.who())

    def do_create_id_key(self, arg):
        """Create your own identity and associated keys"""
        if self.client.connected:
            __log__.error("Disconnect prior to changing id")
        else:
            self.client.create_id_key(arg)

    @connected
    def do_exchange_id_keys(self, arg):
        """Exchange identity keys with another deadchat user"""
        self.client.exchange_id_key(arg)

    def do_create_fs_key(self, arg):
        """Create a secret key for a shared remote filesystem"""
        self.client.create_room_key()

    @connected
    def do_send_fs_key(self, arg):
        """Send a secret key for a shared remote filesystem securely"""
        self.client.send_room_key(arg)

    @connected
    def do_msg(self, arg):
        """Privately message one user"""
        user, msg = arg.split(" ", 1)
        self.client.message(user, msg)

    @connected
    def do_msg_all(self, arg):
        """Message all users with the room key"""
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc = self.client.secretbox.encrypt(arg.encode('utf-8'), nonce)
        self.client.send_packet(Command.msg_enc_sharekey(enc))

    ###############################
    # remote filesystem commands
    ###############################
    def do_ftp_connect(self, arg):
        """"""
        host, port = arg.split()
        print(self.ftp.connect(host, int(port)))

    def do_ftp_login(self, arg):
        print(self.ftp.login(user=input("username: "), passwd=getpass.getpass()))
        self.ftp.set_pasv(True)

    def do_ftp_disconnect(self, arg):
        """Disconnect from the remote FTP connection"""
        print(self.ftp.quit())

    def do_list_dir(self, arg):
        """List the contents of the current working directory of the
        remote filesystem"""
        # # TODO: refine
        # nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        # enc = self.client.secretbox.encrypt(arg.encode('utf-8'), nonce)
        # self.client.send_packet(Command.list_dir(enc))

        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc = self.client.secretbox.encrypt(arg.encode('utf-8'), nonce)
        import base64
        if arg == "" or arg is None:
            enc_dirs = self.ftp.nlst()
        else:
            enc_dir = base64.urlsafe_b64encode(enc).decode("utf-8")
            enc_dirs = self.ftp.nlst(enc_dir)
        import base64
        for enc_dir in enc_dirs:
            try:
                data = base64.urlsafe_b64decode(enc_dir)
                nonce = data[0:nacl.secret.SecretBox.NONCE_SIZE]
                enc = data[nacl.secret.SecretBox.NONCE_SIZE:]
                msg = self.client.secretbox.decrypt(enc, nonce)
                print(msg.decode("utf8"))
            except nacl.exceptions.ValueError:
                __log__.exception("failed to decrypt folder")
                print(enc_dir)

    def do_make_dir(self, arg):
        """Make a directory with the specified name within the current working
        directory of the remote filesystem"""
        # TODO: refine
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc = self.client.secretbox.encrypt(arg.encode('utf-8'), nonce)
        import base64
        enc_dir = base64.urlsafe_b64encode(enc).decode("utf-8")
        print(enc_dir.strip())
        # self.client.send_packet(Command.make_dir(enc))
        print(self.ftp.mkd(enc_dir.strip()))

    @connected
    def do_delete_dir(self, arg):
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc = self.client.secretbox.encrypt(arg.encode('utf-8'), nonce)
        self.client.send_packet(Command.delete_dir(enc))

    @connected
    def do_change_dir(self, arg):
        """Change the current working directory of the remote filesystem"""
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc = self.client.secretbox.encrypt(arg.encode('utf-8'), nonce)
        self.client.send_packet(Command.change_dir(enc))

    @connected
    def do_write_file(self, arg):
        # TODO: refine
        filename, content = arg.split(" ", 1)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc_filename = self.client.secretbox.encrypt(filename.encode('utf-8'), nonce)
        enc_content = self.client.secretbox.encrypt(content.encode('utf-8'), nonce)
        self.client.send_packet(Command.write_file(enc_filename, enc_content))

    @connected
    def do_read_file(self, arg):
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc = self.client.secretbox.encrypt(arg.encode('utf-8'), nonce)
        self.client.send_packet(Command.read_file(enc))

    @connected
    def do_delete_file(self, arg):
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc = self.client.secretbox.encrypt(arg.encode('utf-8'), nonce)
        self.client.send_packet(Command.delete_file(enc))


