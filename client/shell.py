#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""command shell for the deadchat client"""

import cmd
import getpass
from functools import wraps
from logging import getLogger

from client.client import Client
from client.ftp_client import EncryptedFTPClient
from client.packet import Command

__log__ = getLogger(__name__)


def connected(f):
    """Annotation to check if that the command shell is connected to a
    deadchat server before attempting a deadchat command in
    :class:`DeadChatShell`"""
    @wraps(f)
    def wrapper(*args):
        if args[0].client.connected:
            return f(*args)
        else:
            __log__.error(
                "you must be connected to a deadchat server to "
                "use this function"
            )

    return wrapper


def ftp_connected(f):
    """Annotation to check if that the command shell is connected to a
    ftp server before attempting a ftp command in :class:`DeadChatShell`"""
    @wraps(f)
    def wrapper(*args):
        if args[0].ftp.sock:
            return f(*args)
        else:
            __log__.error(
                "you must be connected to a deadchat ftp server to "
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
        self.ftp_client = EncryptedFTPClient(client.secretbox)

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
        self.ftp_client.close()
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
        self.client.exchange_public_id_key(arg)

    def do_create_fs_key(self, arg):
        """Create a secret key for a shared remote filesystem"""
        self.client.create_shared_fs_key()

    @connected
    def do_send_fs_key(self, arg):
        """Send a secret key for a shared remote filesystem securely"""
        self.client.send_shared_fs_key(arg)

    ###############################
    # remote filesystem commands
    ###############################

    def do_ftp_connect(self, arg):
        """Connect and login into the remote FTP server"""
        host, port = arg.split()
        print(self.ftp_client.connect(host, int(port)))
        print(self.ftp_client.login(user=input("username: "), passwd=getpass.getpass()))
        self.ftp_client.set_pasv(True)

    def do_ftp_disconnect(self, arg):
        """Disconnect from the remote FTP server"""
        print(self.ftp_client.quit())

    @ftp_connected
    def do_ls(self, arg):
        """List the contents of the current working directory of the
        remote filesystem"""
        print(self.ftp_client.nlst(arg))

    @ftp_connected
    def do_mkd(self, arg):
        """Make a sub-directory within the current working directory
        of the remote filesystem"""
        print(self.ftp_client.mkd(arg))

    @ftp_connected
    def do_rmd(self, arg):
        """Remove a directory from the remote filesystem"""
        print(self.ftp_client.rmd(arg))

    @ftp_connected
    def do_cwd(self, arg):
        """Change the current working directory of the remote filesystem"""
        print(self.ftp_client.cwd(arg))

    @ftp_connected
    def do_wf(self, arg):
        """Encrypt and write a file into the remote filesystem"""
        with open(arg, "r") as f:
            print(self.ftp_client.storefile(arg, f.read()))

    @ftp_connected
    def do_rf(self, arg):
        """Read and decrypt a file from the remote filesystem"""
        content = self.ftp_client.readfile(arg)
        print("obtained {}'s content:\n{}".format(arg, content))
        with open(arg, "w") as f:
            f.write(content)

    @ftp_connected
    def do_rmf(self, arg):
        """Delete a file from the remote filesystem"""
        print(self.ftp_client.delete(arg))
