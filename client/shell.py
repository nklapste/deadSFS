#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""command shell for the deadchat client"""
import base64
import cmd
import getpass
import hashlib
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
        """Connect to the remote FTP server"""
        host, port = arg.split()
        print(self.ftp.connect(host, int(port)))

    def do_ftp_login(self, arg):
        """Login to the remote FTP server"""
        print(self.ftp.login(user=input("username: "), passwd=getpass.getpass()))
        self.ftp.set_pasv(True)

    def do_ftp_disconnect(self, arg):
        """Disconnect from the remote FTP server"""
        print(self.ftp.quit())

    def ftp_encrypt(self, string: str) -> str:
        """Encrypt a string for usage in the FTP server using the shared room
        key obtained from the deadchat client"""
        import hashlib
        sha = hashlib.new("sha256")
        sha.update(string.encode("utf-8"))
        hash = sha.hexdigest()
        base_content = "{}{}".format(hash, string)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        enc_string = self.client.secretbox.encrypt(base_content.encode('utf-8'), nonce)
        safe_enc_string = base64.urlsafe_b64encode(enc_string).decode("utf-8")
        return safe_enc_string.strip()

    def ftp_decrypt(self, safe_enc_string: str) -> str:
        """Decrypt a string form the FTP server using the shared room
        key obtained from the deadchat client"""
        try:
            enc_string = base64.urlsafe_b64decode(safe_enc_string)
            nonce = enc_string[0:nacl.secret.SecretBox.NONCE_SIZE]
            enc = enc_string[nacl.secret.SecretBox.NONCE_SIZE:]
            base_content = self.client.secretbox.decrypt(enc, nonce)
            given_hash = base_content[0:64].decode("utf-8")
            string = base_content[64:]
            # validate
            sha = hashlib.new("sha256")
            sha.update(string.decode("utf8").encode("utf-8"))
            computed_hash = sha.hexdigest()
            if computed_hash == given_hash:
                __log__.info("decrypted FTP message: {}".format(string))
                return string.decode("utf-8")
            else:
                __log__.error(
                    "checksum error given hash:{} computed hash: {}".format(
                        given_hash, computed_hash))
        except Exception:
            __log__.exception(
                "failed to decrypt FTP message: {}".format(safe_enc_string))
        __log__.warning("detected unauthorized modification of "
                        "remote filesystem")
        return safe_enc_string

    def get_pwd_encrypted_path(self, path: str):
        enc_filenames = self.ftp.nlst()
        for enc_filename in enc_filenames:
            dec_filename = self.ftp_decrypt(enc_filename)
            if path == dec_filename:
                __log__.info("found match for name: {} -> {}".format(
                    path, enc_filename))
                return enc_filename
        else:
            raise FileNotFoundError(
                "path: {} does not exist within PWD".format(path))

    def do_list_dir(self, arg):
        """List the contents of the current working directory of the
        remote filesystem"""
        if arg == "" or arg is None:
            enc_dirs = self.ftp.nlst()
        else:
            enc_dirs = self.ftp.nlst(self.ftp_encrypt(arg))
        for enc_dir in enc_dirs:
            print(self.ftp_decrypt(enc_dir))

    def do_make_dir(self, arg):
        """Make a directory with the specified name within the current working
        directory of the remote filesystem"""
        print(self.ftp.mkd(self.ftp_encrypt(arg)))

    def do_delete_dir(self, arg):
        print(self.ftp.rmd(self.get_pwd_encrypted_path(arg)))

    def do_change_dir(self, arg):
        """Change the current working directory of the remote filesystem"""
        if arg == "..":  # TODO: more elegant solution
            print(self.ftp.cwd(arg))
        else:
            print(self.ftp.cwd(self.get_pwd_encrypted_path(arg)))

    def do_write_file(self, arg):
        try:
            enc_filename = self.get_pwd_encrypted_path(arg)
        except FileNotFoundError:
            enc_filename = self.ftp_encrypt(arg)
        cmd = "STOR {}".format(enc_filename)
        with open(arg, "r") as f:
            import io
            buf = io.BytesIO(self.ftp_encrypt(f.read()).encode("utf8"))
            print(self.ftp.storbinary(cmd, buf))

    def do_read_file(self, arg):
        enc_filename = self.get_pwd_encrypted_path(arg)
        cmd = "RETR {}".format(enc_filename)
        f = open("tempcrypt", "w")

        def callback(data: bytes):
            f.write(data.decode("utf-8"))
        self.ftp.retrbinary(cmd, callback)
        f.close()
        f = open("tempcrypt", "rb")
        content = self.ftp_decrypt(f.read().decode("utf-8"))
        print("obtained {}'s content:\n{}".format(arg, content))
        with open(arg, "w") as f:
            f.write(content)

    def do_delete_file(self, arg):
        print(self.ftp.delete(self.get_pwd_encrypted_path(arg)))
