#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""command shell for deadSFS"""

import cmd2
import getpass
from io import BytesIO
from functools import wraps
from logging import getLogger

from dead_sfs.ftp_client import EncryptedFTPClient, EncryptedFTPTLSClient

__log__ = getLogger(__name__)


def ftp_connected(f):
    """Annotation to check if that the command shell is connected to a
    FTP server before attempting a FTP command in :class:`DeadSFSShell`"""

    @wraps(f)
    def wrapper(*args):
        if args[0].ftp_client.sock:
            return f(*args)
        __log__.error(
            "you must be connected to a deadSFS ftp server to "
            "use this function"
        )

    return wrapper


class DeadSFSShell(cmd2.Cmd):
    """Main shell for deadSFS"""

    intro = "Welcome to deadSFS shell. Type help or ? to list commands"
    prompt = "deadSFS>"

    def __init__(self, key: bytes, tls: bool = False):
        """Initialize the deadSFS shell"""
        self.allow_cli_args = False
        super().__init__()
        if tls:
            self.ftp_client = EncryptedFTPTLSClient(key)
        else:
            self.ftp_client = EncryptedFTPClient(key)

    def do_quit(self, _):
        """Exit out of the deadSFS shell

        Close connections for the FTP server if they exist.
        """
        self.ftp_client.close()
        return super().do_quit(_)

    def do_connect(self, arg):
        """Connect and login into the remote FTP server"""
        host, port = arg.split()
        print(self.ftp_client.connect(host, int(port)))
        print(self.ftp_client.login(user=input("username: "),
                                    passwd=getpass.getpass()))
        self.ftp_client.set_pasv(True)
        if isinstance(self.ftp_client, EncryptedFTPTLSClient):
            self.ftp_client.prot_p()

    @ftp_connected
    def do_disconnect(self, _):
        """Disconnect from the remote FTP server"""
        print(self.ftp_client.quit())

    @ftp_connected
    def do_nlst(self, arg):
        """List the contents of the current working directory of the
        remote filesystem"""
        print(self.ftp_client.nlst(arg))

    @ftp_connected
    def do_raw_nlst(self, arg):
        """List the contents of the directory specified by its encrypted
        filename on the remote filesystem"""
        print(self.ftp_client.unecrypted_ftp.nlst(arg))

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
    def do_raw_rmd(self, arg):
        """Remove a directory specified by its encrypted filename
        from the remote filesystem"""
        print(self.ftp_client.unecrypted_ftp.rmd(arg))

    @ftp_connected
    def do_cwd(self, arg):
        """Change the current working directory of the remote filesystem"""
        print(self.ftp_client.cwd(arg))

    @ftp_connected
    def do_raw_cwd(self, arg):
        """Change the current working directory of the remote filesystem
        to the one specified by its encrypted path"""
        print(self.ftp_client.unecrypted_ftp.cwd(arg))

    @ftp_connected
    def do_wf(self, arg):
        """Encrypt and write a file into the remote filesystem"""
        with open(arg, "r") as f:
            print(self.ftp_client.storefile(arg, f.read()))

    @ftp_connected
    def do_rf(self, arg):
        """Decrypt, Read, and save in the current working directory a file
        from the remote filesystem"""
        content = self.ftp_client.readfile(arg)
        print("obtained {}'s content:\n{}".format(arg, content))
        with open(arg, "w") as f:
            f.write(content)

    @ftp_connected
    def do_raw_rf(self, arg):
        """Read, and save in the current working directory a file
        from the remote filesystem"""
        cmd = "RETR {}".format(arg)
        buf = BytesIO()

        def callback(data: bytes):
            buf.write(data)

        self.ftp_client.unecrypted_ftp.retrbinary(cmd, callback)
        buf.seek(0)
        content = buf.read().decode("utf-8")
        print("obtained {}'s content:\n{}".format(arg, content))
        with open(arg, "w") as f:
            f.write(content)

    @ftp_connected
    def do_rmf(self, arg):
        """Delete a file from the remote filesystem"""
        print(self.ftp_client.delete(arg))

    @ftp_connected
    def do_raw_rmf(self, arg):
        """Delete a file specified by its encrypted filename from the
        remote filesystem without"""
        print(self.ftp_client.unecrypted_ftp.delete(arg))
