#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""command shell for deadSFS"""

import cmd
import getpass
from functools import wraps
from logging import getLogger

from dead_sfs.ftp_client import EncryptedFTPClient

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


class DeadSFSShell(cmd.Cmd):
    """Main shell for deadSFS"""

    intro = "Welcome to deadSFS shell. Type help or ? to list commands"
    prompt = "deadSFS>"

    def __init__(self, key: bytes):
        """Initialize the deadSFS shell"""
        super().__init__()
        self.ftp_client = EncryptedFTPClient(key)
    
    def do_exit(self, _):
        """Exit out of the deadSFS shell

        Close connections from the both the deadSFS server and FTP server
        if they exist.
        """
        __log__.info("exiting deadSFS shell")
        self.ftp_client.close()
        return True

    def do_ftp_connect(self, arg):
        """Connect and login into the remote FTP server"""
        host, port = arg.split()
        print(self.ftp_client.connect(host, int(port)))
        print(self.ftp_client.login(user=input("username: "),
                                    passwd=getpass.getpass()))
        self.ftp_client.set_pasv(True)

    @ftp_connected
    def do_ftp_disconnect(self, _):
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
