#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Command shell for deadSFS"""

import argparse
import getpass
import ssl
from functools import wraps
from io import BytesIO
from logging import getLogger
from typing import List

import cmd2
from cmd2 import with_argparser, argparse_completer, with_category, \
    with_argparser_and_unknown_args

from dead_sfs.encrypted_ftp import EncryptedFTP, EncryptedFTPTLS

__log__ = getLogger(__name__)


def ftp_connected(f):
    """Annotation to check if that the command shell is connected to a
    FTP server before attempting a FTP command in :class:`DeadSFSShell`"""

    @wraps(f)
    def wrapper(*args):
        if args[0].enc_ftp.sock:
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

    CAT_CONNECTION = "Connection"
    CAT_ENCRYPTED_FTP_COMMANDS = "Encrypted FTP commands"
    CAT_RAW_FTP_COMMANDS = "Raw (non-decrypted) FTP commands"

    def _instance_pwd_file_names(self, _) -> List[str]:
        decrypted_files, failed_files = self.enc_ftp.shared_nlst()
        return decrypted_files + list(map(lambda x: "WARNING: NOT DECRYPTED: {}".format(x),  failed_files))

    filename_parser = argparse_completer.ACArgumentParser()
    filename = filename_parser.add_argument(
        "filename", nargs="?", help="decrypted filename/path")
    setattr(filename, argparse_completer.ACTION_ARG_CHOICES,
            '_instance_pwd_file_names')

    def _instance_pwd_raw_file_names(self) -> List[str]:
        return self.enc_ftp.non_decrypted_ftp.nlst()

    raw_filename_parser = argparse_completer.ACArgumentParser()
    raw_filename = raw_filename_parser.add_argument(
        "raw_filename", nargs="?", help="raw (non-decrypted) filename/path")
    setattr(raw_filename, argparse_completer.ACTION_ARG_CHOICES,
            '_instance_pwd_raw_file_names')

    def __init__(self, enc_key: bytes, tls: bool = False,
                 certfile=None, keyfile=None, cafile=None):
        """Initialize the deadSFS shell

        :param enc_key: The private key used for filename and file encryption
        :param tls: Enable using a FTP TLS connection

        The below parameters are only relevant if ``tls`` is equal
        to :obj:`True`:

        :param certfile: Path to the clients *.pem self-certificate
        :param keyfile: Path to the clients *.pem self-certificate key
        :param cafile: Path the *.pem certificate authority to validate the
            FTP server's connection
        """
        self.allow_cli_args = False
        super().__init__()
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)

            # use TLS_V1_2 only instead of TLS_V1_1, TLS_V1, SSLv2, or SSLv3
            context.options |= ssl.OP_NO_TLSv1
            context.options |= ssl.OP_NO_TLSv1_1
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_SSLv3

            # use a custom self certificate,otherwise, use default certificates
            if certfile and keyfile:
                context.load_cert_chain(certfile=certfile, keyfile=keyfile)
            else:
                context.load_default_certs()

            # enable validating the FTP servers connection with a ca
            if cafile:
                context.load_verify_locations(cafile=cafile)

            self.enc_ftp = EncryptedFTPTLS(enc_key, context=context)
        else:
            self.enc_ftp = EncryptedFTP(enc_key)

    def do_quit(self, _):
        """Exit out of the deadSFS shell

        Close connections for the FTP server if they exist.
        """
        self.enc_ftp.close()
        return super().do_quit(_)

    connect_argparser = argparse.ArgumentParser()
    connect_argparser.add_argument('host', type=str,
                                   help="hostname to connect to")
    connect_argparser.add_argument('port', type=int,
                                   help="port to connect to")

    @with_category(CAT_CONNECTION)
    @with_argparser(connect_argparser)
    def do_connect(self, args):
        """Connect and login into the remote FTP server"""
        print(self.enc_ftp.connect(args.host, args.port))
        username = input("username: ")
        print(self.enc_ftp.login(user=username,
                                 passwd=getpass.getpass()))
        if isinstance(self.enc_ftp, EncryptedFTPTLS):
            self.enc_ftp.prot_p()

        # silently change directory to the users home
        self.enc_ftp.non_decrypted_ftp.cwd(username)
        # validate the integrity of the users home
        self.enc_ftp.validate_dir(".")

    @ftp_connected
    @with_category(CAT_CONNECTION)
    def do_disconnect(self, _):
        """Disconnect from the remote FTP server"""
        print(self.enc_ftp.quit())

    @staticmethod
    def _fix_filename_arg(filename_arg: str) -> str:
        if filename_arg is None or \
                isinstance(filename_arg, str) and not filename_arg.strip():
            return ""
        return filename_arg

    @ftp_connected
    @with_category(CAT_ENCRYPTED_FTP_COMMANDS)
    @with_argparser(filename_parser)
    def do_nlst(self, args):
        """List the contents of the current working directory of the
        remote filesystem"""
        filename = DeadSFSShell._fix_filename_arg(args.filename)
        print(self.enc_ftp.nlst(filename))

    @ftp_connected
    @with_category(CAT_RAW_FTP_COMMANDS)
    @with_argparser(raw_filename_parser)
    def do_raw_nlst(self, args):
        """List the contents of the directory specified by its encrypted
        filename on the remote filesystem"""
        filename = DeadSFSShell._fix_filename_arg(args.raw_filename)
        print(self.enc_ftp.non_decrypted_ftp.nlst(filename))

    @ftp_connected
    @with_category(CAT_ENCRYPTED_FTP_COMMANDS)
    @with_argparser(filename_parser)
    def do_mkd(self, args):
        """Make a sub-directory within the current working directory
        of the remote filesystem"""
        print(self.enc_ftp.mkd(args.filename))

    @ftp_connected
    @with_category(CAT_ENCRYPTED_FTP_COMMANDS)
    @with_argparser(filename_parser)
    def do_rmd(self, args):
        """Remove a directory from the remote filesystem"""
        print(self.enc_ftp.rmd(args.filename))

    @ftp_connected
    @with_category(CAT_RAW_FTP_COMMANDS)
    @with_argparser(raw_filename_parser)
    def do_raw_rmd(self, args):
        """Remove a directory specified by its encrypted filename
        from the remote filesystem"""
        print(self.enc_ftp.non_decrypted_ftp.rmd(args.raw_filename))

    @ftp_connected
    @with_category(CAT_ENCRYPTED_FTP_COMMANDS)
    def do_pwd(self, _):
        """Print the pathname of the current directory on the server"""
        print(self.enc_ftp.pwd())

    @ftp_connected
    @with_category(CAT_RAW_FTP_COMMANDS)
    def do_raw_pwd(self, _):
        """Print the non-decrypted pathname of the current directory
        on the server"""
        print(self.enc_ftp.non_decrypted_ftp.pwd())

    @ftp_connected
    @with_category(CAT_ENCRYPTED_FTP_COMMANDS)
    @with_argparser(filename_parser)
    def do_cwd(self, args):
        """Change the current working directory of the remote filesystem"""
        filename = DeadSFSShell._fix_filename_arg(args.filename)
        print(self.enc_ftp.cwd(filename))

    @ftp_connected
    @with_category(CAT_RAW_FTP_COMMANDS)
    @with_argparser(raw_filename_parser)
    def do_raw_cwd(self, args):
        """Change the current working directory of the remote filesystem
        to the one specified by its encrypted path"""
        filename = DeadSFSShell._fix_filename_arg(args.raw_filename)
        print(self.enc_ftp.non_decrypted_ftp.cwd(filename))

    @ftp_connected
    @with_category(CAT_ENCRYPTED_FTP_COMMANDS)
    def do_wf(self, arg):
        """Encrypt and write a file into the remote filesystem"""
        with open(arg, "r") as f:
            print(self.enc_ftp.storefile(arg, f.read()))

    @ftp_connected
    @with_category(CAT_ENCRYPTED_FTP_COMMANDS)
    @with_argparser(filename_parser)
    def do_rf(self, args):
        """Decrypt, Read, and save in the current working directory a file
        from the remote filesystem"""
        content = self.enc_ftp.readfile(args.filename)
        print("obtained {}'s content:\n{}".format(args.filename, content))
        with open(args.filename, "w") as f:
            f.write(content)

    @ftp_connected
    @with_category(CAT_RAW_FTP_COMMANDS)
    @with_argparser(raw_filename_parser)
    def do_raw_rf(self, args):
        """Read, and save in the current working directory a file
        from the remote filesystem"""
        cmd = "RETR {}".format(args.raw_filename)
        buf = BytesIO()

        def callback(data: bytes):
            buf.write(data)

        self.enc_ftp.non_decrypted_ftp.retrbinary(cmd, callback)
        buf.seek(0)
        content = buf.read().decode("utf-8")
        print("obtained {}'s content:\n{}".format(args.raw_filename, content))
        with open(args.raw_filename, "w") as f:
            f.write(content)

    @ftp_connected
    @with_category(CAT_ENCRYPTED_FTP_COMMANDS)
    @with_argparser(filename_parser)
    def do_rmf(self, args):
        """Delete a file from the remote filesystem"""
        print(self.enc_ftp.delete(args.filename))

    @ftp_connected
    @with_category(CAT_RAW_FTP_COMMANDS)
    @with_argparser(raw_filename_parser)
    def do_raw_rmf(self, args):
        """Delete a file specified by its encrypted filename from the
        remote filesystem without"""
        print(self.enc_ftp.non_decrypted_ftp.delete(args.raw_filename))

    # we have to re-build this manually as we cannot copy argparsers
    # this is a direct limitation of python currently
    rename_filename_parser = argparse_completer.ACArgumentParser()
    rename_filename = rename_filename_parser.add_argument(
        "filename", nargs="?", help="decrypted filename to change")
    setattr(rename_filename, argparse_completer.ACTION_ARG_CHOICES,
            '_instance_pwd_file_names')
    rename_filename_parser.add_argument("new_filename",
                                        help="new decrypted filename")

    @ftp_connected
    @with_category(CAT_ENCRYPTED_FTP_COMMANDS)
    @with_argparser_and_unknown_args(rename_filename_parser)
    def do_rename(self, args):
        """Rename an encrypted file"""
        print(self.enc_ftp.rename(args.filename, args.new_filename))

    @ftp_connected
    @with_category(CAT_ENCRYPTED_FTP_COMMANDS)
    @with_argparser(raw_filename_parser)
    def do_vald(self, args):
        """Validate that all files (including files within nested directories)
        within a specified directory are properly encrypted and not wrongly
        modified on the remote FTP server"""
        filename = DeadSFSShell._fix_filename_arg(args.raw_filename)
        self.enc_ftp.validate_dir(filename)
