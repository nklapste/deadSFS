#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""FTP and FTP_TLS clients that wraps all sent files with encryption"""

import base64
import binascii
import os
from ftplib import FTP, FTP_TLS
from io import BytesIO
from logging import getLogger
from typing import Tuple, List, Optional, Dict

import nacl.exceptions
import nacl.secret
import nacl.utils

__log__ = getLogger(__name__)


class EncryptedFTPClient(FTP):
    """Simple wrapper class of :class:`ftplib.FTP` the encrypts both a
    file's name and contents before sending it to the remote FTP server"""

    def __init__(self, key: bytes, **kwargs):
        self.secretbox = nacl.secret.SecretBox(key)
        super().__init__(**kwargs)
        self.non_decrypted_ftp = super()

    def ftp_encrypt(self, string: str) -> str:
        """Encrypt a string to send to the FTP server"""
        enc_string = self.secretbox.encrypt(string.encode('utf-8'))
        safe_enc_string = base64.urlsafe_b64encode(enc_string).decode("utf-8")
        return safe_enc_string.strip()

    def ftp_decrypt(self, safe_enc_string: str) -> str:
        """Decrypt a string from the FTP server"""
        try:
            enc_string = base64.urlsafe_b64decode(safe_enc_string)
            nonce = enc_string[0:nacl.secret.SecretBox.NONCE_SIZE]
            enc = enc_string[nacl.secret.SecretBox.NONCE_SIZE:]
            string = self.secretbox.decrypt(enc, nonce)
            return string.decode("utf-8")
        except (nacl.exceptions.CryptoError, IndexError,
                binascii.Error, ValueError):
            __log__.critical(
                "detected unauthorized modification of remote filesystem "
                "with FTP message: {}".format(safe_enc_string), exc_info=True)
            raise

    def path_exists(self, path: str) -> bool:
        """Check whether a decrypted path exists within the encrypted
        filesystem"""
        try:
            self.get_pwd_encrypted_path(path)
            return True
        except FileNotFoundError:
            return False

    def get_pwd_encrypted_path(self, path: str) -> str:
        """Attempt to match a decrypted path with a
        encrypted filesystem path"""
        for enc_filename in super().nlst():
            try:
                dec_filename = self.ftp_decrypt(enc_filename)
            except (nacl.exceptions.CryptoError, IndexError,
                    binascii.Error, ValueError):
                continue
            if path == dec_filename:
                return enc_filename
        raise FileNotFoundError(
            "cannot get encrypted path for ‘{}’: "
            "File **likely** does not exist".format(path))

    def map_enc_dec_files(self, *args) -> Dict[str, Optional[str]]:
        enc_dec_map = {}
        for arg in args:
            if self.path_exists(arg):
                file = self.get_pwd_encrypted_path(arg)
                enc_dec_map[file] = arg
            else:
                enc_dec_map[arg] = None
        return enc_dec_map

    def shared_nlst(self, *args) -> Tuple[List[str], List[str]]:
        files = []
        for arg in args:
            if self.path_exists(arg):
                file = self.get_pwd_encrypted_path(arg)
            else:
                file = arg
            files.append(file)

        enc_dirs = super().nlst(*files)

        decrypted_files = []
        failed_files = []
        for dir in enc_dirs:
            try:
                decrypted_files.append(self.ftp_decrypt(os.path.split(dir)[-1]))
            except (nacl.exceptions.CryptoError, IndexError,
                    binascii.Error, ValueError):
                failed_files.append(os.path.split(dir)[-1])
        return decrypted_files, failed_files

    def nlst(self, *args) -> List[str]:
        decrypted_files, failed_files = self.shared_nlst(*args)
        return decrypted_files

    def mkd(self, dirname: str):
        if self.path_exists(dirname):
            raise FileExistsError(
                "cannot create directory ‘{}’: "
                "File exists".format(dirname))
        return super().mkd(self.ftp_encrypt(dirname))

    def rmd(self, dirname: str):
        return super().rmd(self.get_pwd_encrypted_path(dirname))

    def cwd(self, dirname: str):
        # TODO: more elegant solution
        if dirname == "." or dirname == ".." or dirname == "":
            return super().cwd(dirname)
        return super().cwd(self.get_pwd_encrypted_path(dirname))

    def delete(self, filename: str):
        return super().delete(self.get_pwd_encrypted_path(filename))

    def storefile(self, filename: str, content: str):
        if self.path_exists(filename):
            enc_filename = self.get_pwd_encrypted_path(filename)
        else:
            enc_filename = self.ftp_encrypt(filename)
        cmd = "STOR {}".format(enc_filename)

        buf = BytesIO(self.ftp_encrypt(content).encode("utf8"))
        return super().storbinary(cmd, buf)

    def readfile(self, filename: str) -> str:
        enc_filename = self.get_pwd_encrypted_path(filename)
        cmd = "RETR {}".format(enc_filename)
        buf = BytesIO()

        def callback(data: bytes):
            buf.write(data)

        super().retrbinary(cmd, callback)
        buf.seek(0)
        content = self.ftp_decrypt(buf.read().decode("utf-8"))
        return content

    def rename(self, fromname: str, toname: str):
        if not self.path_exists(fromname):
            raise FileNotFoundError(
                "cannot rename file ‘{}’: "
                "File does not exist".format(fromname))

        if self.path_exists(toname):
            raise FileExistsError(
                "cannot rename file ‘{}’ to ‘{}’: "
                "File exists".format(fromname, toname))
        return super().rename(
            self.get_pwd_encrypted_path(fromname),
            self.ftp_encrypt(toname)
        )

    def size(self, filename: str) -> Optional[int]:
        return super().size(self.get_pwd_encrypted_path(filename))

    def chmod(self, chmod_permissions: str, filename: str):
        return super().sendcmd(
            'SITE CHMOD {} {}'.format(
                chmod_permissions,
                self.get_pwd_encrypted_path(filename)
            )
        )


class EncryptedFTPTLSClient(EncryptedFTPClient, FTP_TLS):
    """"Subclass of :class:`EncryptedFTPClient` that supports
    FTP TLS connections"""
