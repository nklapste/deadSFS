#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""FTP client that wraps all sent/given files with an encryption"""

import base64
import binascii
from ftplib import FTP
from io import BytesIO
from logging import getLogger

import nacl.exceptions
import nacl.secret
import nacl.utils

__log__ = getLogger(__name__)


class EncryptedFTPClient(FTP):
    """Simple wrapper class of :class:`ftplib.FTP` the encrypts both a
    file's name and contents before sending it to the remote FTP server"""

    def __init__(self, secretbox: nacl.secret.SecretBox, **kwargs):
        self.secretbox = secretbox
        FTP.__init__(self, **kwargs)

    def ftp_encrypt(self, string: str) -> str:
        """Encrypt a string for usage in the FTP server using the shared room
        key obtained from the deadchat client"""
        enc_string = self.secretbox.encrypt(string.encode('utf-8'))
        safe_enc_string = base64.urlsafe_b64encode(enc_string).decode("utf-8")
        return safe_enc_string.strip()

    def ftp_decrypt(self, safe_enc_string: str) -> str:
        """Decrypt a string form the FTP server using the shared room
        key obtained from the deadchat client"""
        try:
            enc_string = base64.urlsafe_b64decode(safe_enc_string)
            nonce = enc_string[0:nacl.secret.SecretBox.NONCE_SIZE]
            enc = enc_string[nacl.secret.SecretBox.NONCE_SIZE:]
            string = self.secretbox.decrypt(enc, nonce)
            __log__.info("decrypted FTP message: {}".format(string))
            return string.decode("utf-8")
        except (nacl.exceptions.CryptoError, IndexError,
                binascii.Error, ValueError):
            __log__.exception(
                "detected unauthorized modification of remote filesystem "
                "with FTP message: {}".format(safe_enc_string))
            raise

    def path_exists(self, path: str):
        """Check whether a decrypted path exists within the encrypted
        filesystem"""
        try:
            self.get_pwd_encrypted_path(path)
            return True
        except FileNotFoundError:
            return False

    def get_pwd_encrypted_path(self, path: str):
        """Attempt to match a decrypted path with a
        encrypted filesystem path"""
        for enc_filename in super().nlst():
            dec_filename = self.ftp_decrypt(enc_filename)
            if path == dec_filename:
                __log__.info("found match for name: {} -> {}".format(
                    path, enc_filename))
                return enc_filename
        raise FileNotFoundError("path: {} does not exist in PWD".format(path))

    def nlst(self, dirname: str = None, *args):
        # TODO: some better solution to deal with relative paths
        if dirname == "" or dirname == "." or dirname is None:
            enc_dirs = super().nlst(*args)
        else:
            enc_dirs = super().nlst(self.ftp_encrypt(dirname), *args)
        return list(map(self.ftp_decrypt, enc_dirs))

    def mkd(self, dirname: str):
        if self.path_exists(dirname):
            raise FileExistsError(
                "cannot create directory ‘{}’: File exists".format(dirname))
        return super().mkd(self.ftp_encrypt(dirname))

    def rmd(self, dirname: str):
        return super().rmd(self.get_pwd_encrypted_path(dirname))

    def cwd(self, dirname: str):
        if dirname == "." or dirname == ".." or dirname == "":  # TODO: more elegant solution
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

    def readfile(self, filename: str):
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
        if self.path_exists(fromname):
            if self.path_exists(toname):
                raise FileExistsError(
                    "cannot rename file ‘{}’ to ‘{}’: File exists".format(
                        fromname, toname))
            super().rename(self.get_pwd_encrypted_path(fromname), self.ftp_encrypt(toname))
        else:
            raise FileNotFoundError(
                "cannot rename file ‘{}’: File does not exist".format(
                    fromname))

    def size(self, filename: str):
        return super().size(self.get_pwd_encrypted_path(filename))

    def chmod(self, chmod_permissions: str, filename: str):
        super().sendcmd(
            'SITE CHMOD {} {}'.format(
                chmod_permissions,
                self.get_pwd_encrypted_path(filename)
            )
        )
