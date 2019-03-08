#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""FTP and FTP_TLS clients that wraps all sent files with encryption"""

import base64
import binascii
import ftplib
import os
from ftplib import FTP, FTP_TLS
from io import BytesIO
from logging import getLogger
from pathlib import PurePosixPath
from typing import Tuple, List, Optional, Dict

import nacl.exceptions
import nacl.secret
import nacl.utils

__log__ = getLogger(__name__)


class EncryptedFTP(FTP):
    """Simple wrapper class of :class:`ftplib.FTP` the encrypts both a
    file's name and contents before sending it to the remote FTP server"""

    def __init__(self, enc_key: bytes, **kwargs):
        self.secretbox = nacl.secret.SecretBox(enc_key)
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
            raise

    def path_exists(self, path: str) -> bool:
        """Check whether a decrypted path exists within the encrypted
        filesystem

        :param path: decrypted path to check for existence
        :return: :obj:`True` if the decrypted path exists as an encrypted path,
            otherwise :obj:`False`
        """
        try:
            self.get_pwd_encrypted_path(path)
            return True
        except FileNotFoundError:
            return False

    def get_pwd_encrypted_path(self, path: str) -> str:
        """Attempt to match a decrypted path with a encrypted path within the
        current working directory

        :param path: decrypted path to match with a encrypted path
        :return: encrypted path that decrypts to the given decrypted path
        """
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

    def validate_dir(self, *args) -> List[str]:
        """Validate that all paths within the specified director(y|ies)
        are properly encrypted via deadSFS. If not raise a warning message
        noting the invalid paths.

        :param args: list of directories to validate contained contents
        :return: list of paths that failed validation

        .. note::
            The director(y|ies) to be validated should be specified with their
            encrypted filename.
        """
        nlst_dirs = []
        for nlst_dir in args:
            if self.path_exists(nlst_dir):
                nlst_dir = self.get_pwd_encrypted_path(nlst_dir)
            nlst_dirs.append(nlst_dir)

        raw_paths = super().nlst(*nlst_dirs)
        invalid_paths = []
        for raw_path in raw_paths:
            try:
                dec_path = self.ftp_decrypt(os.path.split(raw_path)[-1])
                # if it is a file and not a dir attempt to download and
                # decrypt its contents
                try:
                    self.readfile(dec_path)
                except ftplib.error_perm:  # path was not a file!
                    self.validate_dir(dec_path)
            except (nacl.exceptions.CryptoError, IndexError,
                    binascii.Error, ValueError):
                __log__.critical("detected non-encrypted or modified "
                                 "file / directory: {}".format(raw_path))
                invalid_paths.append(raw_path)
        return invalid_paths

    def shared_nlst(self, *args) -> Tuple[List[str], List[str]]:
        """List both the decrypted paths and paths that failed to be
        decrypted of files (encrypted or not encrypted) within the
        specified director(y|ies)

        :param args: list of directories to obtain paths from
        :return: list of decrypted paths of encrypted files and list of
            paths that failed to be decrypted of files contained within
            the specified director(y|ies)
        """
        nlst_dirs = []
        for nlst_dir in args:
            if self.path_exists(nlst_dir):
                nlst_dir = self.get_pwd_encrypted_path(nlst_dir)
            nlst_dirs.append(nlst_dir)

        raw_paths = super().nlst(*nlst_dirs)
        decrypted_paths = []
        failed_paths = []
        for raw_path in raw_paths:
            try:
                decrypted_paths.append(self.ftp_decrypt(os.path.split(raw_path)[-1]))
            except (nacl.exceptions.CryptoError, IndexError,
                    binascii.Error, ValueError):
                failed_paths.append(os.path.split(raw_path)[-1])
        return decrypted_paths, failed_paths

    def nlst(self, *args) -> List[str]:
        """List the decrypted paths of encrypted files within the
        specified director(y|ies)

        :param args: list of directories to obtain decrypted paths
            of encrypted files contained within
        :return: list of decrypted paths of encrypted files contained within
            the specified director(y|ies)
        """
        decrypted_files, failed_files = self.shared_nlst(*args)
        return decrypted_files

    def mkd(self, dirname: str):
        """Create a encrypted directory

        :param dirname: decrypted path of the encrypted directory to create
        """
        if self.path_exists(dirname):
            raise FileExistsError(
                "cannot create directory ‘{}’: "
                "File exists".format(dirname))
        return super().mkd(self.ftp_encrypt(dirname))

    def rmd(self, dirname: str):
        """Remove a encrypted directory

        :param dirname: decrypted path of the encrypted directory to remove
        """
        return super().rmd(self.get_pwd_encrypted_path(dirname))

    def decrypt_path(self, path: str) -> str:
        """Decrypt a path component by component

        :param path: encrypted path to decrypt
        :return: the raw-text decrypted path

        .. note::
            This only supports PosixPath types for now.

        .. note::
            Components that cannot be decrypted remain the same and are
            appended to the output path non-less.
        """
        # TODO: Add detection and support for windows paths
        decrypted_path = PurePosixPath()
        for path_comp in PurePosixPath(path).parts:
            try:
                path_comp = self.ftp_decrypt(path_comp)
            except (nacl.exceptions.CryptoError, IndexError,
                    binascii.Error, ValueError):
                pass
            decrypted_path = decrypted_path.joinpath(path_comp)
        return str(decrypted_path)

    def pwd(self):
        """Return the decrypted path of the current working directory

        :return: decrypted path of the current working directory
        """
        return self.decrypt_path(super().pwd())

    def cwd(self, dirname: str):
        """Change the current working directory to the specified decrypted
        path

        :param dirname: decrypted path of the encrypted directory to change to
        """
        # TODO: more elegant solution
        if dirname == "." or dirname == ".." or dirname == "":
            return super().cwd(dirname)
        return super().cwd(self.get_pwd_encrypted_path(dirname))

    def delete(self, filename: str):
        """Delete a encrypted file

        :param filename: decrypted path of the encrypted file
        """
        return super().delete(self.get_pwd_encrypted_path(filename))

    def storefile(self, filename: str, content: str):
        """Encrypt and store a encrypted file

        Encrypt both its path and its contents.

        :param filename: decrypted path of the encrypted file
        :param content: content to encrypt and store within the encrypted file
        """
        if self.path_exists(filename):
            enc_filename = self.get_pwd_encrypted_path(filename)
        else:
            enc_filename = self.ftp_encrypt(filename)
        cmd = "STOR {}".format(enc_filename)

        buf = BytesIO(self.ftp_encrypt(content).encode("utf8"))
        return super().storbinary(cmd, buf)

    def readfile(self, filename: str) -> str:
        """Read and decrypt a encrypted file

        :param filename: decrypted path of the encrypted file
        """
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
        """Rename a encrypted file

        :param fromname: decrypted path of the encrypted file
        :param toname: new decrypted path to rename the encrypted file to
        """
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
        """Return the size of a encrypted file

        :param filename: decrypted path of the encrypted file
        """
        return super().size(self.get_pwd_encrypted_path(filename))

    def chmod(self, chmod_permissions: str, filename: str):
        return super().sendcmd(
            'SITE CHMOD {} {}'.format(
                chmod_permissions,
                self.get_pwd_encrypted_path(filename)
            )
        )


class EncryptedFTPTLS(EncryptedFTP, FTP_TLS):
    """"Subclass of :class:`EncryptedFTP` that supports
    FTP TLS connections"""
