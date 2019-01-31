#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pytests for :class:`client.ftp_client`"""

import base64
import io
from ftplib import FTP
from unittest.mock import patch

import nacl
import nacl.exceptions
import nacl.secret
import nacl.utils
import pytest

from client.ftp_client import EncryptedFTPClient


@pytest.fixture(scope='session')
def secretbox():
    shared_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    secretbox = nacl.secret.SecretBox(shared_key)
    return secretbox


@patch('ftplib.FTP.__init__', autospec=True)
def test_construction_file(mock_ftp_constructor, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    mock_ftp_constructor.assert_called_with(ftp_client)


def test_ftp_encrypt(secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    enc = ftp_client.ftp_encrypt("nonsuch")
    assert isinstance(enc, str)
    assert enc != "nonsuch"
    assert len(enc) > len("nonsuch")


def test_ftp_decrypt(secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    enc = ftp_client.ftp_encrypt("nonsuch")
    assert isinstance(enc, str)
    assert enc != "nonsuch"
    assert len(enc) > len("nonsuch")
    dec = ftp_client.ftp_decrypt(enc)
    assert dec == "nonsuch"


def test_ftp_decrypt_modified(secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    enc = ftp_client.ftp_encrypt("nonsuch")
    enc_raw = base64.urlsafe_b64decode(enc)
    bad_enc_raw = enc_raw + b"tampering"
    bad_enc = base64.urlsafe_b64encode(bad_enc_raw).decode("utf-8")

    with pytest.raises(nacl.exceptions.CryptoError):
        ftp_client.ftp_decrypt(bad_enc)


def test_get_pwd_encrypted_path(secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst",
                      return_value=[return_value]) as mock_ftp_nlst:
        ftp_client.get_pwd_encrypted_path("test_file")
        mock_ftp_nlst.assert_called_once()
        mock_ftp_nlst.assert_called_with()


def test_get_pwd_encrypted_path_nonsuch(secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.get_pwd_encrypted_path("test_dir")
        mock_ftp_nlst.assert_called_once()
        mock_ftp_nlst.assert_called_with()


@patch("ftplib.FTP.cwd")
def test_cwd_backdir(mock_ftp_cwd, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    ftp_client.cwd("..")
    mock_ftp_cwd.assert_called_with("..")
    ftp_client.cwd(".")
    mock_ftp_cwd.assert_called_with(".")
    ftp_client.cwd("")
    mock_ftp_cwd.assert_called_with("")


@patch("ftplib.FTP.cwd")
def test_cwd_valid_dir(mock_ftp_cwd, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    return_value = ftp_client.ftp_encrypt("test_dir")
    with patch.object(FTP, "nlst",
                      return_value=[return_value]) as mock_ftp_nlst:
        ftp_client.cwd("test_dir")
        mock_ftp_nlst.assert_called_once()
        mock_ftp_cwd.assert_called_with(return_value)
        assert mock_ftp_cwd.call_args[0][0] != 'test_dir'
        assert ftp_client.ftp_decrypt(mock_ftp_cwd.call_args[0][0]) == \
               'test_dir'


@patch("ftplib.FTP.rmd")
def test_rmd(mock_ftp_rmd, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)

    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst",
                      return_value=[return_value]) as mock_ftp_nlst:
        ftp_client.rmd("test_file")
        mock_ftp_nlst.assert_called_once()
        mock_ftp_rmd.assert_called_once()
        assert mock_ftp_rmd.call_args[0][0] != 'test_dir'
        assert ftp_client.ftp_decrypt(mock_ftp_rmd.call_args[0][0]) == \
               'test_file'


@patch("ftplib.FTP.rmd")
def test_rmd_nonsuch(mock_ftp_rmd, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.rmd("nonsuch")
        mock_ftp_nlst.assert_called_once()
        mock_ftp_rmd.assert_not_called()


@patch("ftplib.FTP.mkd")
def test_mkd(mock_ftp_mkd, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    return_value = ftp_client.ftp_encrypt("test_dir")
    with patch.object(FTP, "nlst",
                      return_value=[return_value]) as mock_ftp_nlst:
        with pytest.raises(FileExistsError):
            ftp_client.mkd("test_dir")
        mock_ftp_nlst.assert_called_once()
        mock_ftp_mkd.assert_not_called()


@patch("ftplib.FTP.mkd")
def test_mkd_nonsuch(mock_ftp_mkd, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        ftp_client.mkd("test_dir")
        mock_ftp_nlst.assert_called_once()
        mock_ftp_mkd.assert_called_once()
        assert mock_ftp_mkd.call_args[0][0] != "test_dir"
        assert ftp_client.ftp_decrypt(mock_ftp_mkd.call_args[0][0]) == \
               'test_dir'


@patch("ftplib.FTP.delete")
def test_delete_nonsuch(mock_ftp_delete, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.delete("nonsuch")
        mock_ftp_nlst.assert_called_once()
        mock_ftp_delete.assert_not_called()


@patch("ftplib.FTP.delete")
def test_delete(mock_ftp_delete, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst",
                      return_value=[return_value]) as mock_ftp_nlst:
        ftp_client.delete("test_file")
        mock_ftp_nlst.assert_called_once()
        mock_ftp_delete.assert_called_once()
        assert mock_ftp_delete.call_args[0][0] != "test_file"
        assert ftp_client.ftp_decrypt(mock_ftp_delete.call_args[0][0]) == \
               'test_file'


def test_nlst_current_dir(secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        assert ftp_client.nlst(".") == []
        mock_ftp_nlst.assert_called_with()
        assert ftp_client.nlst("") == []
        mock_ftp_nlst.assert_called_with()
        assert ftp_client.nlst(None) == []
        mock_ftp_nlst.assert_called_with()
        assert ftp_client.nlst() == []
        mock_ftp_nlst.assert_called_with()


def test_nlst_dir(secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    return_value = ftp_client.ftp_encrypt("test_dir")
    with patch.object(FTP, "nlst",
                      return_value=[return_value]) as mock_ftp_nlst:
        assert ftp_client.nlst("test_dir") == ["test_dir"]
        mock_ftp_nlst.assert_called_once()
        assert mock_ftp_nlst.call_args[0][0] != "test_dir"
        assert ftp_client.ftp_decrypt(mock_ftp_nlst.call_args[0][0]) == \
               'test_dir'


@patch("ftplib.FTP.storbinary")
def test_ftp_storefile_not_exists(mock_ftp_storbinary, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        ftp_client.storefile('test_file', "test_content")
    mock_ftp_nlst.assert_called_once()
    mock_ftp_storbinary.assert_called_once()
    assert mock_ftp_storbinary.call_args[0][0] != "test_file"
    assert ftp_client.ftp_decrypt(mock_ftp_storbinary.call_args[0][0][5:]) == \
           'test_file'


@patch("ftplib.FTP.storbinary")
def test_ftp_storefile_exists(mock_ftp_storbinary, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst",
                      return_value=[return_value]) as mock_ftp_nlst:
        ftp_client.storefile('test_file', "test_content")
    mock_ftp_nlst.assert_called()
    mock_ftp_storbinary.assert_called_once()
    assert mock_ftp_storbinary.call_args[0][0] != "test_file"
    assert ftp_client.ftp_decrypt(mock_ftp_storbinary.call_args[0][0][5:]) == \
           'test_file'


def test_ftp_readfile(secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    retrbinary_return_value = ftp_client.ftp_encrypt("test_content")

    # mocking BytesIO can be a pain
    class MockBytesIO(io.BytesIO):
        def __init__(self):
            super().__init__()

        def write(self, b):
            pass

        def seek(self, pos, **kwargs):
            pass

        def read(self, **kwargs):
            return retrbinary_return_value.encode("utf-8")

    with patch.object(FTP, "retrbinary",
                      return_value=retrbinary_return_value) as mock_retrbinary:
        with patch("client.ftp_client.BytesIO",
                   return_value=MockBytesIO()) as mock_bytes_io:
            nlst_return_value = ftp_client.ftp_encrypt("test_file")
            with patch.object(FTP, "nlst", return_value=[
                nlst_return_value]) as mock_ftp_nlst:
                ftp_client.readfile("test_file")
                mock_retrbinary.assert_called_once()
                assert "test_file" not in mock_retrbinary.call_args[0][0]
                assert ftp_client.ftp_decrypt(
                    mock_retrbinary.call_args[0][0][5:]) == \
                       'test_file'
                mock_ftp_nlst.assert_called_once()


@patch("ftplib.FTP.rename")
def test_rename_nonsuch(mock_ftp_rename, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.rename("test_file_1", "test_file_2")
        mock_ftp_rename.assert_not_called()
        mock_ftp_nlst.assert_called()


@patch("ftplib.FTP.rename")
def test_rename_collision(mock_ftp_rename, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    return_value_1 = ftp_client.ftp_encrypt("test_file_1")
    return_value_2 = ftp_client.ftp_encrypt("test_file_2")
    with patch.object(FTP, "nlst", return_value=[return_value_1, return_value_2]) as mock_ftp_nlst:
        with pytest.raises(FileExistsError):
            ftp_client.rename("test_file_1", "test_file_2")
        mock_ftp_rename.assert_not_called()
        mock_ftp_nlst.assert_called()


@patch("ftplib.FTP.rename")
def test_rename(mock_ftp_rename, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    return_value_1 = ftp_client.ftp_encrypt("test_file_1")
    with patch.object(FTP, "nlst", return_value=[return_value_1]) as mock_ftp_nlst:
        ftp_client.rename("test_file_1", "test_file_2")
        mock_ftp_rename.assert_called_once()
        assert "test_file_1" not in mock_ftp_rename.call_args[0][0]
        assert ftp_client.ftp_decrypt(
            mock_ftp_rename.call_args[0][0]) == \
               'test_file_1'
        assert "test_file_2" not in mock_ftp_rename.call_args[0][0]
        assert ftp_client.ftp_decrypt(
            mock_ftp_rename.call_args[0][1]) == \
               'test_file_2'
        mock_ftp_nlst.assert_called()


@patch("ftplib.FTP.size")
def test_size_nonsuch(mock_ftp_size, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst", return_value=[return_value]) as mock_ftp_nlst:
        ftp_client.size("test_file")
        mock_ftp_size.assert_called_once()
        assert "test_file" not in mock_ftp_size.call_args[0][0]
        assert ftp_client.ftp_decrypt(
            mock_ftp_size.call_args[0][0]) == \
               'test_file'
        mock_ftp_nlst.assert_called_once()

@patch("ftplib.FTP.size")
def test_size_nonsuch(mock_ftp_size, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.size("test_file")
        mock_ftp_size.assert_not_called()
        mock_ftp_nlst.assert_called_once()


@patch("ftplib.FTP.sendcmd")
def test_chmod(mock_ftp_sendcmd, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst", return_value=[return_value]) as mock_ftp_nlst:
        ftp_client.chmod('644', "test_file")
        mock_ftp_sendcmd.assert_called_once()
        assert "test_file" not in mock_ftp_sendcmd.call_args[0][0]
        assert ftp_client.ftp_decrypt(
            mock_ftp_sendcmd.call_args[0][0][15:]) == \
               'test_file'
        mock_ftp_nlst.assert_called_once()


@patch("ftplib.FTP.sendcmd")
def test_chmod_nonsuch(mock_ftp_sendcmd, secretbox):
    ftp_client = EncryptedFTPClient(secretbox)
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.chmod("644", "test_file")
        mock_ftp_sendcmd.assert_not_called()
        mock_ftp_nlst.assert_called_once()
