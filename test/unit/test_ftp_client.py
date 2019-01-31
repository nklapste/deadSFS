#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pytests for :class:`dead_sfs.ftp_client`"""

import base64
import io
from ftplib import FTP
from unittest.mock import patch

import nacl
import nacl.exceptions
import nacl.secret
import nacl.utils
import pytest

from dead_sfs.ftp_client import EncryptedFTPClient


@pytest.fixture(scope='session')
def secret_key():
    return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)


@patch('ftplib.FTP.__init__', autospec=True)
def test_construction_file(mock_ftp_constructor, secret_key):
    ftp_client = EncryptedFTPClient(secret_key)
    assert ftp_client
    assert isinstance(ftp_client, EncryptedFTPClient)
    assert ftp_client.secretbox
    assert isinstance(ftp_client.secretbox, nacl.secret.SecretBox)
    mock_ftp_constructor.assert_called_once_with(ftp_client)


@pytest.fixture(scope="session")
def ftp_client(secret_key):
    return EncryptedFTPClient(secret_key)


def test_ftp_encrypt(ftp_client):
    enc = ftp_client.ftp_encrypt("test_file")
    assert isinstance(enc, str)
    assert enc != "test_file"
    assert len(enc) > len("test_file")


def test_ftp_decrypt(ftp_client):
    enc = ftp_client.ftp_encrypt("test_file")
    assert isinstance(enc, str)
    assert enc != "test_file"
    assert len(enc) > len("test_file")
    dec = ftp_client.ftp_decrypt(enc)
    assert dec == "test_file"


def test_ftp_decrypt_modified(secret_key):
    ftp_client = EncryptedFTPClient(secret_key)
    enc = ftp_client.ftp_encrypt("nonsuch")

    # tamper the encrypted files
    enc_raw = base64.urlsafe_b64decode(enc)
    bad_enc_raw = enc_raw + b"tampering"
    bad_enc = base64.urlsafe_b64encode(bad_enc_raw).decode("utf-8")

    with pytest.raises(nacl.exceptions.CryptoError):
        ftp_client.ftp_decrypt(bad_enc)


def test_get_pwd_encrypted_path(ftp_client):
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst", return_value=[return_value])\
            as mock_ftp_nlst:
        assert ftp_client.get_pwd_encrypted_path("test_file") == return_value
        mock_ftp_nlst.assert_called_once_with()


def test_get_pwd_encrypted_path_nonsuch(ftp_client):
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.get_pwd_encrypted_path("test_dir")
        mock_ftp_nlst.assert_called_once_with()


@patch("ftplib.FTP.cwd")
@pytest.mark.parametrize("directory", ["..", ".", ""])
def test_cwd_backdir(mock_ftp_cwd, ftp_client, directory):
    ftp_client.cwd(directory)
    mock_ftp_cwd.assert_called_once_with(directory)


@patch("ftplib.FTP.cwd")
def test_cwd_valid_dir(mock_ftp_cwd, ftp_client):
    return_value = ftp_client.ftp_encrypt("test_dir")
    with patch.object(FTP, "nlst", return_value=[return_value])\
            as mock_ftp_nlst:
        ftp_client.cwd("test_dir")
        mock_ftp_cwd.assert_called_once_with(return_value)
        mock_ftp_nlst.assert_called_once()
        assert mock_ftp_cwd.call_args[0][0] != 'test_dir'
        assert ftp_client.ftp_decrypt(mock_ftp_cwd.call_args[0][0]) == \
               'test_dir'


@patch("ftplib.FTP.rmd")
def test_rmd(mock_ftp_rmd, ftp_client):
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst", return_value=[return_value])\
            as mock_ftp_nlst:
        ftp_client.rmd("test_file")
        mock_ftp_rmd.assert_called_once_with(return_value)
        mock_ftp_nlst.assert_called_once()
        assert mock_ftp_rmd.call_args[0][0] != 'test_dir'
        assert ftp_client.ftp_decrypt(mock_ftp_rmd.call_args[0][0]) == \
               'test_file'


@patch("ftplib.FTP.rmd")
def test_rmd_nonsuch(mock_ftp_rmd, ftp_client):
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.rmd("nonsuch")
        mock_ftp_rmd.assert_not_called()
        mock_ftp_nlst.assert_called_once()


@patch("ftplib.FTP.mkd")
def test_mkd(mock_ftp_mkd, secret_key):
    ftp_client = EncryptedFTPClient(secret_key)
    return_value = ftp_client.ftp_encrypt("test_dir")
    with patch.object(FTP, "nlst", return_value=[return_value])\
            as mock_ftp_nlst:
        with pytest.raises(FileExistsError):
            ftp_client.mkd("test_dir")
        mock_ftp_mkd.assert_not_called()
        mock_ftp_nlst.assert_called_once()


@patch("ftplib.FTP.mkd")
def test_mkd_nonsuch(mock_ftp_mkd, ftp_client):
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        ftp_client.mkd("test_dir")
        mock_ftp_mkd.assert_called_once()
        mock_ftp_nlst.assert_called_once()
        assert mock_ftp_mkd.call_args[0][0] != "test_dir"
        assert ftp_client.ftp_decrypt(mock_ftp_mkd.call_args[0][0]) == \
               'test_dir'


@patch("ftplib.FTP.delete")
def test_delete(mock_ftp_delete, ftp_client):
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst", return_value=[return_value])\
            as mock_ftp_nlst:
        ftp_client.delete("test_file")
        mock_ftp_delete.assert_called_once_with(return_value)
        mock_ftp_nlst.assert_called_once()
        assert mock_ftp_delete.call_args[0][0] != "test_file"
        assert ftp_client.ftp_decrypt(mock_ftp_delete.call_args[0][0]) == \
               'test_file'


@patch("ftplib.FTP.delete")
def test_delete_nonsuch(mock_ftp_delete, secret_key):
    ftp_client = EncryptedFTPClient(secret_key)
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.delete("nonsuch")
        mock_ftp_delete.assert_not_called()
        mock_ftp_nlst.assert_called_once()


def test_nlst_dir(ftp_client):
    return_value = ftp_client.ftp_encrypt("test_dir")
    with patch.object(FTP, "nlst", return_value=[return_value])\
            as mock_ftp_nlst:
        assert ftp_client.nlst("test_dir") == ["test_dir"]
        mock_ftp_nlst.assert_called_once()
        assert mock_ftp_nlst.call_args[0][0] != "test_dir"
        assert ftp_client.ftp_decrypt(mock_ftp_nlst.call_args[0][0]) == \
               'test_dir'


@pytest.mark.parametrize("directory", [".", "", None])
def test_nlst_current_dir(ftp_client, directory):
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        assert ftp_client.nlst(directory) == []
        mock_ftp_nlst.assert_called_once_with()


def test_nlst_no_args(ftp_client):
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        assert ftp_client.nlst() == []
        mock_ftp_nlst.assert_called_once_with()


@patch("ftplib.FTP.storbinary")
def test_ftp_storefile(mock_ftp_storbinary, ftp_client):
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst", return_value=[return_value])\
            as mock_ftp_nlst:
        ftp_client.storefile('test_file', "test_content")
    mock_ftp_storbinary.assert_called_once()
    mock_ftp_nlst.assert_called()
    assert mock_ftp_storbinary.call_args[0][0] != "test_file"
    assert ftp_client.ftp_decrypt(mock_ftp_storbinary.call_args[0][0][5:]) == \
           'test_file'
    assert mock_ftp_storbinary.call_args[0][1] != "test_content"
    assert \
        ftp_client.ftp_decrypt(mock_ftp_storbinary.call_args[0][1].read()) == \
        'test_content'


@patch("ftplib.FTP.storbinary")
def test_ftp_storefile_nonsuch(mock_ftp_storbinary, ftp_client):
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        ftp_client.storefile('test_file', "test_content")
    mock_ftp_storbinary.assert_called_once()
    mock_ftp_nlst.assert_called_once()
    assert mock_ftp_storbinary.call_args[0][0] != "test_file"
    assert ftp_client.ftp_decrypt(mock_ftp_storbinary.call_args[0][0][5:]) == \
           'test_file'
    assert mock_ftp_storbinary.call_args[0][1] != "test_content"
    assert \
        ftp_client.ftp_decrypt(mock_ftp_storbinary.call_args[0][1].read()) == \
        'test_content'


def test_ftp_readfile(ftp_client):
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

    with patch.object(FTP, "retrbinary", return_value=retrbinary_return_value)\
            as mock_retrbinary:
        with patch("dead_sfs.ftp_client.BytesIO", return_value=MockBytesIO()):
            nlst_return_value = ftp_client.ftp_encrypt("test_file")
            with patch.object(FTP, "nlst", return_value=[nlst_return_value])\
                    as mock_ftp_nlst:
                ftp_client.readfile("test_file")
                mock_retrbinary.assert_called_once()
                mock_ftp_nlst.assert_called_once()
                assert "test_file" not in mock_retrbinary.call_args[0][0]
                assert ftp_client.ftp_decrypt(
                    mock_retrbinary.call_args[0][0][5:]) == 'test_file'


@patch("ftplib.FTP.rename")
def test_rename(mock_ftp_rename, ftp_client):
    return_value_1 = ftp_client.ftp_encrypt("test_file_1")
    with patch.object(FTP, "nlst", return_value=[return_value_1])\
            as mock_ftp_nlst:
        ftp_client.rename("test_file_1", "test_file_2")
        mock_ftp_rename.assert_called_once()
        mock_ftp_nlst.assert_called()
        assert "test_file_1" not in mock_ftp_rename.call_args[0][0]
        assert ftp_client.ftp_decrypt( mock_ftp_rename.call_args[0][0]) == \
               'test_file_1'
        assert "test_file_2" not in mock_ftp_rename.call_args[0][1]
        assert ftp_client.ftp_decrypt(mock_ftp_rename.call_args[0][1]) == \
               'test_file_2'


@patch("ftplib.FTP.rename")
def test_rename_collision(mock_ftp_rename, secret_key):
    ftp_client = EncryptedFTPClient(secret_key)
    return_value_1 = ftp_client.ftp_encrypt("test_file_1")
    return_value_2 = ftp_client.ftp_encrypt("test_file_2")
    with patch.object(FTP, "nlst",
                      return_value=[return_value_1, return_value_2])\
            as mock_ftp_nlst:
        with pytest.raises(FileExistsError):
            ftp_client.rename("test_file_1", "test_file_2")
        mock_ftp_rename.assert_not_called()
        mock_ftp_nlst.assert_called()


@patch("ftplib.FTP.rename")
def test_rename_nonsuch(mock_ftp_rename, ftp_client):
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.rename("test_file_1", "test_file_2")
        mock_ftp_rename.assert_not_called()
        mock_ftp_nlst.assert_called()


@patch("ftplib.FTP.size")
def test_size(mock_ftp_size, ftp_client):
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst", return_value=[return_value])\
            as mock_ftp_nlst:
        ftp_client.size("test_file")
        mock_ftp_size.assert_called_once_with(return_value)
        mock_ftp_nlst.assert_called_once()
        assert "test_file" not in mock_ftp_size.call_args[0][0]
        assert ftp_client.ftp_decrypt(mock_ftp_size.call_args[0][0]) == \
               'test_file'


@patch("ftplib.FTP.size")
def test_size_nonsuch(mock_ftp_size, ftp_client):
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.size("test_file")
        mock_ftp_size.assert_not_called()
        mock_ftp_nlst.assert_called_once()


@patch("ftplib.FTP.sendcmd")
def test_chmod(mock_ftp_sendcmd, ftp_client):
    return_value = ftp_client.ftp_encrypt("test_file")
    with patch.object(FTP, "nlst", return_value=[return_value])\
            as mock_ftp_nlst:
        ftp_client.chmod('644', "test_file")
        mock_ftp_sendcmd.assert_called_once()
        mock_ftp_nlst.assert_called_once()
        assert "test_file" not in mock_ftp_sendcmd.call_args[0][0]
        assert \
            ftp_client.ftp_decrypt(mock_ftp_sendcmd.call_args[0][0][15:]) == \
            'test_file'


@patch("ftplib.FTP.sendcmd")
def test_chmod_nonsuch(mock_ftp_sendcmd, ftp_client):
    with patch.object(FTP, "nlst", return_value=[]) as mock_ftp_nlst:
        with pytest.raises(FileNotFoundError):
            ftp_client.chmod("644", "test_file")
        mock_ftp_sendcmd.assert_not_called()
        mock_ftp_nlst.assert_called_once()
