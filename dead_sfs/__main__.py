#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""argparse and main entrypoint script for deadSFS"""

import argparse
import logging
import os
import sys
from logging.handlers import TimedRotatingFileHandler

from dead_sfs.shell import DeadSFSShell

LOG_LEVEL_STRINGS = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]


def log_level(log_level_string: str):
    """Argparse type function for determining the specified logging level"""
    if log_level_string not in LOG_LEVEL_STRINGS:
        raise argparse.ArgumentTypeError(
            "invalid choice: {} (choose from {})".format(
                log_level_string,
                LOG_LEVEL_STRINGS
            )
        )
    return getattr(logging, log_level_string, logging.INFO)


def add_log_parser(parser):
    """Add logging options to the argument parser"""
    group = parser.add_argument_group(title="Logging")
    group.add_argument("--log-level", dest="log_level", default="INFO",
                       type=log_level, help="Set the logging output level")
    group.add_argument("--log-dir", dest="log_dir",
                       help="Enable TimeRotatingLogging at the directory "
                            "specified")
    group.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose logging")


def init_logging(args, log_file_path):
    """Intake a argparse.parse_args() object and setup python logging"""
    handlers_ = []
    log_format = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] - %(message)s")
    if args.log_dir:
        os.makedirs(args.log_dir, exist_ok=True)
        file_handler = TimedRotatingFileHandler(
            os.path.join(args.log_dir, log_file_path),
            when="d", interval=1, backupCount=7, encoding="UTF-8",
        )
        file_handler.setFormatter(log_format)
        file_handler.setLevel(args.log_level)
        handlers_.append(file_handler)
    if args.verbose:
        stream_handler = logging.StreamHandler(stream=sys.stderr)
        stream_handler.setFormatter(log_format)
        stream_handler.setLevel(args.log_level)
        handlers_.append(stream_handler)

    logging.basicConfig(
        handlers=handlers_,
        level=args.log_level
    )


def get_parser() -> argparse.ArgumentParser:
    """Create and return the argparser for deadSFS"""
    parser = argparse.ArgumentParser(
        description="Start the deadSFS shell",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("enc_key_file",
                        help="Path to the private key file for encrypting "
                             "contents to be sent to the remote filesystem")
    parser.add_argument("--tls", action="store_true",
                        help="Enable using a FTP TLS connection")
    parser.add_argument("-c", "--certfile", default=None,
                        help="Path to the deadSFS client *.pem "
                             "self-certificate")
    parser.add_argument("-k", "--keyfile", default=None,
                        help="Path to the deadSFS client *.pem "
                             "self-certificate key")
    parser.add_argument("-ca" "--cafile", dest="cafile", default=None,
                        help="Path to the *.pem certificate authority bundle "
                             "to validate the remote FTP server's "
                             "TLS connection")
    add_log_parser(parser)

    return parser


def main(argv=sys.argv[1:]) -> int:
    """main entry point for deadSFS"""
    parser = get_parser()
    args = parser.parse_args(argv)
    init_logging(args, "deadSFS_client.log")
    with open(args.enc_key_file, "rb") as f:
        enc_key = f.read()
    DeadSFSShell(
        enc_key=enc_key,
        tls=args.tls,
        certfile=args.certfile,
        keyfile=args.keyfile,
        cafile=args.cafile
    ).cmdloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
