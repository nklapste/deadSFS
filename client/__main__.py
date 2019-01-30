#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""argparse and main entrypoint script for the deadchat client"""

import argparse
import logging
import os
import sys
from logging.handlers import TimedRotatingFileHandler

from client.shell import DeadChatShell

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
    """Create and return the argparser for the deadchat client"""
    parser = argparse.ArgumentParser(
        description="Start the deadchat client",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("-c", "--config-path", default="deadchat_client.ini",
                        dest="config_path",
                        help="Path to read/write the user config file")
    parser.add_argument("-ca", "--ca-certs", default=None, dest="ca_certs",
                        help="If specified enable using ca certificate "
                             "validation using certificates at the specified "
                             "path")
    add_log_parser(parser)

    return parser


def main(argv=sys.argv[1:]) -> int:
    """main entry point for the deadchat client"""
    parser = get_parser()
    args = parser.parse_args(argv)
    init_logging(args, "deadchat_client.log")
    DeadChatShell(args.config_path, args.ca_certs).cmdloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
