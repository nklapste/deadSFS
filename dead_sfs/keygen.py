#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Simple key generation script for generating keys for the
main deadSFS script"""

import argparse
import sys

import nacl.secret
import nacl.utils


def get_parser() -> argparse.ArgumentParser:
    """Create and return the argparser for deadSFS-keygen"""
    parser = argparse.ArgumentParser(
        description="Create a key file for usage as a private key for in the "
                    "deadSFS shell",
    )

    parser.add_argument("output",
                        help="Path to the output the private key file "
                             "for usage in the deadSFS shell")

    return parser


def write_key(output_file):
    with open(output_file, "wb") as f:
        f.write(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE))


def main(argv=sys.argv[1:]) -> int:
    """main entry point for deadSFS-keygen"""
    parser = get_parser()
    args = parser.parse_args(argv)
    write_key(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
