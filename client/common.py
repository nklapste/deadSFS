#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Common functionality for the deadchat client"""

import argparse


class ShellArgumentException(Exception):
    """Custom exception class noting a invalid argument within a
    :class:`.shell.MiniProjectShell` command"""
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)


class ShellArgumentParser(argparse.ArgumentParser):
    """Custom argument parser for use in :class`.shell.MiniProjectShell`"""

    def __init__(self, *args, **kwargs):
        # set ``add_help`` to false to avoid conflicts with the shell
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)

    def error(self, message):
        self.print_help(sys.stderr)
        raise ShellArgumentException(message)
