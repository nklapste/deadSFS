#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""command shell for the deadchat client"""

import cmd
from logging import getLogger

__log__ = getLogger(__name__)


class DeadChatShell(cmd.Cmd):
    """Main shell for the deadchat client"""
    intro = \
        "Welcome to deadchat client shell. Type help or ? to list commands\n"
    prompt = "deadchat>"

    def __init__(self):
        """Initialize the deadchat client shell"""
        super().__init__()

    def cmdloop(self, intro=None):
        # start a login command at start.
        __log__.info("starting deadchat client shell")
        super().cmdloop()

    def do_exit(self, arg):
        """exit out of the deadchat client shell"""
        __log__.info("exiting deadchat client shell")
        return True
