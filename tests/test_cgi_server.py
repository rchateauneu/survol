#!/usr/bin/env python

from __future__ import print_function

"""This starts a local CGI server and does technical tests."""

import cgitb
import unittest
import subprocess

from init import *


class CgiLocalTest(unittest.TestCase):
    """Just runs locally without any network connection. This does not start the server by importing
    it as a module, but instead starts it from the Shell or as a DOS command."""
    def test_cgiserver_help(self):
        """Check content of help command"""
        wsgi_help_command = [sys.executable, "survol/scripts/cgiserver.py", "--help"]
        command_result = subprocess.check_output(wsgi_help_command)
        print("CGI help:", command_result)
        self.assertTrue(command_result.startswith(b"Survol CGI server"))


if __name__ == '__main__':
    unittest.main()

