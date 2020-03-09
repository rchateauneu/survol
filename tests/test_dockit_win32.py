#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import unittest
import subprocess

# This loads the module from the source, so no need to install it, and no need of virtualenv.
# This is needed when running from PyCharm.
sys.path.append("../survol/scripts")
sys.path.append("survol/scripts")
print("cwd=%s" % os.getcwd())

from init import *

if not is_platform_linux:
    import pydbg
    import pydbg.utils
    from pydbg import pydbg
    import win32_api_definitions

################################################################################

import dockit

# TODO: Add test of win32_api_definitions.Win32Tracer
@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgDockitWin32TracerTest(unittest.TestCase):
    """
    Test Win32Tracer.
    """

    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_basic(self):
        self.assertTrue(isinstance(dockit.G_traceToTracer["pydbg"], win32_api_definitions.Win32Tracer))

if __name__ == '__main__':
    unittest.main()
