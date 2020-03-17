#!/usr/bin/env python

from __future__ import print_function

import os
import unittest

print("cwd=%s" % os.getcwd())

from init import *

if not is_platform_linux:
    from . import pydbg
    import pydbg.utils
    from pydbg import pydbg
    from survol.scripts import win32_api_definitions

################################################################################

from survol.scripts import dockit

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
