#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import unittest
import six
import subprocess

# This loads the module from the source, so no need to install it, and no need of virtualenv.
# This is needed when running from PyCharm.
sys.path.append("../survol/scripts")
sys.path.append("survol/scripts")
print("cwd=%s" % os.getcwd())

from init import *

if not is_platform_linux:
    from pydbg import pydbg

    def create_pydbg():
        if sys.version_info < (3, 8):
            tst_pydbg = pydbg()
        else:
            tst_pydbg = pydbg.pydbg.pydbg()
        return tst_pydbg

# Faire tourner les tests de pydbg a l origine.

################################################################################

@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgBasicTest(unittest.TestCase):
    """
    Test pydbg.
    """

    # This just tests the callbacks which are used for good in other tests.
    # This just tests the callbacks which are used for good in other tests.
    def test_pydbg_RemoveDirectoryW(self):
        import pydbg
        from pydbg import defines
        from pydbg import utils

        tst_pydbg = create_pydbg()

        num_loops = 5
        does_not_exist = "DoesNotExist"

        # This attempts to remove a non-existent dir in a loop.
        dos_command = "FOR /L %%A IN (1,1,%d) DO ( echo %%A & rmdir %s & ping -n 2 127.0.0.1 >NUL )" % (num_loops, does_not_exist)

        # created_process = subprocess.Popen(dos_command, shell=True, stdout=subprocess.PIPE)
        created_process = subprocess.Popen(dos_command, shell=True)
        print("Created process:%d" % created_process.pid)

        time.sleep(1.0)

        print("Attaching. Root pid=%d" % os.getpid())
        tst_pydbg.attach(created_process.pid)

        object_hooks = pydbg.utils.hook_container()

        hook_address_RemoveDirectoryW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"RemoveDirectoryW")

        tst_pydbg.count_entry = 0
        tst_pydbg.count_exit = 0

        def callback_RemoveDirectoryW_entry(object_pydbg, args):
            object_pydbg.count_entry += 1
            dirname = object_pydbg.get_wstring(args[0])
            print("callback_RemoveDirectoryW_entry dirname=", dirname)
            self.assertTrue(dirname == does_not_exist)
            return defines.DBG_CONTINUE

        def callback_RemoveDirectoryW_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            dirname = object_pydbg.get_wstring(args[0])
            print("callback_RemoveDirectoryW_exit dirname=", dirname, function_result)
            self.assertTrue(dirname == does_not_exist)
            self.assertTrue(function_result == 0)
            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_RemoveDirectoryW,
            1,
            callback_RemoveDirectoryW_entry,
            callback_RemoveDirectoryW_exit)

        tst_pydbg.run()

        print("END", tst_pydbg.count_entry, tst_pydbg.count_exit)
        self.assertTrue(tst_pydbg.count_entry == num_loops - 1)
        self.assertTrue(tst_pydbg.count_exit == num_loops - 1)

if __name__ == '__main__':
    unittest.main()
