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

    # This tests the callbacks which are used for good in other tests.
    # It starts a DOS process which attempts to remove a directory.
    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_pydbg_DOS_RemoveDirectoryW(self):
        import pydbg
        from pydbg import defines
        from pydbg import utils

        tst_pydbg = create_pydbg()

        num_loops = 5
        non_existent_dir = "NonExistentDir"

        # This attempts several times to remove a non-existent dir.
        # This is detected by the hook.
        dos_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 >NUL & echo %%A & rmdir %s )" % (num_loops, non_existent_dir)

        created_process = subprocess.Popen(dos_command, shell=True)
        print("Created process:%d" % created_process.pid)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Attaching. Root pid=%d" % os.getpid())
        tst_pydbg.attach(created_process.pid)

        object_hooks = pydbg.utils.hook_container()

        hook_address_RemoveDirectoryW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"RemoveDirectoryW")

        tst_pydbg.count_entry = 0
        tst_pydbg.count_exit = 0

        def callback_RemoveDirectoryW_entry(object_pydbg, args):
            object_pydbg.count_entry += 1
            dir_name = object_pydbg.get_wstring(args[0])
            print("callback_RemoveDirectoryW_entry dir_name=", dir_name)
            self.assertTrue(dir_name == non_existent_dir)
            return defines.DBG_CONTINUE

        def callback_RemoveDirectoryW_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            dir_name = object_pydbg.get_wstring(args[0])
            print("callback_RemoveDirectoryW_exit dir_name=", dir_name, function_result)
            self.assertTrue(dir_name == non_existent_dir)
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
        self.assertTrue(tst_pydbg.count_entry == num_loops)
        self.assertTrue(tst_pydbg.count_exit == num_loops)

    # This starts a separate Python process which attempts several times to open a non-existent file.
    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_pydbg_DOS_CreateFileW(self):
        import pydbg
        from pydbg import defines
        from pydbg import utils

        tst_pydbg = create_pydbg()

        num_loops = 5
        non_existent_file = "NonExistentFile"

        # This attempts several times to remove a non-existent dir.
        # This is detected by the hook.
        python_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 & echo %%A & type %s )" % (num_loops, non_existent_file)

        created_process = subprocess.Popen(python_command, shell=True)
        print("Created process:%d" % created_process.pid)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Attaching. Root pid=%d" % os.getpid())
        tst_pydbg.attach(created_process.pid)

        object_hooks = pydbg.utils.hook_container()

        hook_address_CreateFileW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateFileW")

        tst_pydbg.count_entry = 0
        tst_pydbg.count_exit = 0

        def callback_CreateFileW_entry(object_pydbg, args):
            object_pydbg.count_entry += 1
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_RemoveDirectoryW_entry file_name=", file_name)
            self.assertTrue(file_name == non_existent_file)
            return defines.DBG_CONTINUE

        def callback_CreateFileW_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_RemoveDirectoryW_exit file_name=", file_name, function_result)
            self.assertTrue(file_name == non_existent_file)

            is_invalid_handle = function_result % (1 + defines.INVALID_HANDLE_VALUE) == defines.INVALID_HANDLE_VALUE
            self.assertTrue(is_invalid_handle)
            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_CreateFileW,
            1,
            callback_CreateFileW_entry,
            callback_CreateFileW_exit)

        tst_pydbg.run()

        print("END", tst_pydbg.count_entry, tst_pydbg.count_exit)
        # The first call might be missed.
        self.assertTrue(tst_pydbg.count_entry == num_loops)
        self.assertTrue(tst_pydbg.count_exit == num_loops)

if __name__ == '__main__':
    unittest.main()
