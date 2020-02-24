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
    from pydbg import pydbg
    import win32_api_definitions

################################################################################

import dockit

@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgDirTest(unittest.TestCase):
    """
    Test pydbg.
    """

    # This function is called for each hooked function.
    # Not relevant here.
    @staticmethod
    def syscall_creation_callback(one_syscall, object_pydbg, task_id):
        print("syscall=%s" % one_syscall.function_name)

    # This is called when creating a CIM object.
    # This must inject the objects into dockit.
    @staticmethod
    def cim_object_callback(calling_class_instance, cim_class_name, **cim_arguments):
        print("cim_object_callback", calling_class_instance.__class__.__name__, cim_class_name, cim_arguments)

    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_pydbg_basic(self):

        tst_pydbg = win32_api_definition.create_pydbg()
        win32_api_definition.Win32Hook_BaseClass.object_pydbg = tst_pydbg
        time.sleep(1.0)

        created_process = subprocess.Popen("dir something", shell=True)

        print("Attaching. getpid=%d" % os.getpid())
        tst_pydbg.attach(created_process.pid)

        hooks = pydbg.utils.hook_container()
        win32_api_definition.Win32Hook_BaseClass.object_hooks = hooks

        win32_api_definition.Win32Hook_BaseClass.callback_create_call = PydbgDirTest.syscall_creation_callback
        win32_api_definition.Win32Hook_BaseClass.callback_create_object = PydbgDirTest.cim_object_callback

        for subclass_definition in [
            win32_api_definition.Win32Hook_CreateFileA]:
            win32_api_definition.Win32Hook_BaseClass.add_subclass(subclass_definition)

        tst_pydbg.run()

        print("Detaching")
######        tst_pydbg.detach()
        created_process.terminate()
        created_process.join()
        print("Finished")

if __name__ == '__main__':
    unittest.main()
