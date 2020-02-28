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

@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgDockitBasicTest(unittest.TestCase):
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
    def test_basic_dir(self):
        import pydbg
        import win32_api_definitions

        tst_pydbg = win32_api_definitions.create_pydbg()

        win32_api_definitions.Win32Hook_BaseClass.object_pydbg = tst_pydbg

        time.sleep(0.5)

        num_loops = 3

        dir_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 1.2.3.4 & type something.xyz )" % num_loops

        created_process = subprocess.Popen(dir_command, shell=True)

        time.sleep(0.5)

        print("Attaching. getpid=%d" % os.getpid())
        tst_pydbg.attach(created_process.pid)

        # TEMP ONLY !!
        win32_api_definitions.Win32Hook_BaseClass.callback_create_call = PydbgDockitBasicTest.syscall_creation_callback
        win32_api_definitions.Win32Hook_BaseClass.callback_create_object = PydbgDockitBasicTest.cim_object_callback

        for subclass_definition in [
            win32_api_definitions.Win32Hook_CreateFileW]:
            win32_api_definitions.Win32Hook_BaseClass.add_subclass(subclass_definition)

        tst_pydbg.run()

        print("TODO: Should detaching")
        ## tst_pydbg.detach()
        created_process.terminate()
        ## created_process.join()
        print("Finished")

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
