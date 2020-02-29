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

################################################################################

@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgDockitBasicTest(unittest.TestCase):
    """
    Test pydbg.
    """

    # Used to check which functions were called.
    function_calls_set = set()

    # Used to check which objects were created.
    created_objects_set = set()

    # This function is called for each hooked function.
    # Not relevant here.
    @staticmethod
    def syscall_creation_callback(one_syscall, object_pydbg, task_id):
        print("syscall=%s %s" % (one_syscall.function_name, task_id))
        PydbgDockitBasicTest.function_calls_set.add(one_syscall.function_name)

    # Quick function which transforms the parameter of an object,
    # into a string which can be handled easily to check if a function call attempted to created this object.
    @staticmethod
    def object_parameters_to_string(function_class_name, cim_class_name, cim_arguments):
        return "%s:%s:%s" % (
                function_class_name,
                cim_class_name,
                "+".join( "%s=%s" % argument_item for argument_item in sorted(cim_arguments.items())))

    # This is called when an object modeling a function call, needs to create a CIM object,
    # to represent a parameter of the function call.
    # This must inject the objects into dockit.
    @staticmethod
    def cim_object_callback(calling_class_instance, cim_class_name, **cim_arguments):
        print("cim_object_callback", calling_class_instance.__class__.__name__, cim_class_name, cim_arguments)

        params_to_string = PydbgDockitBasicTest.object_parameters_to_string(calling_class_instance.__class__.__name__, cim_class_name, cim_arguments)
        PydbgDockitBasicTest.created_objects_set.add(params_to_string)

    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_basic_dir(self):
        import pydbg
        import win32_api_definitions

        tst_pydbg = win32_api_definitions.create_pydbg()

        win32_api_definitions.Win32Hook_BaseClass.object_pydbg = tst_pydbg

        num_loops = 2

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

        print("function_calls_set=", PydbgDockitBasicTest.function_calls_set)
        print("created_objects_set=", PydbgDockitBasicTest.created_objects_set)
        self.assertTrue( PydbgDockitBasicTest.function_calls_set == {"CreateFileW"})
        self.assertTrue( PydbgDockitBasicTest.created_objects_set == {u'Win32Hook_CreateFileW:CIM_DataFile:Name=something.xyz'})
        print("Finished")

if __name__ == '__main__':
    unittest.main()
