from __future__ import print_function

import os
import sys
import unittest
import six
import ctypes
import multiprocessing

# This loads the module from the source, so no need to install it, and no need of virtualenv.
# This is needed when running from PyCharm.
sys.path.append("../survol/scripts")
sys.path.append("survol/scripts")
print("cwd=%s" % os.getcwd())

from init import *

if not is_platform_linux:
    #from pydbg import pydbg
    #import win32_api_definitions
	from survol.scripts import win32_api_definitions

################################################################################

nonexistent_file = "NonExistentFile.xyz"

# This procedure calls various win32 systems functions,
# which are hooked then tested: Arguments, return values etc...
# It is started in a subprocess.
# It has to be global otherwise it fails with the error message:
# PicklingError: Can't pickle <function processing_function at ...>: it's not found as test_pydbg.processing_function
def processing_function(one_argument, num_loops):
    time.sleep(one_argument)
    print('processing_function START.')
    while num_loops:
        time.sleep(one_argument)
        num_loops -= 1
        print("This is a nice message")
        dir_binary = six.b("NonExistentDirBinary")
        dir_unicode = six.u("NonExistentDirUnicode")

        try:
            ctypes.windll.kernel32.RemoveDirectoryW(dir_unicode)
            os.rmdir(dir_unicode)  # RemoveDirectoryW

            ctypes.windll.kernel32.RemoveDirectoryA(dir_binary)
            os.rmdir(dir_binary)  # RemoveDirectoryA

        except Exception as exc:
            print("=============== CAUGHT:", exc)
            pass

        # This opens a non-existent, which must be detected.
        try:
            opfil = open(nonexistent_file)
        except Exception as exc:
            pass

        try:
            os.system("dir nothing_at_all")
        except Exception as exc:
            pass
    print('processing_function END.')

################################################################################

@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgAttachTest(unittest.TestCase):
    """
    Test pydbg.
    """

    # This function is called for each hooked function.
    @staticmethod
    def syscall_creation_callback(one_syscall, object_pydbg, task_id):
        print("syscall=%s" % one_syscall.function_name)
        try:
            object_pydbg.calls_counter[one_syscall.function_name] += 1
        except KeyError:
            object_pydbg.calls_counter[one_syscall.function_name] = 1

    # This is called when creating a CIM object.
    @staticmethod
    def cim_object_callback(calling_class_instance, cim_class_name, **cim_arguments):
        print("cim_object_callback", calling_class_instance.__class__.__name__, cim_class_name, cim_arguments)
        function_name = calling_class_instance.function_name
        if function_name == b"RemoveDirectoryA":
            assert cim_arguments["Name"] == "NonExistentDirBinary"
        elif function_name == b"RemoveDirectoryW":
            #assert cim_arguments["Name"] == b"NonExistentDirUnicode"
            if sys.version_info > (3,):
                assert cim_arguments["Name"] == "NonExistentDirUnicode"
            else:
                assert cim_arguments["Name"] == b"NonExistentDirUnicode"
        elif function_name == b"CreateFileA":
            assert cim_arguments["Name"] in [
                nonexistent_file,
                "C:\\Python27\\lib\\encodings\\unicode_escape.pyd",
                "C:\\Python27\\lib\\encodings\\unicode_escape.pyc",
                "C:\\Python27\\lib\\encodings\\unicode_escape.py"]
        elif function_name == b"CreateFileW":
            assert cim_arguments["Name"] == "NonExistentDirUnicode"
        elif function_name == b"CreateProcessA":
            print("cim_arguments=", cim_arguments)
        elif function_name == b"CreateProcessW":
            print("cim_arguments=", cim_arguments)
        else:
            raise Exception("Unexpected API function:", function_name)

    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_callbacks_basic(self):
        num_loops = 3
        created_process = multiprocessing.Process(target=processing_function, args=(1.0, num_loops))
        created_process.start()
        print("created_process=", created_process.pid)

        time.sleep(1)

        tst_pydbg = win32_api_definitions.create_pydbg()
        win32_api_definitions.Win32Hook_BaseClass.object_pydbg = tst_pydbg
        time.sleep(1.0)

        print("Attaching. getpid=%d" % os.getpid())
        tst_pydbg.attach(created_process.pid)

        win32_api_definitions.Win32Hook_BaseClass.callback_create_call = PydbgAttachTest.syscall_creation_callback
        win32_api_definitions.Win32Hook_BaseClass.callback_create_object = PydbgAttachTest.cim_object_callback

        for subclass_definition in [
            win32_api_definitions.Win32Hook_CreateProcessA,
            win32_api_definitions.Win32Hook_CreateProcessW,
            win32_api_definitions.Win32Hook_RemoveDirectoryA,
            win32_api_definitions.Win32Hook_RemoveDirectoryW,
            win32_api_definitions.Win32Hook_CreateFileA]:
            win32_api_definitions.Win32Hook_BaseClass.add_subclass(subclass_definition)

        # Use thi object to count how many times functions are called.
        tst_pydbg.calls_counter = {}

        tst_pydbg.run()

        print("Detaching")
######        tst_pydbg.detach()
        created_process.terminate()
        created_process.join()

        print("Finished:", tst_pydbg.calls_counter)

        if sys.version_info > (3,):
            self.assertTrue(tst_pydbg.calls_counter == {
                b'RemoveDirectoryW': 2 * num_loops,
                b'CreateProcessW': num_loops} )
        else:
            self.assertTrue(tst_pydbg.calls_counter == {
                'CreateFileA': num_loops + 3,
                'RemoveDirectoryW': 2 * num_loops,
                'CreateProcessA': num_loops} )

if __name__ == '__main__':
    unittest.main()
