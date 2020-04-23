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
        print("This message is correct")
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

    # @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_callbacks_basic(self):
        num_loops = 3
        created_process = multiprocessing.Process(target=processing_function, args=(1.0, num_loops))
        created_process.start()
        print("created_process=", created_process.pid)

        time.sleep(1.0)

        print("Attaching. getpid=%d" % os.getpid())
        win32_api_definitions.hooks_manager.object_pydbg.attach(created_process.pid)

        class Context:
            calls_counter = {}

        class TestTracer(win32_api_definitions.TracerBase):
            def report_function_call(self, function_name, task_id):
                print("report_function_call function_name=%s" % function_name)
                try:
                    Context.calls_counter[function_name] += 1
                except KeyError:
                    Context.calls_counter[function_name] = 1

            def report_object_creation(self, cim_class_name, **cim_arguments):
                print("report_object_creation", cim_class_name, cim_arguments)

        win32_api_definitions.tracer_object = TestTracer()

        win32_api_definitions.hook_all_functions()

        win32_api_definitions.hooks_manager.object_pydbg.run()

        print("Detaching")
######        tst_pydbg.detach()
        created_process.terminate()
        created_process.join()

        print("Finished:", Context.calls_counter)

        if sys.version_info > (3,):
            self.assertTrue(Context.calls_counter == {
                b'RemoveDirectoryW':  2 * num_loops,
                b'CreateFileW': num_loops,
                b'CreateProcessW': num_loops})
        else:
            self.assertTrue(Context.calls_counter == {
                b'CreateFileA': num_loops + 3,
                b'RemoveDirectoryW': 2 * num_loops,
                b'CreateProcessA': num_loops} )

if __name__ == '__main__':
    unittest.main()
