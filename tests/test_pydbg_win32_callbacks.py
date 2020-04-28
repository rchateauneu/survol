from __future__ import print_function

import os
import sys
import unittest
import six
import ctypes
import collections
import multiprocessing

from init import *

if not is_platform_linux:
    from survol.scripts import win32_api_definitions

    class TracerForTests(win32_api_definitions.TracerBase):
        def __init__(self):
            self.calls_counter = collections.defaultdict(lambda: 0)
            self.created_objects = collections.defaultdict(list)

        def report_function_call(self, function_name, task_id):
            self.calls_counter[function_name] += 1

        def report_object_creation(self, cim_class_name, **cim_arguments):
            self.created_objects[cim_class_name].append(cim_arguments)

################################################################################

nonexistent_file = "NonExistentFile.xyz"


# This procedure calls various win32 systems functions,
# which are hooked then tested: Arguments, return values etc...
# It is started in a subprocess.
# It has to be global otherwise it fails with the error message:
# PicklingError: Can't pickle <function processing_function at ...>: it's not found as test_pydbg.processing_function
def attach_pid_target_function(one_argument, num_loops):
    time.sleep(one_argument)
    print('test_attach_pid_target_function START.')
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
    print('test_attach_pid_target_function END.')

################################################################################

@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgAttachTest(unittest.TestCase):
    """
    Test pydbg callbacks.
    """

    def setUp(self):
        win32_api_definitions.tracer_object = TracerForTests()

    def tearDown(self):
        win32_api_definitions.tracer_object = None

    def test_attach_pid(self):
        num_loops = 3
        created_process = multiprocessing.Process(target=attach_pid_target_function, args=(1.0, num_loops))
        created_process.start()
        print("created_process=", created_process.pid)

        time.sleep(1.0)

        hooks_manager = win32_api_definitions.Win32Hook_Manager()

        hooks_manager.attach_to_pid(created_process.pid, win32_api_definitions.functions_list)

        created_process.terminate()
        created_process.join()

        print("test_attach_pid counters:", win32_api_definitions.tracer_object.calls_counter)
        if is_py3:
            # FIXME: For an unknown reason, the Python function open() of the implementation used by Travis
            # does not use CreateFileW or CreateFileA. This problem is not understood yet.
            # Other functions do not have the same problem. This is not a big issue because
            # this test just checks general behaviour of funcitons and breakpoints.
            if is_travis_machine():
                self.assertTrue(win32_api_definitions.tracer_object.calls_counter == {
                    b'RemoveDirectoryW': 2 * num_loops,
                    b'CreateProcessW': num_loops})
            else:
                self.assertTrue(win32_api_definitions.tracer_object.calls_counter == {
                    b'RemoveDirectoryW':  2 * num_loops,
                    b'CreateFileW': num_loops,
                    b'CreateProcessW': num_loops,
                    b'WriteFile': 1})
        else:
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter == {
                b'RemoveDirectoryW': 2 * num_loops,
                b'CreateFileA': 2 * num_loops,
                b'CreateProcessA': num_loops,
                b'ReadFile': 2,
                b'WriteFile': 1})

        # Not all objects are checked: This just tests the general mechanism.
        print("Objects:", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue({'Name': u'NonExistentDirUnicode'} in win32_api_definitions.tracer_object.created_objects['CIM_Directory'])
        if is_travis_machine():
            # FIXME: Which function is used by Travis Python interpreter ?
            self.assertTrue({'Name': nonexistent_file} not in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])
        else:
            self.assertTrue({'Name': nonexistent_file} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])
        self.assertTrue(len(win32_api_definitions.tracer_object.created_objects['CIM_Process']) == num_loops)

    def test_start_python_process(self):
        temp_data_file_path = unique_temporary_path("test_start_python_process", ".txt")

        temp_python_name = "test_win32_process_basic_%d_%d.py" % (CurrentPid, int(time.time()))
        temp_python_path = os.path.join(tempfile.gettempdir(), temp_python_name)
        result_message = "Hello_%d" % CurrentPid
        script_content = "open(r'%s', 'w').write('%s')" % (temp_data_file_path, result_message)
        with open(temp_python_path, "w") as temp_python_file:
            temp_python_file.write(script_content)

        command_line = "%s %s" % (sys.executable, temp_python_path)

        hooks_manager = win32_api_definitions.Win32Hook_Manager()
        hooks_manager.attach_to_command(command_line, win32_api_definitions.functions_list)

        print("test_start_python_process calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        print("test_start_python_process created_objects=", win32_api_definitions.tracer_object.created_objects)
        function_name_create_file = b"CreateFileW" if is_py3 else b"CreateFileA"
        self.assertTrue(function_name_create_file in win32_api_definitions.tracer_object.calls_counter)

        # This contains many Python modules which are loaded at startup, followed by plain files, checked here.
        self.assertTrue({'Name': temp_python_path} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])
        if is_travis_machine():
            # FIXME: Which function is used by Travis Python interpreter to open a file?
            self.assertTrue( {'Name': temp_data_file_path} not in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])
        else:
            self.assertTrue( {'Name': temp_data_file_path} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])

    def test_dos_create_process(self):
        num_loops = 2
        create_process_command = windows_system32_cmd_exe + " /c "+ "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1)" % num_loops

        hooks_manager = win32_api_definitions.Win32Hook_Manager()
        hooks_manager.attach_to_command(create_process_command, win32_api_definitions.functions_list)

        print("test_dos_create_process calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'WriteFile'] > 0)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateProcessW'] == num_loops)

        print("test_dos_create_process created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue('CIM_Process' in win32_api_definitions.tracer_object.created_objects)

    def test_dos_delete_file(self):
        num_loops = 3
        temp_path = unique_temporary_path("test_basic_delete_file", ".txt")
        delete_file_command = windows_system32_cmd_exe + " /c "+ "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 > %s &del %s)" % (num_loops, temp_path, temp_path)

        hooks_manager = win32_api_definitions.Win32Hook_Manager()
        hooks_manager.attach_to_command(delete_file_command, win32_api_definitions.functions_list)

        print("test_dos_delete_file calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'WriteFile'] > 0)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateProcessW'] == num_loops)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateFileW'] == num_loops)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'DeleteFileW'] == num_loops)

        print("test_dos_delete_file created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue('CIM_Process' in win32_api_definitions.tracer_object.created_objects)
        self.assertTrue({'Name': temp_path} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])

    def test_dos_dir(self):
        num_loops = 2
        dir_command = windows_system32_cmd_exe + " /c "+ "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 1.2.3.4 & type something.xyz )" % num_loops

        hooks_manager = win32_api_definitions.Win32Hook_Manager()
        hooks_manager.attach_to_command(dir_command, win32_api_definitions.functions_list)

        print("test_dos_dir calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'WriteFile'] > 0)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateProcessW'] == num_loops)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateFileW'] == num_loops)

        print("test_dos_dir created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue('CIM_Process' in win32_api_definitions.tracer_object.created_objects)
        self.assertTrue({'Name': 'something.xyz'} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])

if __name__ == '__main__':
    unittest.main()
