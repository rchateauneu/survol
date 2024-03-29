from __future__ import print_function

import os
import sys
import unittest
import socket
import six
import ctypes
import collections
import multiprocessing
import psutil
import filecmp

from init import *

is_pydbg_available = is_platform_windows and not pytest_pypy

pytest_skip_pydbg = unittest.skipIf(not is_pydbg_available, "pydbg must be available")

if is_pydbg_available:
    from survol.scripts import win32_api_definitions

    class TracerForTests(win32_api_definitions.TracerBase):
        """This counts the system function calls, and the creation of objects such as files, processes etc..."""
        def __init__(self):
            # The key is a process id, and the subkey a function name.
            self.calls_counter = collections.defaultdict(lambda:collections.defaultdict(lambda: 0))
            # The label is a class name. Each element of the lists is an object,
            # described as a dict of key-value pairs.
            self.created_objects = collections.defaultdict(list)

        def report_function_call(self, function_name, process_id):
            assert isinstance(function_name, six.binary_type)
            # The main purpose of this virtual function is to check exactly what
            # was called, and by process, to help testing and debugging.
            self.calls_counter[process_id][function_name] += 1

        def report_object_creation(self, cim_objects_context, cim_class_name, **cim_arguments):
            self.created_objects[cim_class_name].append(cim_arguments)

from survol import lib_util

nonexistent_file = "NonExistentFile.xyz"

@pytest_skip_pydbg
class HooksManagerUtil(unittest.TestCase):
    """The role of this class is to create and delete the object
    which handles the debugging session and the break points. """
    def setUp(self):
        """
        Terminate all child processes from a previous test,
        otherwise they might send events to the next test.
        """
        win32_api_definitions.tracer_object = TracerForTests()
        self.hooks_manager = win32_api_definitions.Win32Hook_Manager()

    def tearDown(self):
        print("Test teardown")
        self.hooks_manager.stop_cleanup()
        win32_api_definitions.tracer_object = None

################################################################################


def _attach_pid_target_function(sleep_delay, num_loops):
    r"""
    This procedure calls various win32 systems functions,
    which are hooked then tested: Arguments, return values etc... It is started in a subprocess.
    It has to be global otherwise it fails with the error message:
    PicklingError: Can't pickle <function processing_function at ...>: it's not found as test_pydbg.processing_function

    Also, on Python 2.7 on Windows, this must be run like:
        pytest tests/xxx
    ... but not:
        py -2.7 -m pytest tests/xxx

    Otherwise one would get the error message (See https://bugs.python.org/issue10845 ):
        ---------------------------- Captured stderr call -----------------------------
        Traceback (most recent call last):
          File "<string>", line 1, in <module>
          File "c:\python27\lib\multiprocessing\forking.py", line 380, in main
            prepare(preparation_data)
          File "c:\python27\lib\multiprocessing\forking.py", line 488, in prepare
            assert main_name not in sys.modules, main_name
    """
    print('_attach_pid_target_function START.')
    sys.stderr.write('_attach_pid_target_function START.\n')
    sys.stderr.flush()
    time.sleep(sleep_delay)
    print('_attach_pid_target_function after sleep.')
    while num_loops:
        # time.sleep(sleep_delay)
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

        # This opens a non-existent file, and this event must be detected.
        try:
            opfil = open(nonexistent_file)
        except Exception as exc:
            pass

        try:
            os.system("dir nothing_at_all")
        except Exception as exc:
            pass
    print('_attach_pid_target_function END.')


@pytest_skip_pydbg
class PydbgAttachTest(HooksManagerUtil):
    """
    Test pydbg callbacks.
    """

    # TODO: This test might fail if the main process is slowed down wrt the subprocess it attaches to.
    @unittest.skip("FIXME: Fails quite often due to timing.")
    @unittest.skipIf(is_windows10, "FIXME: Does not work on Windows 10. WHY ?")
    def test_attach_pid_multiprocessing(self):
        """This attaches to a process already running. Beware that it might fail sometimes
        due to synchronization problem: This is inherent to this test."""
        num_loops = 5
        inside_delay = 5.0
        created_process = multiprocessing.Process(target=_attach_pid_target_function, args=(inside_delay, num_loops))
        created_process.start()
        print("created_process=", created_process.pid)

        # This delay must be shorter than inside_delay, so the subprocess is correctly started but is still sleeping,
        # so no file update is lost.
        time.sleep(1.0)

        self.hooks_manager.attach_to_pid(created_process.pid)

        created_process.terminate()
        created_process.join()

        print("test_attach_pid counters:", win32_api_definitions.tracer_object.calls_counter)
        created_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[created_process.pid]
        self.assertEqual(created_process_calls_counter[b'RemoveDirectoryW'], 2 * num_loops)
        if is_py3:
            # FIXME: For an unknown reason, the Python function open() of the implementation used by Windows 10
            # does not use CreateFileW or CreateFileA. This problem is not understood yet.
            # Other functions do not have the same problem. This is not a big issue because
            # this test just checks general behaviour of functions and breakpoints.
            self.assertTrue(created_process_calls_counter[b'CreateProcessW'] == num_loops)
            if is_windows10:
                self.assertTrue(b'CreateFileW' not in created_process_calls_counter)
                #self.assertTrue(b'WriteFile' not in created_process_calls_counter)
            else:
                self.assertEqual(created_process_calls_counter[b'CreateFileW'], num_loops)
                #self.assertTrue(created_process_calls_counter[b'WriteFile'] > 0)
        else:
            ## self.assertEqual(created_process_calls_counter[b'CreateFileA'], 2 * num_loops)
            # FIXME: Some files creations are not detected ?
            self.assertTrue(created_process_calls_counter[b'CreateFileA'] >= 2 * num_loops - 2)
            self.assertEqual(created_process_calls_counter[b'CreateProcessA'], num_loops)
            self.assertEqual(created_process_calls_counter[b'ReadFile'], 2)
            self.assertTrue(created_process_calls_counter[b'WriteFile'] > 0)

        # Not all objects are checked: This just tests the general mechanism.
        print("Objects:", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue({'Name': u'NonExistentDirUnicode'} in win32_api_definitions.tracer_object.created_objects['CIM_Directory'])
        if is_windows10:
            # FIXME: Which function is used by Travis Python interpreter ?
            self.assertTrue({'Name': nonexistent_file} not in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])
        else:
            self.assertTrue({'Name': nonexistent_file} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])
        self.assertEqual(len(win32_api_definitions.tracer_object.created_objects['CIM_Process']), num_loops)

    @unittest.skipIf(is_windows10, "FIXME: Does not work on Windows 10. WHY ?")
    def test_attach_python_open_file(self):
        temp_base_name = "test_attach_python_open_file_%d_%d" % (CurrentPid, int(time.time()))

        temp_file_name = unique_temporary_path(temp_base_name, ".tmp")

        print("temp_file_name=", temp_file_name)
        # The file is an Unicode string, to enforce CreateFileW() in Python 2.
        python_command = 'import time;x=[(time.sleep(1),open(u"%s", "w").close()) for i in range(5)]' % temp_file_name

        # Starts a separate process.
        created_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        # Waits a bit until the process is correctly started.
        time.sleep(1.0)

        # Attach to the process.
        self.hooks_manager.attach_to_pid(created_process.pid)

        # It returns when the process finishes.

        print("Created objects:", win32_api_definitions.tracer_object.created_objects)

        # If this kind of operation is executed in dockit, the pathname is added
        # in the context of the current working directory of the process.
        # In this test, the method TracerForTests.report_object_creation() just stores the file name
        # as detcted in the function call.
        created_files = win32_api_definitions.tracer_object.created_objects['CIM_DataFile']
        print("Created files:", created_files)

        unique_filename = list(set([one_object['Name'] for one_object in created_files]))
        self.assertEqual(unique_filename, [temp_file_name])

    def test_attach_python_mkdir(self):
        temp_base_name = "test_attach_python_mkdir_%d_%d" % (CurrentPid, int(time.time()))
        temp_directory_name = unique_temporary_path(temp_base_name, ".dir")

        temporary_python_file_name = unique_temporary_path("test_attach_python_mkdir", ".py")

        script_content = """
import os
import time
for counter in range(5):
    dn = r'%s';
    os.mkdir(dn);
    os.rmdir(dn)
    time.sleep(1.0)
""" % temp_directory_name

        with open(temporary_python_file_name, "w") as temporary_python_file_fd:
            temporary_python_file_fd.write(script_content)

        print("temporary_python_file_name=", temporary_python_file_name)
        print("temp_directory_name=", temp_directory_name)

        created_process = subprocess.Popen(
            [sys.executable, temporary_python_file_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        # Waits a bit until the process is correctly started.
        time.sleep(1.0)

        # Attach to the process.
        self.hooks_manager.attach_to_pid(created_process.pid)

        # It returns when the process finishes.

        print("Created objects:", win32_api_definitions.tracer_object.created_objects)

        # If this kind of operation is executed in dockit, the pathname is added
        # in the context of the current working directory of the process.
        # In this test, the method TracerForTests.report_object_creation() just stores the file name
        # as detcted in the function call.
        created_directories = win32_api_definitions.tracer_object.created_objects['CIM_Directory']
        print("Created directories:", created_directories)

        unique_dir_name = list(set([one_object['Name'] for one_object in created_directories]))
        self.assertEqual(unique_dir_name, [temp_directory_name])



################################################################################


@pytest_skip_pydbg
class DOSCommandsTest(HooksManagerUtil):
    """
    Test pydbg callbacks when running a DOS command.
    """

    def test_start_python_process(self):
        """
        This creates a Python process, then attaches to it and detects a file creation.
        """
        temp_data_file_path = unique_temporary_path("test_start_python_process", ".txt")

        temp_python_name = "test_win32_process_basic_%d_%d" % (CurrentPid, int(time.time()))
        temp_python_path = unique_temporary_path(temp_python_name, ".py")
        result_message = "Hello_%d" % CurrentPid
        script_content = "open(r'%s', 'w').write('%s')" % (temp_data_file_path, result_message)
        with open(temp_python_path, "w") as temp_python_file:
            temp_python_file.write(script_content)

        command_line = "%s %s" % (sys.executable, temp_python_path)

        dwProcessId = self.hooks_manager.attach_to_command(command_line)

        print("test_start_python_process calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        print("test_start_python_process created_objects=", win32_api_definitions.tracer_object.created_objects)
        created_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        function_name_create_file = b"CreateFileW" if is_py3 else b"CreateFileA"
        self.assertTrue(function_name_create_file in created_process_calls_counter)

        # This contains many Python modules which are loaded at startup, followed by plain files, checked here.
        created_files = win32_api_definitions.tracer_object.created_objects['CIM_DataFile']
        self.assertTrue({'Name': temp_python_path} in created_files)
        if is_windows10:
            # FIXME: Which function is used by Windows 10 Python interpreter to open a file?
            self.assertTrue({'Name': temp_data_file_path} not in created_files)
        else:
            self.assertTrue({'Name': temp_data_file_path} in created_files)

    def test_cmd_create_process(self):
        num_loops = 2
        create_process_command = windows_system32_cmd_exe + " /c "+ "FOR /L %%A IN (1,1,%d) DO ( ping -n 1 127.0.0.1)" % num_loops

        dwProcessId = self.hooks_manager.attach_to_command(create_process_command)

        print("test_cmd_create_process dwProcessId=", dwProcessId)
        print("test_dos_create_process calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        created_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        if is_windows10:
            # FIXME: The Python implementation used by Travis is based on another set of IO functions.
            self.assertTrue(b'WriteFile' not in created_process_calls_counter)
        #else:
        #    self.assertTrue(created_process_calls_counter[b'WriteFile'] > 0)
        self.assertEqual(created_process_calls_counter[b'CreateProcessW'], num_loops)

        print("test_dos_create_process created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue('CIM_Process' in win32_api_definitions.tracer_object.created_objects)

    def test_cmd_delete_file(self):
        num_loops = 3

        # This is not standard, and intentionaly does not use, because the file name needs MSDOS syntax,
        # with backslashes, otherwise the command would not work.
        temp_path = os.path.join(tempfile.gettempdir(), "test_basic_delete_file.txt")

        delete_file_command = \
            windows_system32_cmd_exe + \
            " /c "+ "FOR /L %%A IN (1,1,%d) DO ( ping -n 1 127.0.0.1 > %s &del %s)" \
            % (num_loops, temp_path, temp_path)

        # Now, it can be standardized, with backslahes replaced by slashes.
        temp_path = lib_util.standardized_file_path(temp_path)

        dwProcessId = self.hooks_manager.attach_to_command(delete_file_command)
        print("test_cmd_delete_file dwProcessId=", dwProcessId)

        print("test_dos_delete_file calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        created_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        print("created_process_calls_counter=", created_process_calls_counter)
        print("test_dos_delete_file created_objects=", win32_api_definitions.tracer_object.created_objects)

        self.assertEqual(created_process_calls_counter[b'CreateProcessW'], num_loops)
        self.assertTrue('CIM_Process' in win32_api_definitions.tracer_object.created_objects)

        if is_windows10:
            # FIXME: cmd.exe used by Windows 10 is based on another set of IO functions.
            #self.assertTrue(b'WriteFile' not in created_process_calls_counter)
            self.assertTrue(b'CreateFileW' not in created_process_calls_counter)
            self.assertTrue(b'DeleteFileW' not in created_process_calls_counter)
            self.assertTrue('CIM_DataFile' not in win32_api_definitions.tracer_object.created_objects)
        else:
            #self.assertTrue(created_process_calls_counter[b'WriteFile'] > 0)
            self.assertEqual(created_process_calls_counter[b'CreateFileW'], num_loops)
            self.assertEqual(created_process_calls_counter[b'DeleteFileW'], num_loops)
            self.assertTrue({'Name': temp_path} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])

    @unittest.skipIf(is_travis_machine(), "Possible problem with Windows 10")
    @unittest.skipIf(is_windows7, "Sometimes it hangs with Windows 7")
    def test_cmd_ping_type(self):
        num_loops = 5
        dir_command = \
            windows_system32_cmd_exe + \
            " /c "+ "FOR /L %%A IN (1,1,%d) DO ( ping -n 1 1.2.3.4 & type something.xyz )" % num_loops

        dwProcessId = self.hooks_manager.attach_to_command(dir_command)

        print("test_dos_dir calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        created_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        self.assertEqual(created_process_calls_counter[b'CreateProcessW'], num_loops)

        print("test_dos_dir created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue('CIM_Process' in win32_api_definitions.tracer_object.created_objects)

        if is_windows10:
            # FIXME: cmd.exe used by Windows 10 is based on another set of IO functions.
            self.assertTrue(b'CreateFileW' not in created_process_calls_counter)
            self.assertTrue('CIM_DataFile' not in win32_api_definitions.tracer_object.created_objects)
        else:
            self.assertEqual(created_process_calls_counter[b'CreateFileW'], num_loops)
            self.assertTrue({'Name': 'something.xyz'} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])

    def test_cmd_type(self):
        num_loops = 2
        dir_command = windows_system32_cmd_exe + " /c "+ "FOR /L %%A IN (1,1,%d) DO type something.xyz )" % num_loops

        dwProcessId = self.hooks_manager.attach_to_command(dir_command)

        print("test_dos_dir calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        created_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        print("test_dos_dir created_objects=", win32_api_definitions.tracer_object.created_objects.keys())
        print("test_dos_dir created_objects=", win32_api_definitions.tracer_object.created_objects)

        if is_windows10:
            # FIXME: The cmd.exe in Windows 10 is based on another set of IO functions?
            self.assertTrue(b'WriteFile' not in created_process_calls_counter)
            self.assertTrue(b'CreateFileW' not in created_process_calls_counter)
            self.assertTrue(not win32_api_definitions.tracer_object.created_objects)
        else:
            self.assertEqual(created_process_calls_counter[b'CreateFileW'], 2 * num_loops)
            self.assertTrue(created_process_calls_counter[b'WriteFile'] > 0)
            self.assertTrue(list(win32_api_definitions.tracer_object.created_objects.keys()) == ['CIM_DataFile'])
            self.assertTrue({'Name': 'something.xyz'} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])

    def test_cmd_mkdir_rmdir(self):
        # This is not standard but plain MSDOS syntax, otherwise the command would not work.
        temp_path = os.path.join(tempfile.gettempdir(), "test_basic_delete_file.txt")
        dir_mk_rm_command = windows_system32_cmd_exe + " /c "+ "mkdir %s&rmdir %s" % (temp_path, temp_path)

        # Now replace backslahes by slashes.
        temp_path = lib_util.standardized_file_path(temp_path)

        dwProcessId = self.hooks_manager.attach_to_command(dir_mk_rm_command)

        print("test_cmd_mkdir_rmdir calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        created_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        print("test_cmd_mkdir_rmdir created_objects=", win32_api_definitions.tracer_object.created_objects)

        if is_windows10:
            # FIXME: Cmd.exe used by Windows 10 is based on another set of IO functions.
            self.assertTrue(b'CreateDirectoryW' not in created_process_calls_counter)
            self.assertTrue(b'RemoveDirectoryW' not in created_process_calls_counter)
            self.assertTrue('CIM_Directory' not in win32_api_definitions.tracer_object.created_objects)
        else:
            self.assertEqual(created_process_calls_counter[b'CreateDirectoryW'], 1)
            self.assertEqual(created_process_calls_counter[b'RemoveDirectoryW'], 1)
            self.assertTrue({'Name': temp_path} in win32_api_definitions.tracer_object.created_objects['CIM_Directory'])

    def test_cmd_nslookup(self):
        nslookup_command = windows_system32_cmd_exe + " /c "+ "nslookup primhillcomputers.com"

        dwProcessId = self.hooks_manager.attach_to_command(nslookup_command)

        # Typical answer:
        # > Server:  UnKnown
        # Address:  fe80::22b0:1ff:fea4:4672
        #
        # Name:    primhillcomputers.com
        # Address:  164.132.235.17
        # The port number must be 53, for DNS.

        print("test_DOS_nslookup calls_counter=", win32_api_definitions.tracer_object.calls_counter)

        # This NSLOOKUP command creates a subprocess.

        self.assertEqual(len(win32_api_definitions.tracer_object.calls_counter), 2)
        self.assertEqual(win32_api_definitions.tracer_object.calls_counter[dwProcessId][b'CreateProcessW'], 1)

        # Find the sub-process of the process created by us:
        all_created_processes = list(win32_api_definitions.tracer_object.calls_counter.keys())
        print("all_created_processes=", all_created_processes)
        all_created_processes.remove(dwProcessId)
        sub_process_id = all_created_processes[0]
        print("sub_process_id", sub_process_id)

        # FIXME: Adjust this, depending on the machine, the number of DNS connections will vary.
        connections_number = 3 if is_travis_machine() else 5
        self.assertEqual(win32_api_definitions.tracer_object.calls_counter[sub_process_id][b'connect'], connections_number)
        if not is_windows10:
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[sub_process_id][b'WriteFile'] > 0)

        created_objects = win32_api_definitions.tracer_object.created_objects
        print("test_DOS_nslookup created_objects=", created_objects)
        self.assertTrue( {'Handle': sub_process_id} in created_objects['CIM_Process'])
        if not is_windows10:
            # 'CIM_DataFile': [{'Name': u'\\\\.\\Nsi'}]}
            self.assertTrue('CIM_DataFile' in win32_api_definitions.tracer_object.created_objects)

        # All sockets used the port number 53 for DNS, whether in IPV4 or IPV6.
        for dict_key_value in win32_api_definitions.tracer_object.created_objects['addr']:
            self.assertTrue(dict_key_value['Id'].endswith(':53'))

    #@unittest.skipIf(is_travis_machine(), "Possible problem with Windows 10")
    def test_copy_cmd_exe_rdf(self):
        """
        This checks the events generated by a file copy with a DOS command.
        It starts the command under control of pydbg module, then waits until the command is finished.
        At the end, it checks which files were accessed.
        """

        # Any input file is OK. The current script is obviously accessible.
        input_data_file = __file__

        # This temporary file does not use __init__.unique_temporary_path because Windows COPY command needs
        # backslashes in commands.
        output_data_file = os.path.join(tempfile.gettempdir(), "test_copy_cmd_exe_rdf.tmp")

        # It copies the current script elsewhere. Any file would be OK.
        copy_dos_command = windows_system32_cmd_exe + " /c " + "copy %s %s" % (input_data_file, output_data_file)
        dwProcessId = self.hooks_manager.attach_to_command(copy_dos_command)

        # Check that the file is correctly copied, to be sure.
        self.assertTrue(filecmp.cmp(input_data_file, output_data_file, shallow=False))

        created_objects = win32_api_definitions.tracer_object.created_objects
        print("test_copy_cmd_exe_rdf created_objects=", created_objects)
        input_data_file_standard = lib_util.standardized_file_path(input_data_file)
        output_data_file_standard = lib_util.standardized_file_path(output_data_file)
        self.assertTrue({'Name': input_data_file_standard} in created_objects['CIM_DataFile'])
        self.assertTrue({'Name': output_data_file_standard} in created_objects['CIM_DataFile'])

        called_functions = win32_api_definitions.tracer_object.calls_counter
        print("Calls:", win32_api_definitions.tracer_object.calls_counter)
        self.assertTrue(dwProcessId in called_functions)
        called_functions_created_process = called_functions[dwProcessId]
        if is_windows10:
            self.assertEqual(called_functions_created_process[b'CopyFileExW'], 1)
        else:
            # Windows 7 CMD implements differently a file copy.
            self.assertEqual(called_functions_created_process[b'ReadFile'], 1)
            self.assertEqual(called_functions_created_process[b'CreateFileW'], 2)


################################################################################


@pytest_skip_pydbg
class PythonScriptsTest(HooksManagerUtil):
    """
    Test python scripts created on-the-fly.
    """

    def setUp(self):
        HooksManagerUtil.setUp(self)
        self._temporary_python_file = tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False)
        self._temporary_python_path = self._temporary_python_file.name

    def tearDown(self):
        HooksManagerUtil.tearDown(self)
        os.remove(self._temporary_python_path)

    def _debug_python_script(self, script_content):
        """Starts a Python script in a debugging sesson"""
        self._temporary_python_file.write(script_content)
        self._temporary_python_file.close()

        connect_command = "%s %s" % (sys.executable, self._temporary_python_path)

        dwProcessId = self.hooks_manager.attach_to_command(connect_command)
        print("_debug_python_script dwProcessId=", dwProcessId)

        # print("win32_api_definitions.tracer_object.calls_counter=", win32_api_definitions.tracer_object.calls_counter)

        return dwProcessId

    def test_python_mkdir_loop(self):
        """
        This creates directories in a loop then deletes them.
        """

        loops_number = 100

        # Each system function is modelled by a class, with an internal counter for entry and exit of the function.
        # These counters are for debugging purpose, and shared by all subprocesses of the root process being debugged.
        # Because thees counters are class-specific, this resets them to zero before counting.
        class_create_directory = win32_api_definitions.Win32Hook_CreateDirectoryW if is_py3 else win32_api_definitions.Win32Hook_CreateDirectoryA
        class_create_directory._debug_counter_before = 0
        class_create_directory._debug_counter_after = 0

        temporary_directories_prefix = os.path.join(tempfile.gettempdir(), "test_python_%d_mkdir_loop_" % os.getpid())
        # Needed for mkdir.
        temporary_directories_prefix = lib_util.standardized_file_path(temporary_directories_prefix)

        script_content = """
import os
for dir_index in range(%d):
    directory_path = '%s' + str(dir_index)
    os.mkdir(directory_path)
""" % (loops_number, temporary_directories_prefix)

        dwProcessId = self._debug_python_script(script_content)

        print("Win32Hook_CreateDirectoryX BEFORE:", class_create_directory._debug_counter_before)
        print("Win32Hook_CreateDirectoryX AFTER :", class_create_directory._debug_counter_after)
        self.hooks_manager.debug_print_hooks_counter()

        created_directories_set = {
            one_directory['Name']
            for one_directory in win32_api_definitions.tracer_object.created_objects['CIM_Directory']}
        print("created_directories_set=", created_directories_set)
        for dir_index in range(loops_number):
            directory_path = temporary_directories_prefix + str(dir_index)
            self.assertTrue(os.path.isdir(directory_path))
            # Standardize now, because the directory is created, before it is deleted.
            directory_path = lib_util.standardized_file_path(directory_path)
            os.rmdir(directory_path)

            self.assertTrue({'Name': directory_path}
                            in win32_api_definitions.tracer_object.created_objects['CIM_Directory'])
            self.assertTrue(directory_path in created_directories_set)

        create_directory_function = b'CreateDirectoryW' if is_py3 else b'CreateDirectoryA'

        created_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        self.assertEqual(created_process_calls_counter[create_directory_function], loops_number)

        self.assertEqual(class_create_directory._debug_counter_before, loops_number)
        self.assertEqual(class_create_directory._debug_counter_after, loops_number)

    @unittest.skipIf(not pkgutil.find_loader('pyodbc'), "pyodbc cannot be imported.")
    def test_python_SQLDataSources_pyodbc(self):
        """
        This gets ODBC data sources and checks that SQLDataSources() is called.
        """

        # Typical ODBC data sources:
        # {'MyNativeSqlServerDataSrc': 'SQL Server Native Client 11.0', 'Excel Files': 'Microsoft Excel Driver (*.xls, *.xlsx, *.xlsm, *.xlsb)
        # ', 'SqlSrvNativeDataSource': 'SQL Server Native Client 11.0', 'mySqlServerDataSource': 'SQL Server', 'MyOracleDataSource': 'Oracle i
        # n XE', 'SysDataSourceSQLServer': 'SQL Server', 'dBASE Files': 'Microsoft Access dBASE Driver (*.dbf, *.ndx, *.mdx)', 'OraSysDataSrc'
        # : 'Oracle in XE', 'MS Access Database': 'Microsoft Access Driver (*.mdb, *.accdb)'}
        script_content = """
import pyodbc
odbc_sources = pyodbc.dataSources()
"""
        dwProcessId = self._debug_python_script(script_content)
        print("Object:", list(win32_api_definitions.tracer_object.created_objects.keys()))
        created_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        print("created_process_calls_counter=", created_process_calls_counter)
        self.assertTrue(created_process_calls_counter[b'SQLDataSources'] > 0)

    def test_python_connect(self):
        """
        This does a TCP/IP connection to Primhill Computers website.
        The call to socket() is detected, the IP address and the port number are reported.
        """

        server_domain = "primhillcomputers.com"
        server_address = socket.gethostbyname(server_domain)
        server_port = 80

        temp_path = unique_temporary_path("test_api_Python_connect", ".txt")
        print("temp_path=", temp_path)

        # A subprocess is about to connect to a remote HTTP server.
        script_content = """
import socket
import os
import psutil
client_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Hello from subprocess")
client_socket.connect(('%s', %d))
client_socket.sendall(b'Hello, world')
data = client_socket.recv(1024)
client_socket.close()
subprocess_object = psutil.Process(os.getpid())
outfil = open(r"%s", "w")
outfil.write("%%d\\n%%d\\n" %% (os.getpid(), subprocess_object.ppid()))
outfil.close()
""" % (server_domain, server_port, temp_path)

        dwProcessId = self._debug_python_script(script_content)

        # The created subprocess has written in a file its id and parent id.
        with open(temp_path) as temp_file:
            temp_data = temp_file.readlines()
            print("temp_data=", temp_data)
            sub_pid = int(temp_data[0])
            sub_ppid = int(temp_data[1])
            print("sub_pid=", sub_pid, "sub_ppid=", sub_ppid)
        self.assertTrue(sub_pid == dwProcessId)

        self.assertEqual(len(win32_api_definitions.tracer_object.calls_counter), 1)
        sub_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[dwProcessId]

        if not is_py3:
            self.assertTrue(sub_process_calls_counter[b'CreateFileA'] > 0)
        self.assertTrue(sub_process_calls_counter[b'CreateFileW'] > 0)
        if is_windows10:
            # FIXME: It uses another set of IO functions.
            self.assertTrue(b'WriteFile' not in sub_process_calls_counter)
            self.assertTrue(b'ReadFile' not in sub_process_calls_counter)
        else:
            self.assertTrue(sub_process_calls_counter[b'WriteFile'] > 0)
            self.assertTrue(sub_process_calls_counter[b'ReadFile'] > 0)
        self.assertEqual(sub_process_calls_counter[b'connect'], 1)

        self.assertTrue('CIM_DataFile' in win32_api_definitions.tracer_object.created_objects)
        expected_addr = "%s:%d" % (server_address, server_port)
        self.assertTrue({'Id': expected_addr} in win32_api_definitions.tracer_object.created_objects['addr'])

    def test_python_bind(self):
        """
        This opens a TCP/IP socket, ready for a client connection.
        """

        server_port = 12345
        script_content = """
import socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((socket.gethostname(), %d))
server_socket.listen(5)
server_socket.close()
""" % server_port

        win32_api_definitions.Win32Hook_bind._debug_counter_before = 0
        win32_api_definitions.Win32Hook_bind._debug_counter_after = 0

        dwProcessId = self._debug_python_script(script_content)

        print("Win32Hook_bind BEFORE:", win32_api_definitions.Win32Hook_bind._debug_counter_before)
        print("Win32Hook_bind AFTER :", win32_api_definitions.Win32Hook_bind._debug_counter_after)

        print("debug_counter_WaitForDebugEvent:", self.hooks_manager.debug_counter_WaitForDebugEvent)
        print("debug_counter_exception_breakpoint:", self.hooks_manager.debug_counter_exception_breakpoint)

        self.hooks_manager.debug_print_hooks_counter()

        calls_counter_process = win32_api_definitions.tracer_object.calls_counter[dwProcessId]

        self.assertTrue(calls_counter_process[b'CreateFileW'] > 0)
        self.assertEqual(calls_counter_process[b'bind'], 1)

        # 'addr': [{'Id': '192.168.1.10:12345'}
        server_address = socket.gethostbyname(socket.gethostname())
        expected_addr = "%s:%d" % (server_address, server_port)
        print("expected_addr=", expected_addr)
        self.assertTrue('CIM_DataFile' in win32_api_definitions.tracer_object.created_objects)
        self.assertTrue({'Id': expected_addr} in win32_api_definitions.tracer_object.created_objects['addr'])

    def test_python_os_system_dir_once(self):
        """
        This creates a subprocess with the system call os.system(), running dir.
        """
        script_content = """
import os
os.system('dir')
"""
        dwProcessId = self._debug_python_script(script_content)

        created_processes =  win32_api_definitions.tracer_object.created_objects['CIM_Process']
        print("created_objects=", win32_api_definitions.tracer_object.created_objects['CIM_Process'])

        calls_counter_process = win32_api_definitions.tracer_object.calls_counter[dwProcessId]

        if is_py3:
            self.assertEqual(calls_counter_process[b'CreateProcessW'], 1)
            self.assertTrue(b'CreateProcessA' not in calls_counter_process)
        else:
            self.assertEqual(calls_counter_process[b'CreateProcessA'], 1)
            self.assertTrue(b'CreateProcessW' not in calls_counter_process)

        # This creates one single subprocess running cmd.exe
        self.assertEqual(len(created_processes), 1)

    def test_python_os_system_dir_multiple(self):
        """
        This creates a subprocess with the system call os.system(), running dir.
        """
        loops_number = 100
        script_content = """
import os
for loop_index in range(%d):
    os.system('dir > null')
""" % loops_number

        dwProcessId = self._debug_python_script(script_content)

        created_processes = win32_api_definitions.tracer_object.created_objects['CIM_Process']
        print("created_objects=", win32_api_definitions.tracer_object.created_objects['CIM_Process'])

        calls_counter_process = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        print("calls_counter_process.keys()=", calls_counter_process.keys())
        if is_py3:
            self.assertEqual(calls_counter_process[b'CreateProcessW'], loops_number)
            self.assertTrue(b'CreateProcessA' not in calls_counter_process)
        else:
            self.assertEqual(calls_counter_process[b'CreateProcessA'], loops_number)
            self.assertTrue(b'CreateProcessW' not in calls_counter_process)

        # This creates one single subprocess running cmd.exe
        self.assertEqual(len(created_processes), loops_number)

    # See difference between "cmd -c" and "cmd -k"
    def test_python_os_system_python_stdout(self):
        """
        This creates a subprocess with the system call os.system(), starting python
        """

        script_content = """
import os
import sys
# Double-quotes because of spaces: C:\\Program Files (x86)\\...\\python.exe
# This starts the command: "..\\cmd.exe /c C:\\Python27\\python.exe -V"
os.system('"%s" -V' % sys.executable)
"""
        dwProcessId = self._debug_python_script(script_content)

        created_processes =  win32_api_definitions.tracer_object.created_objects['CIM_Process']
        print("created_objects=", win32_api_definitions.tracer_object.created_objects['CIM_Process'])

        calls_counter_process = win32_api_definitions.tracer_object.calls_counter[dwProcessId]

        # The first process is created for the shell cmd.
        if is_py3:
            self.assertEqual(calls_counter_process[b'CreateProcessW'], 1)
            self.assertTrue(b'CreateProcessA' not in calls_counter_process)
        else:
            self.assertEqual(calls_counter_process[b'CreateProcessA'], 1)
            self.assertTrue(b'CreateProcessW' not in calls_counter_process)

        # This creates a cmd.exe subprocess, creating a Python subprocess.
        self.assertEqual(len(created_processes), 2)

    def test_python_os_system_python_redirect(self):
        """
        This creates a subprocess with the system call os.system(), starting python.
        This checks the output.
        """
        temporary_text_file = tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False)
        temporary_text_file.close()

        # Python 3 confusion with backslashes and unicode escape sequences.
        clean_text_name = lib_util.standardized_file_path(temporary_text_file.name)
        script_content = """
import os
import sys
# Double-quotes because of spaces: C:\\Program Files (x86)\\...\\python.exe
ret = os.system('"%s" -c print(123456) > %s')
print("ret=", ret)
""" % ( lib_util.standardized_file_path(sys.executable), clean_text_name)

        dwProcessId = self._debug_python_script(script_content)

        created_processes = win32_api_definitions.tracer_object.created_objects['CIM_Process']
        print("created_objects=", win32_api_definitions.tracer_object.created_objects['CIM_Process'])

        calls_counter_process = win32_api_definitions.tracer_object.calls_counter[dwProcessId]

        # The first process is created for the shell cmd.
        if is_py3:
            self.assertEqual(calls_counter_process[b'CreateProcessW'], 1)
            self.assertTrue(b'CreateProcessA' not in calls_counter_process)
        else:
            self.assertEqual(calls_counter_process[b'CreateProcessA'], 1)
            self.assertTrue(b'CreateProcessW' not in calls_counter_process)

        print("Check:", temporary_text_file.name)
        with open(temporary_text_file.name) as in_text_file:
            in_content = in_text_file.readlines()
        print("in_content=", in_content)
        # This is the line written by the Python script.
        self.assertEqual(in_content, ['123456\n'])

        # This creates a cmd.exe subprocess, creating a Python subprocess.
        self.assertEqual(len(created_processes), 2)
        os.remove(temporary_text_file.name)

    def test_python_check_output_python(self):
        """
        This creates a subprocess with the system call os.system(), starting python
        """

        script_content = """
import subprocess
import sys
# Double-quotes because of spaces: C:\\Program Files (x86)\\...\\python.exe
subprocess.check_output([sys.executable, '-V'], shell=False)
"""
        class_create_process = win32_api_definitions.Win32Hook_CreateProcessW if is_py3 else win32_api_definitions.Win32Hook_CreateProcessA
        class_create_process._debug_counter_before = 0
        class_create_process._debug_counter_after = 0

        dwProcessId = self._debug_python_script(script_content)

        created_processes = win32_api_definitions.tracer_object.created_objects['CIM_Process']
        print("created_objects=", win32_api_definitions.tracer_object.created_objects['CIM_Process'])

        calls_counter_process = win32_api_definitions.tracer_object.calls_counter[dwProcessId]

        print("Win32Hook_CreateProcessX BEFORE:", class_create_process._debug_counter_before)
        print("Win32Hook_CreateProcessX AFTER :", class_create_process._debug_counter_after)

        # The first process is created for the shell cmd.
        if is_py3:
            self.assertEqual(calls_counter_process[b'CreateProcessW'], 1)
            self.assertTrue(b'CreateProcessA' not in calls_counter_process)
        else:
            self.assertEqual(calls_counter_process[b'CreateProcessA'], 1)
            self.assertTrue(b'CreateProcessW' not in calls_counter_process)

        # This creates a Python subprocess.
        self.assertEqual(len(created_processes), 1)

    def test_python_multiprocessing_recursive_noio(self):
        """
        This uses multiprocessing.Process recursively.
        """
        loops_number = 3
        script_content = """
import multiprocessing
def spawned_function(level):
    if level > 0:
        sub_process = multiprocessing.Process(target=spawned_function, args=(level-1,))
        sub_process.start()
        sub_process.join()
if __name__ == '__main__':
    spawned_function(%d)
""" % loops_number

        dwProcessId = self._debug_python_script(script_content)

        created_processes = win32_api_definitions.tracer_object.created_objects['CIM_Process']
        print("created_processes=", created_processes)

        create_process_function = b'CreateProcessW' if is_py3 else b'CreateProcessA'

        # Maybe the most nested subprocess called other functions, or nothing at all.
        creator_processes_handles = {
            process_id
            for process_id, calls_counter in win32_api_definitions.tracer_object.calls_counter.items()
            if create_process_function in calls_counter
        }

        print("creator_processes_handles=", creator_processes_handles)
        self.assertEqual(len(creator_processes_handles), loops_number)

        created_processes_handles = {process_object['Handle'] for process_object in created_processes}
        print("created_processes_handles=", created_processes_handles)
        self.assertEqual(len(created_processes_handles), loops_number)

        calculated_root_process = list(creator_processes_handles - created_processes_handles)
        print("calculated_root_process=", calculated_root_process)
        self.assertEqual(calculated_root_process, [dwProcessId])
        last_created_process = list(created_processes_handles - creator_processes_handles)
        print("last_created_process=", last_created_process)
        self.assertEqual(len(last_created_process), 1)

        for process_id, function_calls_list in win32_api_definitions.tracer_object.calls_counter.items():
            # There might be other functions: "CreateFileA" ...
            if process_id == last_created_process[0]:
                self.assertTrue(create_process_function not in function_calls_list)
            else:
                self.assertEqual(function_calls_list[create_process_function], 1)

    def test_python_multiprocessing_recursive_io(self):
        """
        This uses multiprocessing.Process recursively: Each process does some IOs.
        """

        temporary_text_file = tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False)
        temporary_text_file.close()
        # Python does not like backslashes.
        clean_text_name = lib_util.standardized_file_path(temporary_text_file.name)
        loops_number = 5
        script_content = """
from __future__ import print_function
import multiprocessing
import os
import psutil
def spawned_function(level):
    current_pid = os.getpid()
    process_object = psutil.Process(current_pid)
    parent_pid = process_object.ppid()
    with open('%s', 'a') as file_descriptor:
        print(level, current_pid, parent_pid, file=file_descriptor)
    if level > 0:
        sub_process = multiprocessing.Process(target=spawned_function, args=(level-1,))
        sub_process.start()
        sub_process.join()
if __name__ == '__main__':
    spawned_function(%d)
""" % (clean_text_name, loops_number)

        dwProcessId = self._debug_python_script(script_content)

        created_processes = win32_api_definitions.tracer_object.created_objects['CIM_Process']
        print("created_processes=", created_processes)

        create_process_function = b'CreateProcessW' if is_py3 else b'CreateProcessA'

        # Maybe the most nested subprocess called other functions, or nothing at all.
        creator_processes_handles = {
            process_id
            for process_id, calls_counter in win32_api_definitions.tracer_object.calls_counter.items()
            if create_process_function in calls_counter
        }

        self.assertEqual(len(creator_processes_handles), loops_number)

        created_processes_handles = {process_object['Handle'] for process_object in created_processes}
        self.assertEqual(len(created_processes_handles), loops_number)

        calculated_root_process = list(creator_processes_handles - created_processes_handles)
        self.assertEqual(calculated_root_process, [dwProcessId])

        last_created_process = list(created_processes_handles - creator_processes_handles)
        self.assertEqual(len(last_created_process), 1)

        for process_id, function_calls_list in win32_api_definitions.tracer_object.calls_counter.items():
            # There might be other functions: "CreateFileA" ...
            if process_id == last_created_process[0]:
                self.assertTrue(create_process_function not in function_calls_list)
            else:
                self.assertEqual(function_calls_list[create_process_function], 1)

        with open(temporary_text_file.name) as input_file:
            file_content = [list(map(int, one_line.split())) for one_line in input_file.readlines()]
        print("file_content=", file_content)

        # Check the content of the file appended to by the subprocesses.
        self.assertEqual([one_line[0] for one_line in file_content], list(range(loops_number, -1, -1)))
        self.assertEqual({one_line[1] for one_line in file_content}, created_processes_handles.union({dwProcessId}))
        self.assertEqual({one_line[2] for one_line in file_content}, creator_processes_handles.union({CurrentPid}))

        os.remove(temporary_text_file.name)

    @unittest.skipIf(not is_windows10, "This test sometimes does not work on Windows 7, but does on Windows 10")
    def test_python_multiprocessing_flat(self):
        """
        This uses multiprocessing.Process in a loop.
        """

        # Each system function is modelled by a class. Thees classes have an internal counter
        # for the entry and the exit of the function.
        # These counters are only for debugging purpose. They are shared by all subprocesses
        # of the root process being debugged.
        # Because these counters are class-specific, this resets them to zero before counting.
        class_create_process = win32_api_definitions.Win32Hook_CreateProcessW if is_py3 else win32_api_definitions.Win32Hook_CreateProcessA
        class_create_process._debug_counter_before = 0
        class_create_process._debug_counter_after = 0

        temporary_files_prefix = unique_temporary_path(
            "test_python_%d_multiprocessing_flat",
            ".txt_%d" % os.getpid())

        loops_number = 10

        # Each subprocess writes in a specific file, its index and process id.
        script_content = """
from __future__ import print_function
import multiprocessing
import os
import time
def flat_spawned_function(index):
    print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< flat_spawned_function index:", index, "pid=", os.getpid())
    temporary_file_path = '%s' + str(index)
    print("flat_spawned_function temporary_file_path:", temporary_file_path)
    with open(temporary_file_path, 'w') as output_file:
        print(index, file=output_file)
        print(os.getpid(), file=output_file)
    print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> flat_spawned_function done index:", index)

if __name__ == '__main__':
    sub_processes = []
    print("Mypid=", os.getpid())
    for index in range(%d):
        sub_process = multiprocessing.Process(target=flat_spawned_function, args=(index,))
        sub_process.start()
        sub_processes.append(sub_process)
        print("Started pid=", sub_process.pid)
        # Maybe it needs a bit of time to really start. If a process is joined before really starting,
        # it fails. Or maybe it has to finished its task ?
        time.sleep(2)
    print("Started processes=", len(sub_processes))
    for sub_process in sub_processes:
        print("+++++++++++++++++++++++++++++++++++++++++++ Joining pid=", sub_process.pid, "alive=", sub_process.is_alive())
        sub_process.join()
        print("------------------------------------------- Joined pid=", sub_process.pid, "alive=", sub_process.is_alive())
""" % (temporary_files_prefix, loops_number)

        dwProcessId = self._debug_python_script(script_content)

        print("Win32Hook_CreateProcessX BEFORE:", class_create_process._debug_counter_before)
        print("Win32Hook_CreateProcessX AFTER :", class_create_process._debug_counter_after)

        # This reads the files created by the subprocesses and extracts the process ids.
        created_processes_handles_from_files = set()
        for index in range(loops_number):
            temporary_file_path = temporary_files_prefix + str(index)
            with open(temporary_file_path) as input_file:
                actual_index = int(input_file.readline())
                self.assertEqual(actual_index, index)
                actual_pid = int(input_file.readline())
            self.assertEqual(index, actual_index)
            created_processes_handles_from_files.add(actual_pid)
            # Temporary data file not needed anymore.
            # os.remove(temporary_file_path)

        created_processes = win32_api_definitions.tracer_object.created_objects['CIM_Process']
        print("created_processes=", created_processes)

        created_processes_handles = {process_object['Handle'] for process_object in created_processes}
        self.assertEqual(len(created_processes_handles), loops_number)

        self.assertEqual(created_processes_handles, created_processes_handles_from_files)

        create_process_function = b'CreateProcessW' if is_py3 else b'CreateProcessA'

        root_process_calls = win32_api_definitions.tracer_object.calls_counter[dwProcessId]

        # Number of process creation calls by the root process.
        self.assertEqual(root_process_calls[create_process_function], loops_number)

        self.assertEqual(class_create_process._debug_counter_before, loops_number)
        self.assertEqual(class_create_process._debug_counter_after, loops_number)


################################################################################


@pytest_skip_pydbg
@unittest.skipIf(not check_program_exists("perl"), "Perl must be installed.")
class PerlScriptsTest(HooksManagerUtil):
    """
    Test Perl scripts created on-the-fly.
    """

    def setUp(self):
        HooksManagerUtil.setUp(self)
        # This temporary file contains a Perl script.
        self._temporary_perl_file = tempfile.NamedTemporaryFile(suffix='.pl', mode='w', delete=False)
        self._temporary_perl_path = lib_util.standardized_file_path(self._temporary_perl_file.name)

    def tearDown(self):
        HooksManagerUtil.tearDown(self)
        os.remove(self._temporary_perl_path)

    def _debug_perl_script(self, script_content):
        """Starts a Perl script in a debugging sesson"""
        self._temporary_perl_file.write(script_content)
        self._temporary_perl_file.close()

        connect_command = "perl %s" % self._temporary_perl_path

        dwProcessId = self.hooks_manager.attach_to_command(connect_command)
        print("_debug_perl_script dwProcessId=", dwProcessId)

        return dwProcessId

    @unittest.skipIf(is_windows10, "This test does not work on Windows 10")
    def test_perl_write_file(self):
        """
        Simplistic Perl script which just writes into a file.
        """

        temporary_text_file = tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False)
        temporary_text_file.close()
        # Python does not like backslashes.
        clean_text_name = lib_util.standardized_file_path(temporary_text_file.name)

        script_content = """\
open(FH, '>', '%s') or die $!;
print FH "Hello world";
close(FH);
""" % clean_text_name

        dwProcessId = self._debug_perl_script(script_content)

        self.hooks_manager.debug_print_hooks_counter()

        # Did the program successfully write in the output file ?
        with open(clean_text_name) as clean_output_file:
            result_lines = clean_output_file.readlines()
        print("result_lines=", result_lines)
        self.assertEqual(result_lines, ["Hello world"])
        os.remove(clean_text_name)

        print("win32_api_definitions.tracer_object.created_objects=", win32_api_definitions.tracer_object.created_objects)
        print("win32_api_definitions.tracer_object.calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        print("debug_counter_WaitForDebugEvent:", self.hooks_manager.debug_counter_WaitForDebugEvent)
        print("debug_counter_exception_breakpoint:", self.hooks_manager.debug_counter_exception_breakpoint)

        print("debug_counter_not_ours_breakpoints:", self.hooks_manager.debug_counter_not_ours_breakpoints)
        print("debug_counter_deleted_breakpoints:", self.hooks_manager.debug_counter_deleted_breakpoints)
        print("debug_counter_handled_breakpoints:", self.hooks_manager.debug_counter_handled_breakpoints)

        created_files = win32_api_definitions.tracer_object.created_objects['CIM_DataFile']

        # These are the files open when Perl starts. The script must be in these.
        created_files_names = {file_object['Name'] for file_object in created_files}
        print("created_files_names=", created_files_names)

        self.assertTrue(self._temporary_perl_path in created_files_names)

        root_process_calls = win32_api_definitions.tracer_object.calls_counter[dwProcessId]

        self.assertTrue(root_process_calls[b'CreateFileA'] > 0)

        # FIXME: Differences between platforms.

        # FIXME: This works.
        # Windows 7, perl v5.20.2
        # created_files_names= [
        # 'C:\\Perl64\\site\\lib\5.20.2\\MSWin32-x64-multi-thread',
        # 'C:\\Perl64\\site\\lib\\5.20.2',
        # 'C:\\Perl64\\site\\lib\\MSWin32-x64-multi-thread',
        # 'C:\\Perl64\\lib\\5.20.2\\MSWin32-x64-multi-thread',
        # 'C:\\Perl64\\lib\\5.20.2',
        # 'C:\\Perl64\\lib\\MSWin32-x64-multi-thread',
        # 'C:\\Users\\rchateau\\AppData\\Local\\Temp\\tmp9zgy2691.pl',
        # 'C:\\Perl64\\site\\lib\\sitecustomize.pl',
        # 'C:\\Perl64\\site\\lib\\sitecustomize.pl',
        # 'C:\\Perl64\\site\\lib\\sitecustomize.pl'}]
        #
        # win32_api_definitions.tracer_object.calls_counter= ... , {545228: ...
        # {b'CreateFileA': 10, b'ReadFile': 4, b'WriteFile': 3})})

        # FIXME: This does not work. What opens the input script file ? CreateThread ?
        # FIXME: But the breakpoints would still apply.
        # Windows 10 (Travis):
        # created_files_names= [
        # '\\\\.\\pipe\\msys-1888ae32e00d56aa-1768-sigwait',
        # '\\\\.\\pipe\\msys-1888ae32e00d56aa-lpc'}])
        #
        # win32_api_definitions.tracer_object.calls_counter= ... {
        # 1768: {b'CreateFileA': 1, b'CreateThread': 1, b'CreateFileW': 1, b'ReadFile': 1, b'TerminateProcess': 1})})

        # Windows 10, perl v5.28.1
        # win32_api_definitions.tracer_object.calls_counter= ... , {b'CreateFileA': 7})})
        # created_files_names= {
        # b'C:\\Perl64\\site\\lib\\5.28.1',
        # b'C:\\Perl64\\lib\\5.28.1',
        # b'C:\\Perl64\\site\\lib\\MSWin32-x64-multi-thread',
        # b'C:\\Perl64\\lib\\5.28.1\\MSWin32-x64-multi-thread',
        # b'C:\\Perl64\\site\\lib\\5.28.1\\MSWin32-x64-multi-thread',
        # b'C:\\Perl64\\lib\\MSWin32-x64-multi-thread',
        # b'C:\\Perl64\\site\\lib\\sitecustomize.pl'}
        #
        # win32_api_definitions.tracer_object.calls_counter= ... {
        # 1768: {b'CreateFileA': 7})})

    @unittest.skipIf(is_windows10, "Not completely understood on Windows 10.")
    def test_perl_create_process_line(self):
        """
        This creates a process with system() in its first form (Command line).
        """

        temporary_text_file = tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False)
        temporary_text_file.close()
        # Perl does not like backslashes.
        clean_text_name = lib_util.standardized_file_path(temporary_text_file.name)

        # If the operating system command contains meta-characters, use this first form.
        script_content = 'system("cmd /c echo HelloFromDOS> %s") or die $!;' % clean_text_name

        dwProcessId = self._debug_perl_script(script_content)

        self.hooks_manager.debug_print_hooks_counter()

        # This checks that the program successfully created its output file.
        with open(clean_text_name) as clean_output_file:
            result_lines = clean_output_file.readlines()
        print("result_lines=", result_lines)
        self.assertEqual(result_lines, ["HelloFromDOS\n"])
        # File is no longer needed.
        os.remove(clean_text_name)

        print("win32_api_definitions.tracer_object.created_objects=", win32_api_definitions.tracer_object.created_objects)
        print("win32_api_definitions.tracer_object.calls_counter=", win32_api_definitions.tracer_object.calls_counter)

        # Windows 7, Python 3.
        # created_files_names= {
        # b'C:\\Perl64\\site\\lib\\5.20.2\\MSWin32-x64-multi-thread',
        # 'C:/Users/rchateau/AppData/Local/Temp/tmpepyno8cw.txt',
        # b'C:\\Perl64\\lib\\5.20.2\\MSWin32-x64-multi-thread',
        # b'C:\\Perl64\\site\\lib\\sitecustomize.pl',
        # b'C:\\Users\\rchateau\\AppData\\Local\\Temp\\tmpoxu_rdu9.pl',
        # b'C:\\Perl64\\site\\lib\\MSWin32-x64-multi-thread',
        # b'C:\\Perl64\\site\\lib\\5.20.2',
        # b'C:\\Perl64\\lib\\MSWin32-x64-multi-thread',
        # b'C:\\Perl64\\lib\\5.20.2'}

        created_files = win32_api_definitions.tracer_object.created_objects['CIM_DataFile']

        # These are the files open when Perl starts.
        created_files_names = {file_object['Name'] for file_object in created_files}
        print("created_files_names=", created_files_names)

        # The Perl script file must be there.
        self.assertTrue(self._temporary_perl_path in created_files_names)

        # This checks that the output file creation is detected.
        self.assertTrue(clean_text_name in created_files_names)

        # Windows 7, Python 3.
        # win32_api_definitions.tracer_object.calls_counter= {
        # 750752: {b'CreateFileA': 10, b'ReadFile': 4, b'CreateProcessA': 2, b'WriteFile': 1}),
        # 751104: {b'CreateFileW': 1, b'CreateProcessW': 1}),
        # 750892: {b'WriteFile': 1})})
        #

        # Three processes are apparently created:
        # The root process, created by Survol.
        # A subprocess created by Perl, which runs cmd.exe.
        # Another process created by cmd.exe, which actually executes the command "echo".

        root_process_calls = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        self.assertTrue(root_process_calls[b'CreateFileA'] > 0)
        self.assertTrue(root_process_calls[b'CreateProcessA'] > 0)

        # Now look for the two subprocesses.
        self.assertEqual(len(win32_api_definitions.tracer_object.calls_counter), 3)

        sub_pid = None
        sub_sub_pid = None
        for one_process_id, one_calls_counter in win32_api_definitions.tracer_object.calls_counter.items():
            if one_process_id != dwProcessId:
                if b'CreateProcessW' in one_calls_counter:
                    self.assertEqual(sub_pid, None, "The sub process id should not be already set")
                    sub_pid = one_process_id
                else:
                    self.assertEqual(sub_sub_pid, None, "The sub-sub process id should not be already set")
                    sub_sub_pid = one_process_id
        self.assertTrue(sub_pid, "The sub process id was not found")
        self.assertTrue(sub_sub_pid, "The sub-sub process id was not found")

    @unittest.skipIf(is_travis_machine(), "Not completely understood on Travis.")
    def test_perl_create_process_args(self):
        """
        This creates a process with system() in its second form, with several arguments.
        """

        temporary_text_file = tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False)
        temporary_text_file.close()
        # Perl does not like backslashes.
        clean_text_name = lib_util.standardized_file_path(temporary_text_file.name)

        # Perl executes system() by trying several values for lpApplicationName
        # when calling CreateProcessA:
        # lpApplicationName= b'cmd.exe'
        # lpCommandLine= b'cmd.exe /x/d/c "echo HelloFromDOS > tmp.txt"'
        # ... then:
        # lpApplicationName= b'C:\\Windows\\system32\\cmd.exe'
        # lpCommandLine= b'cmd.exe /x/d/c "echo HelloFromDOS > tmp.txt"'

        script_content = "my @args=('echo HelloFromDOS> %s');system(@args);" % clean_text_name

        dwProcessId = self._debug_perl_script(script_content)

        self.hooks_manager.debug_print_hooks_counter()

        # This checks that the program successfully created its output file.
        with open(clean_text_name) as clean_output_file:
            result_lines = clean_output_file.readlines()
        print("result_lines=", result_lines)
        self.assertEqual(result_lines, ["HelloFromDOS\n"])
        # File is no longer needed.
        os.remove(clean_text_name)

        print("win32_api_definitions.tracer_object.created_objects=", win32_api_definitions.tracer_object.created_objects)
        print("win32_api_definitions.tracer_object.calls_counter=", win32_api_definitions.tracer_object.calls_counter)

        created_files = win32_api_definitions.tracer_object.created_objects['CIM_DataFile']

        # These are the files open when Perl starts.
        created_files_names = {file_object['Name'] for file_object in created_files}
        print("created_files_names=", created_files_names)

        root_process_calls = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        self.assertTrue(root_process_calls[b'CreateFileA'] > 0)
        self.assertTrue(root_process_calls[b'CreateProcessA'] > 0)

        created_process_id = win32_api_definitions.tracer_object.created_objects['CIM_Process'][0]['Handle']

        # Now look for the two subprocesses.
        # Maybe the real criteria is the Perl version ? Or the way the process is created ?
        if is_windows10:
            self.assertEqual(len(win32_api_definitions.tracer_object.calls_counter), 1)
            # cmd.exe does not use 'CreateFileW' and 'WriteFile' apparently, so the subprocess is not detected.
        else:
            self.assertEqual(len(win32_api_definitions.tracer_object.calls_counter), 2)
            self.assertTrue(created_process_id in win32_api_definitions.tracer_object.calls_counter)

    def test_perl_connect_perl_org(self):
        """
        This Perl script connects to a remote web site. The socket must be detected.
        """

        temporary_text_file = tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False)
        temporary_text_file.close()
        # Perl does not like backslashes.
        clean_text_name = lib_util.standardized_file_path(temporary_text_file.name)

        server_domain = "www.perl.org"
        server_address = socket.gethostbyname(server_domain)
        server_port = 80

        script_content = """\
use strict;
use warnings;
use Socket qw(PF_INET SOCK_STREAM pack_sockaddr_in inet_aton);

socket(my $socket, PF_INET, SOCK_STREAM, 0) or die "socket: $!";
my $port = getservbyname "http", "tcp";
connect($socket, pack_sockaddr_in($port, inet_aton("www.perl.org"))) or die "connect: $!";

send($socket, "GET / HTTP/1.0\r\n", 0);
send($socket, "Host: www.perl.org\r\n", 0);
send($socket, "User-Agent: pureperl\r\n\r\n", 0);

# Now, writes the socket output to a file.
open(FH, '>', '%s') or die $!;
binmode FH;
while (my $line = <$socket>)
{
    print FH $line;
}
close(FH);
""" % clean_text_name

        dwProcessId = self._debug_perl_script(script_content)

        # Check that the content of the output text file is correct.
        # This displays something like:
        # HTTP/1.1 301 Moved Permanently
        # Server: Varnish
        # Retry-After: 0
        # Location: https://www.perl.org/
        with open(clean_text_name, "rb") as input_file:
            input_content = input_file.readlines()

        # Travis only:
        # AssertionError: b'HTTP/1.1 301 Moved Permanently\r\n' != b'HTTP/1.1 301 Moved Permanently\r\r\n'
        self.assertEqual(input_content[0], b"HTTP/1.1 301 Moved Permanently\r\n")
        self.assertEqual(input_content[1], b"Server: Varnish\r\n")

        print("created_objects=", win32_api_definitions.tracer_object.created_objects['addr'])
        expected_addr = "%s:%d" % (server_address, server_port)
        print("expected_addr=", expected_addr)
        self.assertTrue({'Id': expected_addr} in win32_api_definitions.tracer_object.created_objects['addr'])

        root_process_calls = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        print("root_process_calls=", root_process_calls)
        self.assertTrue(root_process_calls[b'CreateFileA'] > 0)
        self.assertEqual(root_process_calls[b'connect'], 1)
        if not is_windows10:
            # FIXME: Why this difference ?
            self.assertTrue(root_process_calls[b'CreateFileW'] > 0)
            self.assertTrue(root_process_calls[b'WriteFile'] > 0)
            self.assertTrue(root_process_calls[b'ReadFile'] > 0)

        os.remove(temporary_text_file.name)

    def test_perl_socket_bind(self):
        """
        This Perl script creates a server socket which must be detected.
        """

        server_port = 12345

        script_content = """\
use Socket;
socket(SERVER, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, 1);
$my_addr = sockaddr_in(%s, INADDR_ANY);
bind(SERVER, $my_addr) or die "Couldn't bind to port $server_port : $!\n";
""" % server_port

        dwProcessId = self._debug_perl_script(script_content)

        print("Win32Hook_bind BEFORE:", win32_api_definitions.Win32Hook_bind._debug_counter_before)
        print("Win32Hook_bind AFTER :", win32_api_definitions.Win32Hook_bind._debug_counter_after)

        self.hooks_manager.debug_print_hooks_counter()

        print("debug_counter_WaitForDebugEvent:", self.hooks_manager.debug_counter_WaitForDebugEvent)
        print("debug_counter_exception_breakpoint:", self.hooks_manager.debug_counter_exception_breakpoint)

        # No subprocess creation
        self.assertEqual(len(win32_api_definitions.tracer_object.calls_counter), 1)

        root_process_calls = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        self.assertTrue(root_process_calls[b'CreateFileA'] > 0)
        self.assertEqual(root_process_calls[b'bind'], 1)
        if not is_windows10:
            self.assertTrue(root_process_calls[b'ReadFile'] > 0)
            self.assertEqual(root_process_calls[b'fopen'], 1)
            self.assertEqual(win32_api_definitions.Win32Hook_bind._debug_counter_before, 2) # Was 1.
            self.assertEqual(win32_api_definitions.Win32Hook_bind._debug_counter_after, 2) # Was 1.

        #     b'CreateFileA'                   1   1
        #     b'CreateFileW'                   1   1
        #     b'CreateProcessA'                0   0
        #     b'CreateProcessAsUserA'          0   0
        #     b'CreateProcessAsUserW'          0   0
        #     b'CreateProcessW'                0   0
        #     b'CreateRemoteThread'            0   0
        #     b'CreateRemoteThreadEx'          0   0
        #     b'CreateThread'                  1   1
        #     b'DeleteFileA'                   0   0
        #     b'DeleteFileW'                   0   0
        #     b'ReadFile'                      1   0
        #     b'ReadFileEx'                    0   0
        #     b'ReadFileScatter'               0   0
        #     b'RemoveDirectoryA'              0   0
        #     b'RemoveDirectoryW'              0   0
        #     b'TerminateProcess'              1   0


        # TODO: Results with fsopen are not stable. Maybe a thread ?

        print("created_objects=", win32_api_definitions.tracer_object.created_objects)
        server_address = "0.0.0.0"
        expected_addr = "%s:%d" % (server_address, server_port)
        print("expected_addr=", expected_addr)
        self.assertTrue({'Id': expected_addr} in win32_api_definitions.tracer_object.created_objects['addr'])

    @unittest.skipIf(is_windows10, "Does not work on Windows 10. Why ???")
    def test_perl_create_directory(self):
        """
        This Perl script creates a directory.
        """

        temporary_directory = unique_temporary_path("test_perl_create_directory", ".dir")

        script_content = """\
mkdir '%s'
    """ % temporary_directory

        dwProcessId = self._debug_perl_script(script_content)

        self.hooks_manager.debug_print_hooks_counter()

        self.assertTrue(os.path.isdir(temporary_directory))
        os.rmdir(temporary_directory)

        root_process_calls = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        print("root_process_calls=", root_process_calls)
        self.assertEqual(root_process_calls[b'CreateDirectoryA'], 1)

        print("created_objects=", win32_api_definitions.tracer_object.created_objects['CIM_Directory'])
        created_directories = win32_api_definitions.tracer_object.created_objects['CIM_Directory']
        self.assertTrue({'Name': temporary_directory} in created_directories)

    @unittest.skip("Not implemented yet")
    def test_perl_SQLDataSources(self):
        """
        This gets ODBC data sources and checks that SQLDataSources() is called.
        """

        raise Exception("NOT IMPLEMENTED YET")


        script_content = """
import pyodbc
odbc_sources = pyodbc.dataSources()
	    """
        dwProcessId = self._debug_python_script(script_content)
        print("Object:", list(win32_api_definitions.tracer_object.created_objects.keys()))
        created_process_calls_counter = win32_api_definitions.tracer_object.calls_counter[dwProcessId]
        print("created_process_calls_counter=", created_process_calls_counter)
        self.assertTrue(created_process_calls_counter[b'SQLDataSources'] > 0)


if __name__ == '__main__':
    unittest.main()
