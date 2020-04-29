from __future__ import print_function

import os
import sys
import unittest
import socket
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

    def test_cmd_create_process(self):
        num_loops = 2
        create_process_command = windows_system32_cmd_exe + " /c "+ "FOR /L %%A IN (1,1,%d) DO ( ping -n 1 127.0.0.1)" % num_loops

        hooks_manager = win32_api_definitions.Win32Hook_Manager()
        hooks_manager.attach_to_command(create_process_command, win32_api_definitions.functions_list)

        print("test_dos_create_process calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        if is_travis_machine():
            # FIXME: The Python implementation used by Travis is based on another set of IO functions.
            self.assertTrue(b'WriteFile' not in win32_api_definitions.tracer_object.calls_counter)
        else:
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'WriteFile'] > 0)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateProcessW'] == num_loops)

        print("test_dos_create_process created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue('CIM_Process' in win32_api_definitions.tracer_object.created_objects)

    def test_cmd_delete_file(self):
        num_loops = 3
        temp_path = unique_temporary_path("test_basic_delete_file", ".txt")
        delete_file_command = windows_system32_cmd_exe + " /c "+ "FOR /L %%A IN (1,1,%d) DO ( ping -n 1 127.0.0.1 > %s &del %s)" % (num_loops, temp_path, temp_path)

        hooks_manager = win32_api_definitions.Win32Hook_Manager()
        hooks_manager.attach_to_command(delete_file_command, win32_api_definitions.functions_list)

        print("test_dos_delete_file calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateProcessW'] == num_loops)
        if is_travis_machine():
            # FIXME: The Python implementation used by Travis is based on another set of IO functions.
            self.assertTrue(b'WriteFile' not in win32_api_definitions.tracer_object.calls_counter)
            self.assertTrue(b'CreateFileW' not in win32_api_definitions.tracer_object.calls_counter)
            self.assertTrue(b'DeleteFileW' not in win32_api_definitions.tracer_object.calls_counter)
        else:
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'WriteFile'] > 0)
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateFileW'] == num_loops)
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'DeleteFileW'] == num_loops)

        print("test_dos_delete_file created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue('CIM_Process' in win32_api_definitions.tracer_object.created_objects)
        if is_travis_machine():
            # FIXME: The Python implementation used by Travis is based on another set of IO functions.
            self.assertTrue('CIM_DataFile' not in win32_api_definitions.tracer_object.created_objects)
        else:
            self.assertTrue({'Name': temp_path} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])

    def test_cmd_ping_type(self):
        num_loops = 2
        dir_command = windows_system32_cmd_exe + " /c "+ "FOR /L %%A IN (1,1,%d) DO ( ping -n 1 1.2.3.4 & type something.xyz )" % num_loops

        hooks_manager = win32_api_definitions.Win32Hook_Manager()
        hooks_manager.attach_to_command(dir_command, win32_api_definitions.functions_list)

        print("test_dos_dir calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateProcessW'] == num_loops)
        if is_travis_machine():
            # FIXME: The Python implementation used by Travis is based on another set of IO functions.
            self.assertTrue(b'WriteFile' not in win32_api_definitions.tracer_object.calls_counter)
            self.assertTrue(b'CreateFileW' not in win32_api_definitions.tracer_object.calls_counter)
        else:
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'WriteFile'] > 0)
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateFileW'] == num_loops)

        print("test_dos_dir created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue('CIM_Process' in win32_api_definitions.tracer_object.created_objects)
        self.assertTrue({'Name': 'something.xyz'} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])

    def test_cmd_type(self):
        num_loops = 2
        dir_command = windows_system32_cmd_exe + " /c "+ "FOR /L %%A IN (1,1,%d) DO type something.xyz )" % num_loops

        hooks_manager = win32_api_definitions.Win32Hook_Manager()
        hooks_manager.attach_to_command(dir_command, win32_api_definitions.functions_list)

        print("test_dos_dir calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateFileW'] == 2 * num_loops)
        if is_travis_machine():
            # FIXME: The Python implementation used by Travis is based on another set of IO functions.
            self.assertTrue(b'WriteFile' not in win32_api_definitions.tracer_object.calls_counter)
        else:
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'WriteFile'] > 0)

        print("test_dos_dir created_objects=", win32_api_definitions.tracer_object.created_objects.keys())
        print("test_dos_dir created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue( list(win32_api_definitions.tracer_object.created_objects.keys()) == ['CIM_DataFile'])
        self.assertTrue({'Name': 'something.xyz'} in win32_api_definitions.tracer_object.created_objects['CIM_DataFile'])

    def test_cmd_mkdir_rmdir(self):
        temp_path = unique_temporary_path("test_cmd_mkdir_rmdir", ".dir")

        dir_mk_rm_command = windows_system32_cmd_exe + " /c "+ "mkdir %s&rmdir %s" % (temp_path, temp_path)

        hooks_manager = win32_api_definitions.Win32Hook_Manager()
        hooks_manager.attach_to_command(dir_mk_rm_command, win32_api_definitions.functions_list)

        print("test_cmd_mkdir_rmdir calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateDirectoryW'] == 1)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'RemoveDirectoryW'] == 1)

        print("test_cmd_mkdir_rmdir created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue({'Name': temp_path} in win32_api_definitions.tracer_object.created_objects['CIM_Directory'])

    @unittest.skip("FIXME")
    def test_cmd_nslookup(self):
        nslookup_command = windows_system32_cmd_exe + " /c "+ "nslookup primhillcomputers.com"
        # It seems nslookup needs to be started from a cmd process, otherwise it crashes.
        # nslookup_command = r"C:\Windows\System32\nslookup.exe primhillcomputers.com"

        hooks_manager = win32_api_definitions.Win32Hook_Manager()
        hooks_manager.attach_to_command(nslookup_command, win32_api_definitions.functions_list)

        # Typical answer:
        # > Server:  UnKnown
        # Address:  fe80::22b0:1ff:fea4:4672
        #
        # Name:    primhillcomputers.com
        # Address:  164.132.235.17
        # The port number must be 53, for DNS.

        print("test_DOS_nslookup calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        # Ca cree un process. Pourquoi ? Supposons que cmd.exe cree un process pour nslookup,
        # mais on n en aurait l id.
        # Et que multiprocess.process ou POpen renvoie l id du sous-process,
        # et donc qu on attach correctement au bon pid.
        # Mais dans ce cas en effet, test_api_Python_connect ne cree pas de sous process mais on devrait
        # voir arriver la dll car on est dans le bon process.
        # Et on ne voit pas passer la dll python.
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateProcessW'] > 0)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'connect'] == 123)

        print("test_DOS_nslookup created_objects=", win32_api_definitions.tracer_object.created_objects)
        self.assertTrue('CIM_DataFile' in win32_api_definitions.tracer_object.created_objects)

    def test_api_Python_connect(self):
        """
        This does a TCP/IP connection to Primhill Computers website.
        The call to socket() is detected, the IP address and the port number are reported.
        """

        server_domain = "primhillcomputers.com"
        server_address = socket.gethostbyname(server_domain)
        server_port = 80

        temp_path = unique_temporary_path("test_api_Python_connect", ".txt")
        print("temp_path=", temp_path)

        # A subprocess is about to loop on a socket connection to a remote machine.
        temporary_python_file = tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False)
        script_content = """
import socket
import time
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Hello from subprocess")
s.connect(('%s', %d))
s.sendall(b'Hello, world')
data = s.recv(1024)
s.close()
import os
import psutil
subprocess_object = psutil.Process(os.getpid())
outfil = open(r"%s", "w")
outfil.write("%%d\\n%%d\\n" %% (os.getpid(), subprocess_object.ppid()))
outfil.close()
""" % (server_domain, server_port, temp_path)
        temporary_python_file.write(script_content)
        temporary_python_file.close()

        connect_command = "%s %s" % (sys.executable, temporary_python_file.name)

        hooks_manager = win32_api_definitions.Win32Hook_Manager()

        dwProcessId = hooks_manager.attach_to_command(connect_command, win32_api_definitions.functions_list)
        print("dwProcessId=", dwProcessId)

        with open(temp_path) as temp_file:
            temp_data = temp_file.readlines()
            print("temp_data=", temp_data)
            sub_pid = int(temp_data[0])
            sub_ppid = int(temp_data[1])
            print("sub_pid=", sub_pid, "sub_ppid=", sub_ppid)
        self.assertTrue(sub_pid== dwProcessId)

        print("test_api_Python_connect calls_counter=", win32_api_definitions.tracer_object.calls_counter)
        if not is_py3:
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateFileA'] > 0)
        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'CreateFileW'] > 0)
        if is_travis_machine():
            # FIXME: It uses another set of IO funcitons.
            self.assertTrue(b'WriteFile' not in win32_api_definitions.tracer_object.calls_counter)
            self.assertTrue(b'ReadFile' not in win32_api_definitions.tracer_object.calls_counter)
        else:
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'WriteFile'] == 2)
            self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'ReadFile'] > 0)

        self.assertTrue(win32_api_definitions.tracer_object.calls_counter[b'connect'] == 1)

        # print("test_api_Python_connect created_objects=", win32_api_definitions.tracer_object.created_objects)
        expected_addr = "%s:%s" % (server_address, server_port)
        self.assertTrue('CIM_DataFile' in win32_api_definitions.tracer_object.created_objects)
        self.assertTrue({'Id': expected_addr} in win32_api_definitions.tracer_object.created_objects['addr'])
        os.remove(temporary_python_file.name)


if __name__ == '__main__':
    unittest.main()
