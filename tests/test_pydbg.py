#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import six
import subprocess
import tempfile
import unittest

# This loads the module from the source, so no need to install it, and no need of virtualenv.
# This is needed when running from PyCharm.
sys.path.append("../survol/scripts")
sys.path.append("survol/scripts")
print("cwd=%s" % os.getcwd())

root_process_id = os.getpid()

from init import *

if not is_platform_linux:
    from pydbg import pydbg

    def create_pydbg():
        if sys.version_info < (3, 8):
            tst_pydbg = pydbg()
        else:
            tst_pydbg = pydbg.pydbg.pydbg()
        return tst_pydbg

################################################################################

@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgDosCmdHooksTest(unittest.TestCase):
    """
    Test pydbg with DOS CMD processes.
    These tests hook specific Win32 API functions and start DOC CMD processes
    doing things which should trigger calls to these system functions.
    Calls to these funcitons are then detected and reported.
    """

    # This tests the callbacks which are used for good in other tests.
    # It starts a DOS process which attempts to remove a directory.
    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_pydbg_DOS_RemoveDirectoryW(self):
        import pydbg
        from pydbg import defines
        from pydbg import utils

        tst_pydbg = create_pydbg()

        num_loops = 4
        non_existent_dir = "NonExistentDir"

        # This attempts several times to remove a non-existent dir.
        # This is detected by the hook.
        rmdir_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 >NUL & echo %%A & rmdir %s )" % (num_loops, non_existent_dir)

        created_process = subprocess.Popen(rmdir_command, shell=True)
        print("Created process:%d" % created_process.pid)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Attaching. Root pid=%d" % root_process_id)
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

            # object_pydbg.dbg is a LPDEBUG_EVENT, pointer to DEBUG_EVENT.
            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId, type(object_pydbg.dbg.dwProcessId))
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return defines.DBG_CONTINUE

        def callback_RemoveDirectoryW_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            dir_name = object_pydbg.get_wstring(args[0])
            print("callback_RemoveDirectoryW_exit dir_name=", dir_name, function_result)
            self.assertTrue(dir_name == non_existent_dir)
            self.assertTrue(function_result == 0)

            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId, type(object_pydbg.dbg.dwProcessId))
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

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

    # It starts a DOS process which attempts to remove a directory.
    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_pydbg_DOS_DeleteFileW(self):
        import pydbg
        from pydbg import defines
        from pydbg import utils

        tst_pydbg = create_pydbg()

        num_loops = 3
        temp_file = "Temporary_%d_%d.xyz" % (os.getpid(), int(time.time()))
        temp_path = os.path.join( tempfile.gettempdir(), temp_file)

        # This creates a file then removes it, several times.
        # This is detected by the hook.
        del_file_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 >%s & echo %%A & del %s )" % (num_loops, temp_path, temp_path)

        created_process = subprocess.Popen(del_file_command, shell=True)
        print("Created process:%d" % created_process.pid)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Attaching. Root pid=%d" % root_process_id)
        tst_pydbg.attach(created_process.pid)

        object_hooks = pydbg.utils.hook_container()

        hook_address_DeleteFileW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"DeleteFileW")

        tst_pydbg.count_entry = 0
        tst_pydbg.count_exit = 0

        def callback_DeleteFileW_entry(object_pydbg, args):
            object_pydbg.count_entry += 1
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_DeleteFileW_entry file_name=", file_name)
            print("callback_DeleteFileW_entry getcwd=", os.getcwd())
            self.assertTrue(file_name == temp_path)

            # object_pydbg.dbg is a LPDEBUG_EVENT, pointer to DEBUG_EVENT.
            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId, type(object_pydbg.dbg.dwProcessId))
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return defines.DBG_CONTINUE

        def callback_DeleteFileW_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_DeleteFileW_exit file_name=", file_name, function_result)
            self.assertTrue(file_name == temp_path)

            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId, type(object_pydbg.dbg.dwProcessId))
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_DeleteFileW,
            1,
            callback_DeleteFileW_entry,
            callback_DeleteFileW_exit)

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
        type_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 & echo %%A & type %s )" % (num_loops, non_existent_file)

        created_process = subprocess.Popen(type_command, shell=True)
        print("Created process:%d" % created_process.pid)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Attaching. Root pid=%d" % root_process_id)
        tst_pydbg.attach(created_process.pid)

        object_hooks = pydbg.utils.hook_container()

        hook_address_CreateFileW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateFileW")

        tst_pydbg.count_entry = 0
        tst_pydbg.count_exit = 0

        def callback_CreateFileW_entry(object_pydbg, args):
            object_pydbg.count_entry += 1
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_CreateFileW_entry file_name=", file_name)
            self.assertTrue(file_name == non_existent_file)
            return defines.DBG_CONTINUE

        def callback_CreateFileW_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_CreateFileW_exit file_name=", file_name, function_result)
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

    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_pydbg_DOS_CreateProcessW(self):
        import pydbg
        from pydbg import utils

        tst_pydbg = create_pydbg()

        num_loops = 3

        # Each loop creates a sub-process which immediately exists.
        # This is detected by the hook.
        ping_echo_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1& echo %%A )" % num_loops

        created_process = subprocess.Popen(ping_echo_command, shell=True)
        print("Created process:%d" % created_process.pid)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Attaching. Root pid=%d" % root_process_id)
        tst_pydbg.attach(created_process.pid)

        object_hooks = pydbg.utils.hook_container()

        hook_address_CreateProcessW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateProcessW")

        tst_pydbg.count_entry = 0
        tst_pydbg.count_exit = 0

        #         BOOL CreateProcessW(
        #             LPCWSTR               lpApplicationName,
        #             LPWSTR                lpCommandLine,
        #             LPSECURITY_ATTRIBUTES lpProcessAttributes,
        #             LPSECURITY_ATTRIBUTES lpThreadAttributes,
        #             BOOL                  bInheritHandles,
        #             DWORD                 dwCreationFlags,
        #             LPVOID                lpEnvironment,
        #             LPCWSTR               lpCurrentDirectory,
        #             LPSTARTUPINFOW        lpStartupInfo,
        #             LPPROCESS_INFORMATION lpProcessInformation

        def callback_CreateProcessW_entry(object_pydbg, args):
            object_pydbg.count_entry += 1
            lpApplicationName = object_pydbg.get_wstring(args[0])
            print("callback_CreateProcessW_entry lpApplicationName=", lpApplicationName)
            assert lpApplicationName == r"C:\windows\system32\PING.EXE"
            lpCommandLine = object_pydbg.get_wstring(args[1])
            print("callback_CreateProcessW_entry lpCommandLine=%s." % lpCommandLine)
            assert lpCommandLine == "ping  -n 2 127.0.0.1"

            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId, type(object_pydbg.dbg.dwProcessId))
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return pydbg.defines.DBG_CONTINUE

        def callback_CreateProcessW_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            lpApplicationName = object_pydbg.get_wstring(args[0])
            print("callback_CreateProcessW_entry lpApplicationName=", lpApplicationName)
            assert lpApplicationName == r"C:\windows\system32\PING.EXE"
            lpCommandLine = object_pydbg.get_wstring(args[1])
            print("callback_CreateProcessW_entry lpCommandLine=%s." % lpCommandLine)
            assert lpCommandLine == "ping  -n 2 127.0.0.1"

            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId, type(object_pydbg.dbg.dwProcessId))
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return pydbg.defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_CreateProcessW,
            10,
            callback_CreateProcessW_entry,
            callback_CreateProcessW_exit)

        tst_pydbg.run()

        print("END", tst_pydbg.count_entry, tst_pydbg.count_exit)
        # The first call is missed.
        self.assertTrue(tst_pydbg.count_entry == num_loops - 1)
        self.assertTrue(tst_pydbg.count_exit == num_loops - 1)

    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_pydbg_DOS_process_information(self):
        import pydbg
        from pydbg import utils
        from pydbg import windows_h

        tst_pydbg = create_pydbg()

        num_loops = 3

        # Each loop creates a sub-process which immediately exists.
        # This is detected by the hook.
        ping_command = "FOR /L %%A IN (1,1,%d) DO (ping -n 2 127.0.0.1)" % num_loops

        created_process = subprocess.Popen(ping_command, shell=True)
        print("Created process:%d" % created_process.pid)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Attaching. Root pid=%d" % root_process_id)
        tst_pydbg.attach(created_process.pid)

        object_hooks = pydbg.utils.hook_container()

        hook_address_process_information = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateProcessW")
        # hook_address_process_information=0000000076ed05e0
        print("hook_address_process_information=%016x" % hook_address_process_information)

        tst_pydbg.count_entry = 0
        tst_pydbg.count_exit = 0

        def callback_process_information_entry(object_pydbg, args):
            object_pydbg.count_entry += 1
            lpApplicationName = object_pydbg.get_wstring(args[0])
            print("callback_process_information_entry lpApplicationName=", lpApplicationName)
            assert lpApplicationName == r"C:\windows\system32\PING.EXE"
            lpCommandLine = object_pydbg.get_wstring(args[1])
            print("callback_process_information_entry lpCommandLine=%s." % lpCommandLine)
            assert lpCommandLine == "ping  -n 2 127.0.0.1"

            lpProcessInformation = args[9]

            # _PROCESS_INFORMATION {
            #   HANDLE hProcess;
            #   HANDLE hThread;
            #   DWORD  dwProcessId;
            #   DWORD  dwThreadId;
            # }
            offset_dwProcessId = windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.HANDLE)
            dwProcessId = object_pydbg.get_long(lpProcessInformation + offset_dwProcessId)
            print("callback_process_information_entry Handle=", dwProcessId)

            offset_dwThreadId = windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.DWORD)
            dwThreadId = object_pydbg.get_long(lpProcessInformation + offset_dwThreadId)
            print("callback_process_information_entry dwThreadId=", dwThreadId)

            # object_pydbg.dbg is a LPDEBUG_EVENT, pointer to DEBUG_EVENT.
            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId, type(object_pydbg.dbg.dwProcessId))
            print("object_pydbg.dbg.dwThreadId=", object_pydbg.dbg.dwThreadId)
            ### assert object_pydbg.dbg.dwProcessId == long(root_process_id)

            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return pydbg.defines.DBG_CONTINUE

        def callback_process_information_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            lpApplicationName = object_pydbg.get_wstring(args[0])
            print("callback_process_information_exit lpApplicationName=", lpApplicationName)
            assert lpApplicationName == r"C:\windows\system32\PING.EXE"
            lpCommandLine = object_pydbg.get_wstring(args[1])
            print("callback_process_information_exit lpCommandLine=%s." % lpCommandLine)
            assert lpCommandLine == "ping  -n 2 127.0.0.1"

            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return pydbg.defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_process_information,
            10,
            callback_process_information_entry,
            callback_process_information_exit)

        tst_pydbg.run()

        print("END", tst_pydbg.count_entry, tst_pydbg.count_exit)
        # The first call is missed.
        self.assertTrue(tst_pydbg.count_entry == num_loops - 1)
        self.assertTrue(tst_pydbg.count_exit == num_loops - 1)

    # https://github.com/OpenRCE/pydbg/issues/5
    # from pydbg import *
    # from pydbg.defines import *
    # import pefile
    #
    # dbg = pydbg()
    # dbg.load("c:\windows\system32\notepad.exe")
    # pe = pefile.PE("C:\Windows\System32\notepad.exe")
    # entrypoint = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    # dbg.bp_set(entrypoint)
    # pydbg.debug_event_loop(dbg)



    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_pydbg_DOS_socket(self):
        import pydbg
        from pydbg import defines
        from pydbg import utils

        tst_pydbg = create_pydbg()

        num_loops = 5

        # This attempts several times to remove a non-existent dir.
        # This is detected by the hook.
        nslookup_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 1.2.3.4 & echo %%A & nslookup any.thing.com )" % num_loops

        created_process = subprocess.Popen(nslookup_command, shell=True)
        print("Created process:%d" % created_process.pid)

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Attaching. Root pid=%d" % root_process_id)
        tst_pydbg.attach(created_process.pid)

        object_hooks = pydbg.utils.hook_container()

        import socket


        # "C:\Windows\System32\ws2_32.dll"
        # Windows Socket 2.0 32-Bit DLL
        # Dump of file C:\Windows\System32\ws2_32.dll
        #             8664 machine (x64)

        # "C:\Windows\System32\kernel32.dll"
        # Windows NT BASE API Client DLL

        # hook_address_socket = tst_pydbg.func_resolve_experimental(u"Ws2_32.dll", b"socket")
        hook_address_socket = tst_pydbg.func_resolve_experimental(ur"C:\Windows\System32\ws2_32.dll", b"socket")
        assert hook_address_socket
        print("hook_address_socket=%016x" % hook_address_socket)
        # hook_address_process_information=0000000076ed05e0 OK
        # hook_address_socket             =000007feff0ed910 Broken.

        tst_pydbg.count_entry = 0
        tst_pydbg.count_exit = 0

        def callback_socket_entry(object_pydbg, args):
            object_pydbg.count_entry += 1
            print("callback_socket_entry args=", args)
            return defines.DBG_CONTINUE

        def callback_socket_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            print("callback_socket_exit args=", args, function_result)

            is_invalid_handle = function_result % (1 + defines.INVALID_HANDLE_VALUE) == defines.INVALID_HANDLE_VALUE
            self.assertTrue(is_invalid_handle)
            return defines.DBG_CONTINUE

        # pdx: Failed setting breakpoint at 000007feff0ed910 : [299] ReadProcessMemory(7feff0ed910, 1, read=0):
        # Only part of a ReadProcessMemory or WriteProcessMemory request was completed.
        object_hooks.add(
            tst_pydbg,
            hook_address_socket,
            3,
            callback_socket_entry,
            callback_socket_exit)

        tst_pydbg.run()

        print("END", tst_pydbg.count_entry, tst_pydbg.count_exit)
        # The first call might be missed.
        self.assertTrue(tst_pydbg.count_entry == num_loops)
        self.assertTrue(tst_pydbg.count_exit == num_loops)

@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgPythonHooksTest(unittest.TestCase):
    """
    Test pydbg from Python processes.
    These tests hook specific Win32 API functions and start Python processes
    doing things which should trigger calls to these system functions.
    Calls to these funcitons are then detected and reported.
    """


    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_pydbg_Python_WriteFile(self):
        import pydbg
        from pydbg import defines
        from pydbg import utils
        from pydbg import windows_h

        tst_pydbg = create_pydbg()

        dir_path = os.path.dirname(__file__)
        sys.path.append(dir_path)

        my_env = os.environ.copy()
        tree_depth = 10

        creation_file_process = subprocess.Popen(
            [sys.executable, '-c', 'import time;time.sleep(5.0);f=open(u"tmp.txt", "w");f.close()'],
            stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)

        print("creation_file_process ", creation_file_process.pid)
        sys.stdout.flush()

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Root pid=%d" % root_process_id)
        print("Attaching to pid=%d" % creation_file_process.pid)
        tst_pydbg.attach(creation_file_process.pid)

        object_hooks = pydbg.utils.hook_container()

        hook_address_create_file_w = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateFileW")
        print("hook_address_create_file_w=%016x" % hook_address_create_file_w)

        def callback_create_file_entry(object_pydbg, args):
            print("callback_create_file_entry")
            print("callback_create_file_entry")
            print("callback_create_file_entry")
            print("callback_create_file_entry")
            print("callback_create_file_entry")
            return pydbg.defines.DBG_CONTINUE

        def callback_create_file_exit(object_pydbg, args, function_result):
            print("callback_create_file_exit")
            print("callback_create_file_exit")
            print("callback_create_file_exit")
            print("callback_create_file_exit")
            print("callback_create_file_exit")
            print("callback_create_file_exit")
            return pydbg.defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_create_file_w,
            10,
            callback_create_file_entry,
            callback_create_file_exit)

        print("About to run subprocess")
        tst_pydbg.run()

        print("Finished")







    # Modified Python path so it can find the special module to create a chain of subprocesses.
    @unittest.skip("Does not work")
    def test_pydbg_Python_Subprocesses(self):
        import pydbg
        from pydbg import defines
        from pydbg import utils
        from pydbg import windows_h

        tst_pydbg = create_pydbg()

        dir_path = os.path.dirname(__file__)
        sys.path.append(dir_path)

        my_env = os.environ.copy()
        tree_depth = 10

        top_created_process = subprocess.Popen([sys.executable, '-m', 'create_process_chain', str(tree_depth)],
                                                env = my_env,
                                                stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)

        print("create_process_tree_popen ", top_created_process.pid)
        sys.stdout.flush()

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Root pid=%d" % root_process_id)
        print("Attaching to pid=%d" % top_created_process.pid)
        tst_pydbg.attach(top_created_process.pid)

        object_hooks = pydbg.utils.hook_container()

        hook_address_create_process_w = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateProcessW")
        print("hook_address_create_process_w=%016x" % hook_address_create_process_w)

        def callback_processes_tree_entry(object_pydbg, args):
            lpApplicationName = object_pydbg.get_wstring(args[0])
            print("callback_processes_tree_entry lpApplicationName=", lpApplicationName)
            lpCommandLine = object_pydbg.get_wstring(args[1])
            print("callback_processes_tree_entry lpCommandLine=%s." % lpCommandLine)

            lpProcessInformation = args[9]

            # _PROCESS_INFORMATION {
            #   HANDLE hProcess;
            #   HANDLE hThread;
            #   DWORD  dwProcessId;
            #   DWORD  dwThreadId;
            # }
            offset_dwProcessId = windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.HANDLE)
            dwProcessId = object_pydbg.get_long(lpProcessInformation + offset_dwProcessId)
            print("callback_processes_tree_entry Handle=", dwProcessId)

            offset_dwThreadId = windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.DWORD)
            dwThreadId = object_pydbg.get_long(lpProcessInformation + offset_dwThreadId)
            print("callback_processes_tree_entry dwThreadId=", dwThreadId)

            # object_pydbg.dbg is a LPDEBUG_EVENT, pointer to DEBUG_EVENT.
            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId, type(object_pydbg.dbg.dwProcessId))
            print("object_pydbg.dbg.dwThreadId=", object_pydbg.dbg.dwThreadId)
            ### assert object_pydbg.dbg.dwProcessId == long(root_process_id)

            self.assertTrue(object_pydbg.dbg.dwProcessId == top_created_process.pid)

            return pydbg.defines.DBG_CONTINUE

        def callback_processes_tree_exit(object_pydbg, args, function_result):
            lpApplicationName = object_pydbg.get_wstring(args[0])
            print("callback_processes_tree_exit lpApplicationName=", lpApplicationName)
            lpCommandLine = object_pydbg.get_wstring(args[1])
            print("callback_processes_tree_exit lpCommandLine=%s." % lpCommandLine)

            self.assertTrue(object_pydbg.dbg.dwProcessId == top_created_process.pid)

            return pydbg.defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_create_process_w,
            10,
            callback_processes_tree_entry,
            callback_processes_tree_exit)

        print("About to run subprocess")
        tst_pydbg.run()


        return_dict = {}
        for ix in range(tree_depth+1):
            one_line = top_created_process.stdout.readline()
            print("one_line=", one_line)
            sys.stdout.flush()
            one_depth, one_pid = map(int, one_line.split(b" "))
            return_dict[one_depth] = one_pid
        print("return_dict=", return_dict)




        print("Finished")




if __name__ == '__main__':
    unittest.main()
