#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import struct
import subprocess
import tempfile
import platform
import unittest

try:
    import win32process
    import win32con
    import win32file
except ImportError:
    pass

# This loads the module from the source, so no need to install it, and no need of virtualenv.
# This is needed when running from PyCharm.
sys.path.append("../survol/scripts")
sys.path.append("survol/scripts")
print("cwd=%s" % os.getcwd())

root_process_id = os.getpid()

from init import *

if not is_platform_linux:
    from survol.scripts import pydbg
    from survol.scripts.pydbg import defines
    from survol.scripts.pydbg import utils
    from survol.scripts.pydbg import windows_h

################################################################################

@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgBasicTest(unittest.TestCase):
    """
    Test basic features.
    """

    # This tests the callbacks which are used for good in other tests.
    # It starts a DOS process which attempts to remove a directory.
    @unittest.skipIf(platform.architecture()[0] != '64bit', "Only on 64 bits machines.")
    def test_Wow64_Self(self):
        is_wow64 = pydbg.process_is_wow64(pid=None)
        print("is_wow64=", is_wow64)
        print("platform.architecture()=", platform.architecture())

        if sys.maxsize > 2 ** 32:
            self.assertTrue(not is_wow64)
        else:
            self.assertTrue(is_wow64)

    @unittest.skipIf(platform.architecture()[0] != '64bit', "Only on 64 bits machines.")
    def test_Wow64_Other(self):
        """This starts a 32 bits process on a 64 bits platform"""
        tst_pydbg = pydbg.pydbg()

        cmd32_command = r"C:\Windows\SysWOW64\cmd.exe"

        created_process = subprocess.Popen([cmd32_command, "/c", "FOR /L %A IN (1,1,3) DO ping -n 2 127.0.0.1"], shell=False)

        time.sleep(0.5)

        print("Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        is_wow64 = pydbg.process_is_wow64(pid=created_process.pid)
        print("is_wow64=", is_wow64)

        self.assertTrue(is_wow64)

        # Not needed in the test but does the cleanup.
        tst_pydbg.run()
        created_process.communicate()

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
    def test_DOS_RemoveDirectoryW(self):
        tst_pydbg = pydbg.pydbg()

        num_loops = 4
        non_existent_dir = "NonExistentDir"

        # This attempts several times to remove a non-existent dir.
        # This is detected by the hook.
        rmdir_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 >NUL & echo %%A & rmdir %s )" % (num_loops, non_existent_dir)

        created_process = subprocess.Popen(rmdir_command, shell=True)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        object_hooks = utils.hook_container()

        hook_address_RemoveDirectoryW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"RemoveDirectoryW")

        class Context:
            count_entry = 0
            count_exit = 0

        def callback_RemoveDirectoryW_entry(object_pydbg, args):
            Context.count_entry += 1
            dir_name = object_pydbg.get_wstring(args[0])
            # object_pydbg.dbg is a LPDEBUG_EVENT, pointer to DEBUG_EVENT.
            print("callback_RemoveDirectoryW_entry dir_name=", dir_name, "dwProcessId=", object_pydbg.dbg.dwProcessId)
            self.assertTrue(dir_name == non_existent_dir)
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)
            return defines.DBG_CONTINUE

        def callback_RemoveDirectoryW_exit(object_pydbg, args, function_result):
            Context.count_exit += 1
            dir_name = object_pydbg.get_wstring(args[0])
            print("callback_RemoveDirectoryW_exit dir_name=", dir_name, function_result)
            self.assertTrue(dir_name == non_existent_dir)
            self.assertTrue(function_result == 0)
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)
            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_RemoveDirectoryW,
            1,
            callback_RemoveDirectoryW_entry,
            callback_RemoveDirectoryW_exit)

        tst_pydbg.run()

        print("Counters:", Context.count_entry, Context.count_exit)
        self.assertTrue(Context.count_entry == num_loops)
        self.assertTrue(Context.count_exit == num_loops)

    # It starts a DOS process which attempts to remove a directory.
    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_DOS_DeleteFileW(self):
        tst_pydbg = pydbg.pydbg()

        num_loops = 3
        temp_file = "Temporary_%d_%d.xyz" % (os.getpid(), int(time.time()))
        temp_path = os.path.join( tempfile.gettempdir(), temp_file)

        # This creates a file then removes it, several times.
        # This is detected by the hook.
        del_file_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 >%s & echo %%A & del %s )" % (num_loops, temp_path, temp_path)

        created_process = subprocess.Popen(del_file_command, shell=True)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        object_hooks = utils.hook_container()

        hook_address_DeleteFileW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"DeleteFileW")

        class Context:
            count_entry = 0
            count_exit = 0

        def callback_DeleteFileW_entry(object_pydbg, args):
            Context.count_entry += 1
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_DeleteFileW_entry file_name=", file_name)
            self.assertTrue(file_name == temp_path)

            # object_pydbg.dbg is a LPDEBUG_EVENT, pointer to DEBUG_EVENT.
            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId)
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return defines.DBG_CONTINUE

        def callback_DeleteFileW_exit(object_pydbg, args, function_result):
            Context.count_exit += 1
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_DeleteFileW_exit file_name=", file_name, function_result)
            self.assertTrue(file_name == temp_path)

            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId)
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_DeleteFileW,
            1,
            callback_DeleteFileW_entry,
            callback_DeleteFileW_exit)

        tst_pydbg.run()

        print("Counters:", Context.count_entry, Context.count_exit)
        self.assertTrue(Context.count_entry == num_loops)
        self.assertTrue(Context.count_exit == num_loops)

    # This starts a separate Python process which attempts several times to open a non-existent file.
    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_DOS_CreateFileW(self):
        tst_pydbg = pydbg.pydbg()

        num_loops = 5
        non_existent_file = "NonExistentFile"

        # This attempts several times to remove a non-existent dir.
        # This is detected by the hook.
        type_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 & echo %%A & type %s )" % (num_loops, non_existent_file)

        created_process = subprocess.Popen(type_command, shell=True)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        object_hooks = utils.hook_container()

        hook_address_CreateFileW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateFileW")

        class Context:
            count_entry = 0
            count_exit = 0

        def callback_CreateFileW_entry(object_pydbg, args):
            Context.count_entry += 1
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_CreateFileW_entry file_name=", file_name)
            if object_pydbg.is_wow64:
                self.assertTrue(file_name == non_existent_file)
            else:
                self.assertTrue(file_name in [non_existent_file, r"C:\Windows\SysWOW64\cmd.exe"])
            return defines.DBG_CONTINUE

        def callback_CreateFileW_exit(object_pydbg, args, function_result):
            Context.count_exit += 1
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

        print("END", Context.count_entry, Context.count_exit)
        # The first call might be missed.
        self.assertTrue(Context.count_entry == num_loops)
        self.assertTrue(Context.count_exit == num_loops)

    def test_DOS_create_process(self):
        tst_pydbg = pydbg.pydbg()

        num_loops = 3

        # Each loop creates a sub-process which immediately exists.
        ping_echo_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1& echo %%A )" % num_loops

        created_process = subprocess.Popen(ping_echo_command, shell=True)

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        class Context:
            command_line = None

        def process_creation_callback(object_pydbg):
            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId)
            print("object_pydbg.dbg.dwThreadId=", object_pydbg.dbg.dwThreadId)

            object_process = psutil.Process(object_pydbg.dbg.dwProcessId)
            Context.command_line = object_process.cmdline()
            assert object_pydbg == tst_pydbg
            assert object_process.ppid() == root_process_id
            return defines.DBG_CONTINUE

        tst_pydbg.set_callback(defines.CREATE_PROCESS_DEBUG_EVENT, process_creation_callback)

        tst_pydbg.run()

        print("Command line:", Context.command_line)
        self.assertTrue(Context.command_line[0].lower() == 'C:\\windows\\system32\\cmd.exe'.lower())
        self.assertTrue(Context.command_line[1] == '/c')
        self.assertTrue(Context.command_line[2] == ping_echo_command)

    def test_DOS_CreateProcessW(self):
        tst_pydbg = pydbg.pydbg()

        num_loops = 3

        # Each loop creates a sub-process which immediately exists.
        # This is detected by the hook.
        ping_command = "FOR /L %%A IN (1,1,%d) DO (ping -n 2 127.0.0.1)" % num_loops

        created_process = subprocess.Popen(ping_command, shell=True)
        print("Created process:%d" % created_process.pid)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        object_hooks = utils.hook_container()

        hook_address_process_information = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateProcessW")
        print("hook_address_process_information=%016x" % hook_address_process_information)

        tst_pydbg.count_entry = 0
        tst_pydbg.count_exit = 0

        ping_binary_lower = r"C:\windows\system32\PING.EXE".lower()

        def callback_process_information_entry(object_pydbg, args):
            object_pydbg.count_entry += 1
            lpApplicationName = object_pydbg.get_wstring(args[0])
            print("callback_process_information_entry lpApplicationName=", lpApplicationName)
            assert lpApplicationName.lower() == ping_binary_lower
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
            # object_pydbg.dbg is a LPDEBUG_EVENT, pointer to DEBUG_EVENT.
            print("dwProcessId=", object_pydbg.dbg.dwProcessId, "dwThreadId=", object_pydbg.dbg.dwThreadId)

            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return defines.DBG_CONTINUE

        def callback_process_information_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            lpApplicationName = object_pydbg.get_wstring(args[0])
            print("callback_process_information_exit lpApplicationName=", lpApplicationName)
            assert lpApplicationName.lower() == ping_binary_lower
            lpCommandLine = object_pydbg.get_wstring(args[1])
            print("callback_process_information_exit lpCommandLine=%s." % lpCommandLine)
            assert lpCommandLine == "ping  -n 2 127.0.0.1"

            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_process_information,
            10,
            callback_process_information_entry,
            callback_process_information_exit)

        tst_pydbg.run()

        print("END", tst_pydbg.count_entry, tst_pydbg.count_exit)
        created_process.kill()
        # The first call is missed.
        self.assertTrue(tst_pydbg.count_entry == num_loops - 1)
        self.assertTrue(tst_pydbg.count_exit == num_loops - 1)

    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_DOS_nslookup(self):
        tst_pydbg = pydbg.pydbg()

        created_process = subprocess.Popen(["nslookup"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)

        time.sleep(0.5)

        print("Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        subprocess_object = psutil.Process(created_process.pid)
        self.assertTrue(subprocess_object.ppid() == root_process_id)
        print("Command=", subprocess_object.cmdline())
        self.assertTrue(subprocess_object.cmdline() == ["nslookup"])

        object_hooks = utils.hook_container()

        hook_address_DOS_nslookup = tst_pydbg.func_resolve(b"ws2_32.dll", b"connect")

        assert hook_address_DOS_nslookup
        print("hook_address_DOS_nslookup=%016x" % hook_address_DOS_nslookup)

        class PersistentState:
            port_number = -1
            sin_family = -1
            s_addr = -1

        def check_sockaddr_nslookup(object_pydbg, args):

            sockaddr_address = args[1]

            sin_family_memory = object_pydbg.read_process_memory(sockaddr_address, 2)
            PersistentState.sin_family = struct.unpack("<H", sin_family_memory)[0]
            print("sin_family=", PersistentState.sin_family)

            # AF_INET6 = 23, if this is an IPV6 DNS server.
            if PersistentState.sin_family == defines.AF_INET6:
                # struct sockaddr_in6 {
                #      sa_family_t     sin6_family;   /* AF_INET6 */
                #      in_port_t       sin6_port;     /* port number */
                #      uint32_t        sin6_flowinfo; /* IPv6 flow information */
                #      struct in6_addr sin6_addr;     /* IPv6 address */
                #      uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
                #  };
                #
                # struct in6_addr {
                #      unsigned char   s6_addr[16];   /* IPv6 address */
                # };
                ip_port_memory = object_pydbg.read_process_memory(sockaddr_address + 2, 2)
                PersistentState.ip_port = struct.unpack(">H", ip_port_memory)[0]
                print("ip_port=", PersistentState.ip_port)

                self.assertTrue(args[2] == 28)
                self.assertTrue(PersistentState.ip_port == 53) # DNS

                s_addr_ipv6 = object_pydbg.read_process_memory(sockaddr_address + 8, 16)

                if sys.version_info >= (3,):
                    print("s_addr_ipv6=%s" % str(s_addr_ipv6))
                else:
                    print("s_addr_ipv6=%s" % "".join(["%02x" % ord(one_byte) for one_byte in s_addr_ipv6]))
            else:
                raise Exception("Invalid sa_family")

        def callback_DOS_nslookup_entry(object_pydbg, args):
            print("callback_DOS_nslookup_entry args=", args)
            check_sockaddr_nslookup(object_pydbg, args)
            return defines.DBG_CONTINUE

        def callback_DOS_nslookup_exit(object_pydbg, args, function_result):
            print("callback_DOS_nslookup_exit args=", args, function_result)
            check_sockaddr_nslookup(object_pydbg, args)
            return defines.DBG_CONTINUE

        print("Adding breakpoint")
        object_hooks.add(
            tst_pydbg,
            hook_address_DOS_nslookup,
            3,
            callback_DOS_nslookup_entry,
            callback_DOS_nslookup_exit)

        print("Writing data to input pipe")
        # The maximum number is variable. If too big, it hangs.
        created_process.stdin.write(b"primhillcomputers.com\n" * 10)
        created_process.stdin.write(b"quit\n")
        print("Data written")

        if sys.version_info >= (3,):
            # The subprocess implementation is different between Python 2 and 3.
            # This makes data available to the subprocess while it is still blocked.
            try:
                stdout_data, stderr_data = created_process.communicate(timeout=1.0)
            except subprocess.TimeoutExpired as exc:
                print("exc=", exc)
        print("Running")
        tst_pydbg.run()

        print("Leaving")

        stdout_data, stderr_data = created_process.communicate()
        created_process.stdin.close()
        created_process.kill()

        print("stdout_data=", stdout_data)
        # Typical content:
        # > Server:  UnKnown
        # Address:  fe80::22b0:1ff:fea4:4672
        #
        # Name:    primhillcomputers.com
        # Address:  164.132.235.17
        self.assertTrue(stdout_data.find(b"primhillcomputers.com") > 0)
        self.assertTrue(stderr_data is None)
        self.assertTrue(PersistentState.sin_family == defines.AF_INET6)


# BEWARE: When running DOS tests first, then Python tests fail.
@unittest.skipIf(is_platform_linux, "Windows only.")
class PydbgPythonHooksTest(unittest.TestCase):
    """
    Test pydbg from Python processes.
    These tests hook specific Win32 API functions and start Python processes
    doing things which should trigger calls to these system functions.
    Calls to these functions are then detected and reported.
    """

    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_Python_CreateFile(self):
        tst_pydbg = pydbg.pydbg()

        temp_file_name = "test_pydbg_tmp_create_%d_%d" % (root_process_id, int(time.time()))
        python_command = 'import time;time.sleep(2.0);f=open(u"%s", "w");f.close()' % temp_file_name
        creation_file_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        class Context:
            file_name_entry = None
            file_name_exit = None

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Attaching to pid=%d" % creation_file_process.pid)
        tst_pydbg.attach(creation_file_process.pid)

        object_hooks = utils.hook_container()

        hook_address_create_file_w = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateFileW")
        print("hook_address_create_file_w=%016x" % hook_address_create_file_w)

        def callback_create_file_entry(object_pydbg, args):
            Context.file_name_entry = object_pydbg.get_wstring(args[0])
            print("callback_create_file_entry file_name_entry=", Context.file_name_entry)
            self.assertTrue(Context.file_name_entry == temp_file_name)
            return defines.DBG_CONTINUE

        def callback_create_file_exit(object_pydbg, args, function_result):
            Context.file_name_exit = object_pydbg.get_wstring(args[0])
            print("callback_create_file_exit m=", Context.file_name_exit)
            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_create_file_w,
            10,
            callback_create_file_entry,
            callback_create_file_exit)

        tst_pydbg.run()
        creation_file_process.kill()
        self.assertTrue(Context.file_name_entry == temp_file_name)
        self.assertTrue(Context.file_name_exit == temp_file_name)

    def test_Python_DeleteFile(self):
        tst_pydbg = pydbg.pydbg()

        temp_name = "test_pydbg_tmp_delete_%d_%d" % (root_process_id, int(time.time()))
        python_command = 'import time;import os;time.sleep(2);n=u"%s";f=open(n,"w");f.close();os.remove(n)' % temp_name
        deletion_file_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        class Context:
            file_name_entry = None
            file_name_exit = None

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Attaching to pid=%d" % deletion_file_process.pid)
        tst_pydbg.attach(deletion_file_process.pid)

        object_hooks = utils.hook_container()

        hook_address_delete_file_w = tst_pydbg.func_resolve(b"KERNEL32.dll", b"DeleteFileW")
        print("hook_address_delete_file_w=%016x" % hook_address_delete_file_w)

        def callback_delete_file_entry(object_pydbg, args):
            Context.file_name_entry = object_pydbg.get_wstring(args[0])
            print("callback_delete_file_entry file_name_entry=", Context.file_name_entry)
            return defines.DBG_CONTINUE

        def callback_delete_file_exit(object_pydbg, args, function_result):
            Context.file_name_exit = object_pydbg.get_wstring(args[0])
            print("callback_delete_file_exit file_name_exit=", Context.file_name_exit)
            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_delete_file_w,
            1,
            callback_delete_file_entry,
            callback_delete_file_exit)

        tst_pydbg.run()
        deletion_file_process.kill()
        self.assertTrue(Context.file_name_entry == temp_name)
        self.assertTrue(Context.file_name_exit == temp_name)

    def test_Python_system(self):
        tst_pydbg = pydbg.pydbg()

        temp_name = "test_pydbg_tmp_delete_%d_%d" % (root_process_id, int(time.time()))
        system_command = "dir"
        python_command = 'import time;import os;time.sleep(2);os.system("%s")' % system_command
        system_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        class Context:
            system_command_exit = None

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Attaching to pid=%d" % system_process.pid)
        tst_pydbg.attach(system_process.pid)

        object_hooks = utils.hook_container()

        if sys.version_info >= (3,):
            function_name_create_process = b"CreateProcessW"
            string_getter = "get_wstring"
        else:
            function_name_create_process = b"CreateProcessA"
            string_getter = "get_string"

        hook_address_create_process = tst_pydbg.func_resolve(b"KERNEL32.dll", function_name_create_process)

        def callback_system_exit(object_pydbg, args, function_result):
            Context.system_command_exit = getattr(object_pydbg, string_getter)(args[0])
            print("callback_system_exit system_command_exit=", Context.system_command_exit)
            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_create_process,
            1,
            None,
            callback_system_exit)

        tst_pydbg.run()
        system_process.kill()
        cmd_executable = r'C:\windows\system32\cmd.exe'
        # Conversion to lower case because c:\windows might be C:\Windows on Travis.
        print("cmd_executable=", cmd_executable)
        self.assertTrue(Context.system_command_exit.lower() == cmd_executable.lower())

    def test_Python_mkdir_rmdir(self):
        tst_pydbg = pydbg.pydbg()

        temp_file_name = "test_pydbg_tmp_directory_%d_%d" % (root_process_id, int(time.time()))
        temp_path = os.path.join( tempfile.gettempdir(), temp_file_name)

        python_command = "import time;import os;time.sleep(2.0);dn=r'%s';os.mkdir(dn);os.rmdir(dn)" % temp_path
        print("python_command=", python_command)
        dir_command_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        print("dir_command_process ", dir_command_process.pid)

        class Context:
            created_directory_entry = None
            created_directory_exit = None
            removed_directory_entry = None
            removed_directory_exit = None

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Attaching to pid=%d" % dir_command_process.pid)
        tst_pydbg.attach(dir_command_process.pid)

        object_hooks = utils.hook_container()

        if sys.version_info >= (3,):
            function_name_create_directory = b"CreateDirectoryW"
            function_name_remove_directory = b"RemoveDirectoryW"
            string_getter = "get_wstring"
        else:
            function_name_create_directory = b"CreateDirectoryA"
            function_name_remove_directory = b"RemoveDirectoryA"
            string_getter = "get_string"

        hook_address_CreateDirectory = tst_pydbg.func_resolve(b"KERNEL32.dll", function_name_create_directory)

        def callback_CreateDirectory_entry(object_pydbg, args):
            Context.created_directory_entry = getattr(object_pydbg, string_getter)(args[0])
            print("callback_CreateDirectory_entry created_directory_entry=", Context.created_directory_entry)
            return defines.DBG_CONTINUE

        def callback_CreateDirectory_exit(object_pydbg, args, function_result):
            Context.created_directory_exit = getattr(object_pydbg, string_getter)(args[0])
            print("callback_CreateDirectory_exit created_directory_exit=", Context.created_directory_exit)
            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_CreateDirectory,
            2,
            callback_CreateDirectory_entry,
            callback_CreateDirectory_exit)

        hook_address_RemoveDirectory = tst_pydbg.func_resolve(b"KERNEL32.dll", function_name_remove_directory)

        def callback_RemoveDirectory_entry(object_pydbg, args):
            Context.removed_directory_entry = getattr(object_pydbg, string_getter)(args[0])
            print("callback_RemoveDirectory_entry removed_directory_entry=", Context.removed_directory_entry)
            return defines.DBG_CONTINUE

        def callback_RemoveDirectory_exit(object_pydbg, args, function_result):
            Context.removed_directory_exit = getattr(object_pydbg, string_getter)(args[0])
            print("callback_RemoveDirectory_exit removed_directory_exit=", Context.removed_directory_exit)
            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_RemoveDirectory,
            1,
            callback_RemoveDirectory_entry,
            callback_RemoveDirectory_exit)

        tst_pydbg.run()
        stdout_data, stderr_data = dir_command_process.communicate()
        self.assertTrue(not stdout_data)
        self.assertTrue(not stderr_data)
        dir_command_process.kill()

        print("created_directory_entry=", Context.created_directory_entry)
        print("created_directory_exit=", Context.created_directory_exit)
        print("removed_directory_entry=", Context.removed_directory_entry)
        print("removed_directory_exit=", Context.removed_directory_exit)

        self.assertTrue(Context.created_directory_entry == temp_path)
        self.assertTrue(Context.created_directory_exit == temp_path)
        self.assertTrue(Context.removed_directory_entry == temp_path)
        self.assertTrue(Context.removed_directory_exit == temp_path)

    def test_Python_subprocess(self):
        """This starts a Python subprocess without an intermediary shell."""
        tst_pydbg = pydbg.pydbg()

        python_command = 'print("Hello");import time;time.sleep(2.0)'
        print_hello_process = subprocess.Popen([sys.executable, '-c', python_command],
                                                stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)

        print("print_hello_process ", print_hello_process.pid)

        # A bit of delay so the process can start.
        time.sleep(0.5)

        class Context:
            command_line = None

        tst_pydbg.attach(print_hello_process.pid)

        def print_hello_callback(object_pydbg):
            print("dwProcessId=", object_pydbg.dbg.dwProcessId, "dwThreadId=", object_pydbg.dbg.dwThreadId)

            object_process = psutil.Process(object_pydbg.dbg.dwProcessId)
            Context.command_line = object_process.cmdline()
            print("Command line:", Context.command_line)

            assert object_pydbg == tst_pydbg
            assert object_process.ppid() == root_process_id
            return defines.DBG_CONTINUE

        tst_pydbg.set_callback(defines.CREATE_PROCESS_DEBUG_EVENT, print_hello_callback)

        print("About to run subprocess")
        tst_pydbg.run()
        self.assertTrue(Context.command_line == [sys.executable, '-c', python_command])

    def test_Python_shell_sub_process(self):
        """This starts a shell, then a Python subprocess."""
        tst_pydbg = pydbg.pydbg()

        python_command = 'print("Hello");import time;time.sleep(2.0)'
        process_command = [sys.executable, '-c', python_command]
        print_shell_process = subprocess.Popen(process_command,
                                                stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)

        # A bit of delay so the process can start.
        time.sleep(0.5)

        class Context:
            command_line = None

        tst_pydbg.attach(print_shell_process.pid)

        def print_shell_callback(object_pydbg):
            print("dwProcessId=", object_pydbg.dbg.dwProcessId, "dbg.dwThreadId=", object_pydbg.dbg.dwThreadId)
            object_process = psutil.Process(object_pydbg.dbg.dwProcessId)
            Context.command_line = object_process.cmdline()
            assert object_pydbg == tst_pydbg
            assert object_process.ppid() == root_process_id
            return defines.DBG_CONTINUE

        tst_pydbg.set_callback(defines.CREATE_PROCESS_DEBUG_EVENT, print_shell_callback)

        tst_pydbg.run()
        # FIXME: The command array is wrong when parameters contain spaces:
        # Actual:
        # ['C:\\windows\\system32\\cmd.exe', '/c', 'C:\\Python27\\python.exe -c print("Hello");import', 'time;time.sleep(2.0)'
        # Expected:
        # ['C:\\windows\\system32\\cmd.exe', '/c', 'C:\\Python27\\python.exe -c print("Hello");import time;time.sleep(2.0)'
        # FIXME: Therefore everything is converted to strings before comparison.

        expected_command_line = "C:\\windows\\system32\\cmd.exe /c %s" % " ".join(process_command)
        print("expected_command_line=", expected_command_line)
        actual_command_line = " ".join(Context.command_line)
        print("actual_command_line=", actual_command_line)
        # Conversion to lower case because c:\windows might be C:\Windows.
        self.assertTrue(actual_command_line.lower() == expected_command_line.lower())

    def test_Python_connect(self):
        """
        This does a TCP/IP connection to Primhill Computers website.
        The call to socket() is detected, the IP address and the port number are reported.
        """
        server_domain = "primhillcomputers.com"
        server_port = 80

        # A subprocess is about to loop on a socket connection to a remote machine.
        temporary_python_file = tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False)
        script_content = """
import socket
import time
print('Before')
for counter in range(3):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('%s', %d))
    s.sendall(b'Hello, world')
    data = s.recv(1024)
    s.close()
    time.sleep(2.0)
""" % (server_domain, server_port)
        temporary_python_file.write(script_content)
        temporary_python_file.close()

        tst_pydbg = pydbg.pydbg()

        url_process = subprocess.Popen(
            [sys.executable, temporary_python_file.name],
            stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)

        # A bit of delay so the process can start before attaching to it.
        time.sleep(0.5)

        print("Attaching to pid=%d" % url_process.pid)
        tst_pydbg.attach(url_process.pid)

        object_hooks = utils.hook_container()

        # This library contains the functions socket(), connect(), accept(), bind() etc...
        hook_address_connect = tst_pydbg.func_resolve(b"ws2_32.dll", b"connect")

        assert hook_address_connect
        print("hook_address_connect=%016x" % hook_address_connect)

        class PersistentState:
            port_number = -1
            sin_family = -1
            s_addr = -1

        def check_sockaddr_content(object_pydbg, args):
            # struct sockaddr {
            #         ushort  sa_family;
            #         char    sa_data[14];
            # };
            #
            # struct sockaddr_in {
            #         short   sin_family;
            #         u_short sin_port;
            #         struct  in_addr sin_addr;
            #         char    sin_zero[8];
            # };

            sockaddr_address = args[1]
            assert args[2] == 16

            sin_family_memory = object_pydbg.read_process_memory(sockaddr_address, 2)
            PersistentState.sin_family = struct.unpack("<H", sin_family_memory)[0]
            print("sin_family=", PersistentState.sin_family)

            ip_port_memory = object_pydbg.read_process_memory(sockaddr_address + 2, 2)
            PersistentState.ip_port = struct.unpack(">H", ip_port_memory)[0]
            print("ip_port=", PersistentState.ip_port)

            # struct in_addr {
            #     unsigned long s_addr;  // load with inet_aton()
            # };
            s_addr_memory = object_pydbg.read_process_memory(sockaddr_address + 4, 4)
            s_addr_integer = struct.unpack(">I", s_addr_memory)[0]

            PersistentState.s_addr ="%d.%d.%d.%d" % (
                (s_addr_integer & 0xFF000000)/0x1000000,
                (s_addr_integer & 0x00FF0000)/0x10000,
                (s_addr_integer & 0x0000FF00)/0x100,
                (s_addr_integer & 0x000000FF)/0x1)
            print("s_addr=%s" % PersistentState.s_addr)

        def callback_entry_connect(object_pydbg, args):
            check_sockaddr_content(object_pydbg, args)
            return defines.DBG_CONTINUE

        def callback_exit_connect(object_pydbg, args, function_result):
            check_sockaddr_content(object_pydbg, args)
            return defines.DBG_CONTINUE

        # int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
        object_hooks.add(
            tst_pydbg,
            hook_address_connect,
            3,
            callback_entry_connect,
            callback_exit_connect)

        tst_pydbg.run()
        os.remove(temporary_python_file.name)

        self.assertTrue(PersistentState.sin_family == defines.AF_INET)
        self.assertTrue(PersistentState.ip_port == server_port)
        self.assertTrue(PersistentState.s_addr == socket.gethostbyname(server_domain))

    # This an experimental attempt to detected nested processes creations.
    # Quite probably, a different approach will be chosen.
    @unittest.skip("Does not work yet")
    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_Python_subprocesses_recursive(self):
        tst_pydbg = pydbg.pydbg()

        tree_depth = 5

        top_created_process = subprocess.Popen([sys.executable, '-m', 'create_process_chain', str(tree_depth)],
                                                stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)

        print("create_process_tree_popen ", top_created_process.pid)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Attaching to pid=%d" % top_created_process.pid)
        tst_pydbg.attach(top_created_process.pid)

        tst_pydbg.sub_pydbgs = []

        def python_process_creation_callback(object_pydbg):
            print("dwProcessId=", object_pydbg.dbg.dwProcessId, "dwThreadId=", object_pydbg.dbg.dwThreadId)

            object_process = psutil.Process(object_pydbg.dbg.dwProcessId)
            # Command line: ['C:\\Python27\\python.exe', '-m', 'create_process_chain', '5']
            actual_command_line = object_process.cmdline()
            expected_command_line = [sys.executable, '-m', 'create_process_chain', str(tree_depth)]
            print("python_process_creation_callback Actual command line:", actual_command_line)
            print("python_process_creation_callback Expected command line:", expected_command_line)
            assert actual_command_line == expected_command_line

            assert object_pydbg == tst_pydbg

            assert object_process.ppid() == root_process_id

            the_subpydbg = pydbg.pydbg()
            the_subpydbg.sub_pydbgs = []
            tst_pydbg.sub_pydbgs.append(the_subpydbg)
            the_subpydbg.open_process(object_pydbg.dbg.dwProcessId)
            print("AFTER REDUNDANCY")
            the_subpydbg.attach(object_pydbg.dbg.dwProcessId)
            the_subpydbg.set_callback(defines.CREATE_PROCESS_DEBUG_EVENT, python_process_creation_callback)
            the_subpydbg.run()

            return defines.DBG_CONTINUE

        tst_pydbg.set_callback(defines.CREATE_PROCESS_DEBUG_EVENT, python_process_creation_callback)

        print("About to run subprocess")
        tst_pydbg.run()

        return_dict = {}
        for ix in range(tree_depth+1):
            one_line = top_created_process.stdout.readline()
            print("one_line=", one_line)
            one_depth, one_pid = map(int, one_line.split(b" "))
            return_dict[one_depth] = one_pid
        print("return_dict=", return_dict)


# BEWARE: When running DOS tests first, then Python tests fail.
@unittest.skipIf(is_platform_linux, "Windows only.")
@unittest.skipIf(pkgutil.find_loader('pywin32'), "Needs pywin32 module.")
class PydbgWin32HooksTest(unittest.TestCase):
    """
    Test pydbg from Python processes created with win32.
    It is necessary to create suspended processes, so that breakpoints can be applied before they run.
    The class subprocess.Popen does not allow the creation of suspended processes.
    """

    def test_win32_process_basic(self):
        start_info = win32process.STARTUPINFO()
        start_info.dwFlags = win32con.STARTF_USESHOWWINDOW

        temp_data_file_name = "test_win32_process_basic_%d_%d.txt" % (root_process_id, int(time.time()))
        temp_data_file_path = os.path.join(tempfile.gettempdir(), temp_data_file_name)

        temp_python_name = "test_win32_process_basic_%d_%d.py" % (root_process_id, int(time.time()))
        temp_python_path = os.path.join(tempfile.gettempdir(), temp_python_name)
        result_message = "Hello_%d" % root_process_id
        script_content = "open(r'%s', 'w').write('%s')" % (temp_data_file_path, result_message)
        with open(temp_python_path, "w") as temp_python_file:
            temp_python_file.write(script_content)

        python_command = "%s %s" % (sys.executable, temp_python_path)
        # CreateProcess() takes no keyword arguments
        prc_info = win32process.CreateProcess(
            None,  # appName
            python_command,  # commandLine
            None,  # processAttributes
            None,  # threadAttributes
            False,  # bInheritHandles
            win32con.CREATE_NEW_CONSOLE,  # dwCreationFlags
            None,  # newEnvironment
            os.getcwd(),  # currentDirectory
            start_info)  # startupinfo

        # So the Python process can run and finish to write the file.
        time.sleep(2.0)
        with open(temp_data_file_path) as result_file:
            first_line = result_file.readlines()[0]

        os.remove(temp_data_file_path)
        os.remove(temp_python_path)

        self.assertTrue(first_line == result_message)

    def test_win32_process_suspended(self):
        start_info = win32process.STARTUPINFO()
        start_info.dwFlags = win32con.STARTF_USESHOWWINDOW
        # start_info.wShowWindow = win32con.SW_MAXIMIZE

        temp_data_file_name = "test_win32_process_%d_%d.txt" % (root_process_id, int(time.time()))
        temp_data_file_path = os.path.join(tempfile.gettempdir(), temp_data_file_name)

        temp_python_name = "test_win32_process_%d_%d.py" % (root_process_id, int(time.time()))
        temp_python_path = os.path.join(tempfile.gettempdir(), temp_python_name)
        result_message = "Hello_%d" % root_process_id
        script_content = "open(r'%s', 'w').write('%s')" % (temp_data_file_path, result_message)
        with open(temp_python_path, "w") as temp_python_file:
            temp_python_file.write(script_content)

        python_command = "%s %s" % (sys.executable, temp_python_path)
        print("python_command", python_command)
        # CreateProcess takes no keyword arguments. It returns a tuple (hProcess, hThread, dwProcessId, dwThreadId)
        prc_info = win32process.CreateProcess(
            None,  # appName
            python_command,  # commandLine
            None,  # processAttributes
            None,  # threadAttributes
            False,  # bInheritHandles
            win32con.CREATE_NEW_CONSOLE | win32con.CREATE_SUSPENDED,  # dwCreationFlags
            None,  # newEnvironment
            os.getcwd(),  # currentDirectory
            start_info)  # startupinfo

        # The process must be suspended, so nothing should happen.
        time.sleep(0.1)
        try:
            open(temp_data_file_path)
            self.assertTrue(False, "This file should not be there")
        except IOError:
            pass

        print("prc_info=", prc_info, type(prc_info), dir(prc_info))
        win32process.ResumeThread(prc_info[1])

        time.sleep(0.5)
        # The resumed process had time enough to create the file.
        with open(temp_data_file_path) as result_file:
            first_line = result_file.readlines()[0]
        print("first_line=", first_line)

        os.remove(temp_data_file_path)
        os.remove(temp_python_path)

        self.assertTrue(first_line == result_message)

    def test_win32_process_suspended_hook(self):
        """This tests a process created in suspended state, then stopping in breakpoints."""
        start_info = win32process.STARTUPINFO()
        start_info.dwFlags = win32con.STARTF_USESHOWWINDOW

        temp_data_file_name = "test_win32_process_suspend_hook_%d_%d.txt" % (root_process_id, int(time.time()))
        temp_data_file_path = os.path.join(tempfile.gettempdir(), temp_data_file_name)

        temp_python_name = "test_win32_process_suspend_hook_%d_%d.py" % (root_process_id, int(time.time()))
        temp_python_path = os.path.join(tempfile.gettempdir(), temp_python_name)
        result_message = "Hello_%d" % root_process_id
        script_content = "open(r'%s', 'w').write('%s')" % (temp_data_file_path, result_message)
        with open(temp_python_path, "w") as temp_python_file:
            temp_python_file.write(script_content)

        python_command = "%s %s" % (sys.executable, temp_python_path)
        # CreateProcess returns a tuple (hProcess, hThread, dwProcessId, dwThreadId)
        prc_info = win32process.CreateProcess(None, python_command, None, None, False,  # bInheritHandles
                                              win32con.CREATE_NEW_CONSOLE | win32con.CREATE_SUSPENDED, None,
                                              os.getcwd(), start_info)

        sub_process_id = prc_info[2]
        print("Attaching to pid=%d" % sub_process_id)

        tst_pydbg = pydbg.pydbg()
        tst_pydbg.attach(sub_process_id)

        if sys.version_info >= (3,):
            function_name_create_file = b"CreateFileW"
            string_getter = "get_wstring"
        else:
            function_name_create_file = b"CreateFileA"
            string_getter = "get_string"

        class Context:
            filename_entry = None

        def callback_CreateFile_entry(object_pydbg, args):
            Context.filename_entry = getattr(object_pydbg, string_getter)(args[0])
            print("callback_CreateFile_entry file_name=", Context.filename_entry)
            return defines.DBG_CONTINUE

        object_hooks = utils.hook_container()

        def load_dll_callback(object_pydbg):
            # self.dbg.u.LoadDll is _LOAD_DLL_DEBUG_INFO {
            #   HANDLE hFile;
            #   LPVOID lpBaseOfDll;
            #   DWORD  dwDebugInfoFileOffset;
            #   DWORD  nDebugInfoSize;
            #   LPVOID lpImageName;
            #   WORD   fUnicode;
            # } LOAD_DLL_DEBUG_INFO, *LPLOAD_DLL_DEBUG_INFO;


            dll_filename = win32file.GetFinalPathNameByHandle(
                object_pydbg.dbg.u.LoadDll.hFile, win32con.FILE_NAME_NORMALIZED)
            if dll_filename.startswith("\\\\?\\"):
                dll_filename = dll_filename[4:]

            # a ce moment on ne peut pas encore iterer car pas dans le snap shot,
            # donc faut aller chercher directement dans le handle de la lib.

            self.assertTrue(object_pydbg == tst_pydbg)
            if dll_filename.upper().endswith("KERNEL32.dll".upper()):
                print("FOUND dll_filename=", dll_filename)
                # At this stage, the DLL cannot be enumerated yet: For an unknown reason,
                # it cannot be obtained with CreateToolhelp32Snapshot and Module32First/Module32Next
                # hook_address_CreateFileW = object_pydbg.func_resolve(b"KERNEL32.dll", b"CreateFileW")
                hook_address_CreateFile = object_pydbg.func_resolve_from_dll_address(
                    object_pydbg.dbg.u.LoadDll.lpBaseOfDll,
                    function_name_create_file)

                object_hooks.add(
                    tst_pydbg,
                    hook_address_CreateFile,
                    1,
                    callback_CreateFile_entry,
                    None)

                print("Breakpoint set:", dir(object_hooks))

            return defines.DBG_CONTINUE

        # This event is received after the DLL is mapped into the address space of the debuggee.
        tst_pydbg.set_callback(defines.LOAD_DLL_DEBUG_EVENT, load_dll_callback)

        win32process.ResumeThread(prc_info[1])

        tst_pydbg.run()
        print("Context.filename_entry=", Context.filename_entry)

        # The resumed process had time enough to create the file.
        with open(temp_data_file_path) as result_file:
            first_line = result_file.readlines()[0]

        os.remove(temp_data_file_path)
        os.remove(temp_python_path)

        self.assertTrue(Context.filename_entry == temp_data_file_path)
        self.assertTrue(first_line == result_message)

if __name__ == '__main__':
    unittest.main()

##### Kernel32.dll
# Many functions are very specific to old-style Windows applications.
# Still, this is the only way to track specific behaviour.
#
# CopyFileA
# CopyFileW
# CopyFileExA
# CopyFileExW
# CopyFileTransactedA
# CopyFileTransactedW
# CopyLZFile

# CreateHardLink A/W/TransactedA/TransactedW
# CreateNamedPipe A/W

# LoadLibrary

# MapViewOfIle ?

# MoveFile ...

# OpenFile, OpenFileById
# ReOpenFile

# ReplaceFile, A, W

# OpenJobObjects

##### KernelBase.dll
# Looks like a subset of Kernel32.dll

##### ntdll.dll
# NtOpenFile
# NtOpenDirectoryObject ?

