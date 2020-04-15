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

is_py3 = sys.version_info >= (3,)

# This loads the module from the source, so no need to install it, and no need of virtualenv.
# This is needed when running from PyCharm.
sys.path.append("../survol/scripts")
sys.path.append("survol/scripts")
print("cwd=%s" % os.getcwd())

def unique_temporary_path(prefix, extension):
    temp_file = "%s_%d_%d%s" % (prefix, root_process_id, int(time.time()), extension)
    temp_path = os.path.join(tempfile.gettempdir(), temp_file)
    return temp_path

root_process_id = os.getpid()

from init import *

# Some tests start a DOS box process. The processes application is checked.
windows_system32_cmd_exe = r'C:\Windows\system32\cmd.exe' if is_travis_machine() else r'C:\windows\system32\cmd.exe'

if not is_platform_linux:
    from survol.scripts import pydbg
    from survol.scripts.pydbg import defines
    from survol.scripts.pydbg import utils
    from survol.scripts.pydbg import windows_h

################################################################################

@unittest.skipIf(is_platform_linux, "Windows only.")
class BasicTest(unittest.TestCase):
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
        created_process.terminate()

################################################################################

@unittest.skipIf(is_platform_linux, "Windows only.")
class WindowsDosCmdHooksTest(unittest.TestCase):
    """
    Test pydbg with DOS CMD processes.
    These tests hook specific Win32 API functions and start DOC CMD processes
    doing things which should trigger calls to these system functions.
    Calls to these functions are then detected and reported.
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

        hook_RemoveDirectoryW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"RemoveDirectoryW")

        class Context:
            count_in = 0
            count_out = 0

        def callback_RemoveDirectoryW_in(object_pydbg, args):
            Context.count_in += 1
            dir_name = object_pydbg.get_unicode_string(args[0])
            # object_pydbg.dbg is a LPDEBUG_EVENT, pointer to DEBUG_EVENT.
            print("callback_RemoveDirectoryW_in dir_name=", dir_name, "dwProcessId=", object_pydbg.dbg.dwProcessId)
            self.assertTrue(dir_name == non_existent_dir)
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)
            return defines.DBG_CONTINUE

        def callback_RemoveDirectoryW_out(object_pydbg, args, function_result):
            Context.count_out += 1
            dir_name = object_pydbg.get_unicode_string(args[0])
            print("callback_RemoveDirectoryW_out dir_name=", dir_name, function_result)
            self.assertTrue(dir_name == non_existent_dir)
            self.assertTrue(function_result == 0)
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)
            return defines.DBG_CONTINUE

        object_hooks.add(tst_pydbg, hook_RemoveDirectoryW, 1, callback_RemoveDirectoryW_in, callback_RemoveDirectoryW_out)

        tst_pydbg.run()

        print("Counters:", Context.count_in, Context.count_out)
        self.assertTrue(Context.count_in == num_loops)
        self.assertTrue(Context.count_out == num_loops)
        created_process.terminate()

    # It starts a DOS process which attempts to remove a directory.
    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_DOS_DeleteFileW(self):
        tst_pydbg = pydbg.pydbg()

        num_loops = 3
        temp_file = "Temporary_%d_%d.xyz" % (root_process_id, int(time.time()))
        temp_path = os.path.join( tempfile.gettempdir(), temp_file)

        # This creates a file then removes it, several times.
        # This is detected by the hook.
        del_file_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 >%s & echo %%A & del %s )" % (num_loops, temp_path, temp_path)

        created_process = subprocess.Popen(del_file_command, shell=True)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("Delete file test. Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        object_hooks = utils.hook_container()

        hook_DeleteFileW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"DeleteFileW")

        class Context:
            count_in = 0
            count_out = 0

        def callback_DeleteFileW_in(object_pydbg, args):
            Context.count_in += 1
            file_name = object_pydbg.get_unicode_string(args[0])
            print("callback_DeleteFileW_in file_name=", file_name)
            self.assertTrue(file_name == temp_path)

            # object_pydbg.dbg is a LPDEBUG_EVENT, pointer to DEBUG_EVENT.
            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId)
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return defines.DBG_CONTINUE

        def callback_DeleteFileW_out(object_pydbg, args, function_result):
            Context.count_out += 1
            file_name = object_pydbg.get_unicode_string(args[0])
            print("callback_DeleteFileW_out file_name=", file_name, function_result)
            self.assertTrue(file_name == temp_path)

            print("object_pydbg.dbg.dwProcessId=", object_pydbg.dbg.dwProcessId)
            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)

            return defines.DBG_CONTINUE

        object_hooks.add(tst_pydbg, hook_DeleteFileW, 1, callback_DeleteFileW_in, callback_DeleteFileW_out)

        tst_pydbg.run()

        print("Counters:", Context.count_in, Context.count_out)
        self.assertTrue(Context.count_in == num_loops)
        self.assertTrue(Context.count_out == num_loops)

    # This starts a separate Python process which attempts several times to open a non-existent file.
    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_DOS_CreateFileW(self):
        tst_pydbg = pydbg.pydbg()

        num_loops = 5
        non_existent_file = "NonExistentFile"

        # CreateFileW is used as read-only access, by the DOS command "type".
        type_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1 & echo %%A & type %s )" % (num_loops, non_existent_file)

        created_process = subprocess.Popen(type_command, shell=True)

        # A bit of delay so the process can start.
        time.sleep(1.0)

        print("CreateFile test: Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        object_hooks = utils.hook_container()

        hook_CreateFileW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateFileW")

        class Context:
            count_in = 0
            count_out = 0

        def callback_CreateFileW_in(object_pydbg, args):
            Context.count_in += 1
            file_name = object_pydbg.get_unicode_string(args[0])
            print("callback_CreateFileW_in file_name=", file_name)
            if object_pydbg.is_wow64:
                self.assertTrue(file_name == non_existent_file)
            else:
                self.assertTrue(file_name in [non_existent_file, r"C:\Windows\SysWOW64\cmd.exe"])
            return defines.DBG_CONTINUE

        def callback_CreateFileW_out(object_pydbg, args, function_result):
            Context.count_out += 1
            file_name = object_pydbg.get_unicode_string(args[0])
            print("callback_CreateFileW_out file_name=", file_name, function_result)
            self.assertTrue(file_name == non_existent_file)

            is_invalid_handle = function_result % (1 + defines.INVALID_HANDLE_VALUE) == defines.INVALID_HANDLE_VALUE
            self.assertTrue(is_invalid_handle)
            return defines.DBG_CONTINUE

        object_hooks.add(tst_pydbg, hook_CreateFileW, 1, callback_CreateFileW_in, callback_CreateFileW_out)

        tst_pydbg.run()

        print("END", Context.count_in, Context.count_out)
        # The first call might be missed.
        self.assertTrue(Context.count_in == num_loops)
        self.assertTrue(Context.count_out == num_loops)
        created_process.terminate()

    def test_DOS_create_process(self):
        tst_pydbg = pydbg.pydbg()

        num_loops = 3

        # Each loop creates a sub-process which immediately exists.
        ping_echo_command = "FOR /L %%A IN (1,1,%d) DO ( ping -n 2 127.0.0.1& echo %%A )" % num_loops

        created_process = subprocess.Popen(ping_echo_command, shell=True)

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Create process test: Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        class Context:
            command_line = None

        def process_creation_callback(object_pydbg):
            print("dwProcessId=", object_pydbg.dbg.dwProcessId, "dwThreadId=", object_pydbg.dbg.dwThreadId)

            object_process = psutil.Process(object_pydbg.dbg.dwProcessId)
            Context.command_line = object_process.cmdline()
            assert object_pydbg == tst_pydbg
            assert object_process.ppid() == root_process_id
            return defines.DBG_CONTINUE

        tst_pydbg.set_callback(defines.CREATE_PROCESS_DEBUG_EVENT, process_creation_callback)

        tst_pydbg.run()

        print("Command line:", Context.command_line)
        # windows_system32_cmd_exe
        # self.assertTrue(Context.command_line[0].lower() == 'C:\\windows\\system32\\cmd.exe'.lower())
        self.assertTrue(Context.command_line[0].lower() == windows_system32_cmd_exe.lower())
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

        print("DOS CreateProcessW test: Root pid=%d. Attaching to %d" % (root_process_id, created_process.pid))
        tst_pydbg.attach(created_process.pid)

        object_hooks = utils.hook_container()

        hook_CreateProcessW = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateProcessW")

        class Context:
            count_in = 0
            count_out = 0

        ping_binary_lower = r"C:\windows\system32\PING.EXE".lower()

        def callback_CreateProcessW_in(object_pydbg, args):
            Context.count_in += 1
            lpApplicationName = object_pydbg.get_unicode_string(args[0])
            print("callback_CreateProcessW_in lpApplicationName=", lpApplicationName)
            assert lpApplicationName.lower() == ping_binary_lower
            lpCommandLine = object_pydbg.get_unicode_string(args[1])
            print("callback_CreateProcessW_in lpCommandLine=%s." % lpCommandLine)
            assert lpCommandLine == "ping  -n 2 127.0.0.1"
            print("dwProcessId=", object_pydbg.dbg.dwProcessId, "dwThreadId=", object_pydbg.dbg.dwThreadId)

            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)
            return defines.DBG_CONTINUE

        def callback_CreateProcessW_out(object_pydbg, args, function_result):
            Context.count_out += 1
            lpApplicationName = object_pydbg.get_unicode_string(args[0])
            print("callback_CreateProcessW_out lpApplicationName=", lpApplicationName)
            assert lpApplicationName.lower() == ping_binary_lower
            lpCommandLine = object_pydbg.get_unicode_string(args[1])
            print("callback_CreateProcessW_out lpCommandLine=%s." % lpCommandLine)
            assert lpCommandLine == "ping  -n 2 127.0.0.1"

            self.assertTrue(object_pydbg.dbg.dwProcessId == created_process.pid)
            return defines.DBG_CONTINUE

        object_hooks.add(tst_pydbg, hook_CreateProcessW, 10, callback_CreateProcessW_in, callback_CreateProcessW_out)

        tst_pydbg.run()

        print("END", Context.count_in, Context.count_out)
        created_process.kill()
        # The first call is missed.
        self.assertTrue(Context.count_in == num_loops - 1)
        self.assertTrue(Context.count_out == num_loops - 1)

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

        hook_DOS_nslookup = tst_pydbg.func_resolve(b"ws2_32.dll", b"connect")

        assert hook_DOS_nslookup
        print("hook_DOS_nslookup=%016x" % hook_DOS_nslookup)

        class Context:
            port_number = -1
            sin_family = -1
            s_addr = -1

        def check_sockaddr_nslookup(object_pydbg, args):

            sockaddr_address = args[1]

            sin_family_memory = object_pydbg.read_process_memory(sockaddr_address, 2)
            Context.sin_family = struct.unpack("<H", sin_family_memory)[0]
            print("sin_family=", Context.sin_family)
            sockaddr_size = args[2]
            print("size=", args[2])

            # AF_INET = 2, if this is an IPV4 DNS server.
            if Context.sin_family == defines.AF_INET:
                # struct sockaddr_in {
                #         short   sin_family;
                #         u_short sin_port;
                #         struct  in_addr sin_addr;
                #         char    sin_zero[8];
                # };
                # struct in_addr {
                #   union {
                #     struct {
                #       u_char s_b1;
                #       u_char s_b2;
                #       u_char s_b3;
                #       u_char s_b4;
                #     } S_un_b;
                #     struct {
                #       u_short s_w1;
                #       u_short s_w2;
                #     } S_un_w;
                #     u_long S_addr;
                #   } S_un;
                # };
                ip_port_memory = object_pydbg.read_process_memory(sockaddr_address + 2, 2)
                Context.ip_port = struct.unpack(">H", ip_port_memory)[0]
                print("ip_port=", Context.ip_port)

                self.assertTrue(sockaddr_size == 16)
                self.assertTrue(Context.ip_port == 53)  # DNS

                s_addr_ipv4 = object_pydbg.read_process_memory(sockaddr_address + 4, 4)
                if is_py3:
                    addr_ipv4 = ".".join(["%d" % s_addr_ipv4[i] for i in range(4)])
                else:
                    addr_ipv4 = ".".join(["%d" % ord(s_addr_ipv4[i]) for i in range(4)])
                print("s_addr_ipv4=", addr_ipv4)

            # AF_INET6 = 23, if this is an IPV6 DNS server.
            elif Context.sin_family == defines.AF_INET6:
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
                Context.ip_port = struct.unpack(">H", ip_port_memory)[0]
                print("ip_port=", Context.ip_port)

                self.assertTrue(sockaddr_size == 28)
                self.assertTrue(Context.ip_port == 53) # DNS

                s_addr_ipv6 = object_pydbg.read_process_memory(sockaddr_address + 8, 16)
                if is_py3:
                    addr_ipv6 = str(s_addr_ipv6)
                else:
                    addr_ipv6 = "".join(["%02x" % ord(one_byte) for one_byte in s_addr_ipv6])

                print("s_addr_ipv6=", addr_ipv6)

            else:
                raise Exception("Invalid sa_family")

        def callback_DOS_nslookup_in(object_pydbg, args):
            print("callback_DOS_nslookup_in args=", args)
            check_sockaddr_nslookup(object_pydbg, args)
            return defines.DBG_CONTINUE

        def callback_DOS_nslookup_out(object_pydbg, args, function_result):
            print("callback_DOS_nslookup_out args=", args, function_result)
            check_sockaddr_nslookup(object_pydbg, args)
            return defines.DBG_CONTINUE

        object_hooks.add(tst_pydbg, hook_DOS_nslookup, 3, callback_DOS_nslookup_in, callback_DOS_nslookup_out)

        # The maximum number is variable. If too big, it hangs.
        created_process.stdin.write(b"primhillcomputers.com\n" * 5)
        created_process.stdin.write(b"quit\n")

        if is_py3:
            # The subprocess implementation is different between Python 2 and 3.
            # Hence, communicate() makes data available to the subprocess while it is still blocked.
            try:
                stdout_data, stderr_data = created_process.communicate(timeout=1.0)
            except subprocess.TimeoutExpired as exc:
                print("exc=", exc)
        tst_pydbg.run()

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
        self.assertTrue(Context.sin_family in [defines.AF_INET, defines.AF_INET6])


# BEWARE: When running DOS tests first, then Python tests fail.
@unittest.skipIf(is_platform_linux, "Windows only.")
class PythonHooksTest(unittest.TestCase):
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
        # The file is an Unicode string, to enforce CreateFileW() in Python 2.
        python_command = 'import time;time.sleep(2.0);f=open(u"%s", "w");f.close()' % temp_file_name
        creation_file_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        class Context:
            file_name_in = None
            file_name_out = None

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Attaching to pid=%d" % creation_file_process.pid)
        tst_pydbg.attach(creation_file_process.pid)

        object_hooks = utils.hook_container()

        hook_create_file_w = tst_pydbg.func_resolve(b"KERNEL32.dll", b"CreateFileW")
        print("hook_create_file_w=%016x" % hook_create_file_w)

        def callback_create_file_in(object_pydbg, args):
            Context.file_name_in = object_pydbg.get_unicode_string(args[0])
            print("callback_create_file_in file_name_in=", Context.file_name_in)
            self.assertTrue(Context.file_name_in == temp_file_name)
            return defines.DBG_CONTINUE

        def callback_create_file_out(object_pydbg, args, function_result):
            Context.file_name_out = object_pydbg.get_unicode_string(args[0])
            print("callback_create_file_out m=", Context.file_name_out)
            return defines.DBG_CONTINUE

        object_hooks.add(tst_pydbg, hook_create_file_w, 10, callback_create_file_in, callback_create_file_out)

        tst_pydbg.run()
        creation_file_process.terminate()
        self.assertTrue(Context.file_name_in == temp_file_name)
        self.assertTrue(Context.file_name_out == temp_file_name)
        os.remove(temp_file_name)

    def test_Python_DeleteFile_non_existent(self):
        """This attempts to delete a non-existent file."""
        tst_pydbg = pydbg.pydbg()

        temp_name = "test_tmp_delete_non_existent.tmp"
        # This is an Unicode filename, to force DeleteFileW() in Python 2.
        python_command = 'import time;import os;time.sleep(2);n=u"%s";f=open(n,"w");f.close();os.remove(n)' % temp_name
        deletion_file_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        class Context:
            file_name_in = None
            file_name_out = None

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Attaching to pid=%d" % deletion_file_process.pid)
        tst_pydbg.attach(deletion_file_process.pid)

        object_hooks = utils.hook_container()

        hook_delete_file_w = tst_pydbg.func_resolve(b"KERNEL32.dll", b"DeleteFileW")

        def callback_delete_file_in(object_pydbg, args):
            Context.file_name_in = object_pydbg.get_unicode_string(args[0])
            print("callback_delete_file_in file_name_in=", Context.file_name_in)
            return defines.DBG_CONTINUE

        def callback_delete_file_out(object_pydbg, args, function_result):
            Context.file_name_out = object_pydbg.get_unicode_string(args[0])
            print("callback_delete_file_out file_name_out=", Context.file_name_out, function_result)
            return defines.DBG_CONTINUE

        object_hooks.add(tst_pydbg, hook_delete_file_w, 1, callback_delete_file_in, callback_delete_file_out)

        tst_pydbg.run()
        deletion_file_process.kill()
        self.assertTrue(Context.file_name_in == temp_name)
        self.assertTrue(Context.file_name_out == temp_name)

    def test_Python_system(self):
        """A Python process runs the function system()"""
        tst_pydbg = pydbg.pydbg()

        system_command = "dir"
        python_command = 'import time;import os;time.sleep(2);os.system("%s")' % system_command
        system_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        class Context:
            system_command_out = None

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Attaching to pid=%d" % system_process.pid)
        tst_pydbg.attach(system_process.pid)

        object_hooks = utils.hook_container()

        function_name_create_process =  b"CreateProcessW" if is_py3 else b"CreateProcessA"

        hook_create_process = tst_pydbg.func_resolve(b"KERNEL32.dll", function_name_create_process)

        def callback_system_out(object_pydbg, args, function_result):
            Context.system_command_out = object_pydbg.get_text_string(args[0])
            print("callback_system_out system_command_out=", Context.system_command_out)
            return defines.DBG_CONTINUE

        object_hooks.add(tst_pydbg, hook_create_process, 1, None, callback_system_out)

        tst_pydbg.run()
        system_process.kill()
        # Conversion to lower case because c:\windows might be C:\Windows on Travis.
        print("windows_system32_cmd_exe=", windows_system32_cmd_exe)
        self.assertTrue(Context.system_command_out.lower() == windows_system32_cmd_exe.lower())

    def test_Python_mkdir_rmdir(self):
        """A Python process creates then removes a directory."""
        tst_pydbg = pydbg.pydbg()

        temp_path = unique_temporary_path("test_tmp_directory", ".tmp")

        python_command = "import time;import os;time.sleep(2.0);dn=r'%s';os.mkdir(dn);os.rmdir(dn)" % temp_path
        print("python_command=", python_command)
        dir_command_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

        print("dir_command_process ", dir_command_process.pid)

        class Context:
            created_directory_in = None
            created_directory_out = None
            removed_directory_in = None
            removed_directory_out = None

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Attaching to pid=%d" % dir_command_process.pid)
        tst_pydbg.attach(dir_command_process.pid)

        object_hooks = utils.hook_container()

        function_name_create_directory = b"CreateDirectoryW" if is_py3 else b"CreateDirectoryA"
        function_name_remove_directory = b"RemoveDirectoryW" if is_py3 else b"RemoveDirectoryA"

        hook_CreateDirectory = tst_pydbg.func_resolve(b"KERNEL32.dll", function_name_create_directory)

        def callback_CreateDirectory_in(object_pydbg, args):
            Context.created_directory_in = object_pydbg.get_text_string(args[0])
            print("callback_CreateDirectory_in created_directory_in=", Context.created_directory_in)
            return defines.DBG_CONTINUE

        def callback_CreateDirectory_out(object_pydbg, args, function_result):
            Context.created_directory_out = object_pydbg.get_text_string(args[0])
            print("callback_CreateDirectory_out created_directory_out=", Context.created_directory_out)
            return defines.DBG_CONTINUE

        object_hooks.add(tst_pydbg, hook_CreateDirectory, 2, callback_CreateDirectory_in, callback_CreateDirectory_out)

        hook_RemoveDirectory = tst_pydbg.func_resolve(b"KERNEL32.dll", function_name_remove_directory)

        def callback_RemoveDirectory_in(object_pydbg, args):
            Context.removed_directory_in = object_pydbg.get_text_string(args[0])
            print("callback_RemoveDirectory_in removed_directory_in=", Context.removed_directory_in)
            return defines.DBG_CONTINUE

        def callback_RemoveDirectory_out(object_pydbg, args, function_result):
            Context.removed_directory_out = object_pydbg.get_text_string(args[0])
            print("callback_RemoveDirectory_out removed_directory_out=", Context.removed_directory_out)
            return defines.DBG_CONTINUE

        object_hooks.add(tst_pydbg, hook_RemoveDirectory, 1, callback_RemoveDirectory_in, callback_RemoveDirectory_out)

        tst_pydbg.run()
        stdout_data, stderr_data = dir_command_process.communicate()
        self.assertTrue(not stdout_data)
        self.assertTrue(not stderr_data)
        dir_command_process.kill()

        print("created_directory_in=", Context.created_directory_in)
        print("created_directory_out=", Context.created_directory_out)
        print("removed_directory_in=", Context.removed_directory_in)
        print("removed_directory_out=", Context.removed_directory_out)

        self.assertTrue(Context.created_directory_in == temp_path)
        self.assertTrue(Context.created_directory_out == temp_path)
        self.assertTrue(Context.removed_directory_in == temp_path)
        self.assertTrue(Context.removed_directory_out == temp_path)

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

        tst_pydbg.run()
        print_hello_process.communicate()
        print_hello_process.terminate()
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

        # windows_system32_cmd_exe
        expected_command_line = windows_system32_cmd_exe + " /c "+ " ".join(process_command)
        print("expected_command_line=", expected_command_line)
        actual_command_line = " ".join(Context.command_line)
        print("actual_command_line=", actual_command_line)
        # Conversion to lower case because c:\windows might be C:\Windows.
        self.assertTrue(actual_command_line.lower() == expected_command_line.lower())
        print_shell_process.communicate()
        print_shell_process.terminate()

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

        print("Connect test: Attaching to pid=%d" % url_process.pid)
        tst_pydbg.attach(url_process.pid)

        object_hooks = utils.hook_container()

        # This library contains the functions socket(), connect(), accept(), bind() etc...
        hook_connect = tst_pydbg.func_resolve(b"ws2_32.dll", b"connect")

        class Context:
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
            Context.sin_family = struct.unpack("<H", sin_family_memory)[0]
            print("sin_family=", Context.sin_family)

            ip_port_memory = object_pydbg.read_process_memory(sockaddr_address + 2, 2)
            Context.ip_port = struct.unpack(">H", ip_port_memory)[0]
            print("ip_port=", Context.ip_port)

            # struct in_addr {
            #     unsigned long s_addr;  // load with inet_aton()
            # };
            s_addr_memory = object_pydbg.read_process_memory(sockaddr_address + 4, 4)
            s_addr_integer = struct.unpack(">I", s_addr_memory)[0]

            Context.s_addr ="%d.%d.%d.%d" % (
                (s_addr_integer & 0xFF000000)/0x1000000,
                (s_addr_integer & 0x00FF0000)/0x10000,
                (s_addr_integer & 0x0000FF00)/0x100,
                (s_addr_integer & 0x000000FF)/0x1)
            print("s_addr=%s" % Context.s_addr)

        def callback_in_connect(object_pydbg, args):
            check_sockaddr_content(object_pydbg, args)
            return defines.DBG_CONTINUE

        def callback_out_connect(object_pydbg, args, function_result):
            check_sockaddr_content(object_pydbg, args)
            return defines.DBG_CONTINUE

        # int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
        object_hooks.add(tst_pydbg, hook_connect, 3, callback_in_connect, callback_out_connect)

        tst_pydbg.run()
        os.remove(temporary_python_file.name)
        url_process.terminate()

        self.assertTrue(Context.sin_family == defines.AF_INET)
        self.assertTrue(Context.ip_port == server_port)
        self.assertTrue(Context.s_addr == socket.gethostbyname(server_domain))


@unittest.skipIf(is_platform_linux, "Windows only.")
@unittest.skipIf(pkgutil.find_loader('pywin32'), "Needs pywin32 module.")
class Pywin32HooksTest(unittest.TestCase):
    """
    Test pydbg from Python processes created with win32.
    It is necessary to create suspended processes, so that breakpoints can be applied before they run.
    The class subprocess.Popen does not allow the creation of suspended processes.
    """

    def test_win32_process_basic(self):
        start_info = win32process.STARTUPINFO()
        start_info.dwFlags = win32con.STARTF_USESHOWWINDOW

        # temporary_python_file = tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False)
        temp_data_file_path = unique_temporary_path("test_win32_process_basic", ".txt")

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

        temp_data_file_path = unique_temporary_path("test_win32_process", ".txt")

        temp_python_path = unique_temporary_path("test_win32_process", ".py")

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

        win32process.ResumeThread(prc_info[1])

        time.sleep(0.5)
        # The resumed process had time enough to create the file.
        with open(temp_data_file_path) as result_file:
            first_line = result_file.readlines()[0]
        print("first_line=", first_line)

        os.remove(temp_data_file_path)
        os.remove(temp_python_path)

        self.assertTrue(first_line == result_message)

    def test_win32_process_suspend_hook(self):
        """This tests a process created in suspended state, then stopping in breakpoints."""
        start_info = win32process.STARTUPINFO()
        start_info.dwFlags = win32con.STARTF_USESHOWWINDOW

        temp_text_file_path = unique_temporary_path("test_win32_process_suspend_hook", ".txt")
        temp_python_path = unique_temporary_path("test_win32_process_suspend_hook", ".py")

        # A Python script writes to a file, a text containing the pid and its parent.
        script_content = "import os;open(r'%s', 'w').write('Hello_%d_%%d' %% os.getpid())" % (temp_text_file_path, root_process_id)
        with open(temp_python_path, "w") as temp_python_file:
            temp_python_file.write(script_content)

        python_command = "%s %s" % (sys.executable, temp_python_path)
        # CreateProcess returns a tuple (hProcess, hThread, dwProcessId, dwThreadId)
        prc_info = win32process.CreateProcess(None, python_command, None, None, False,  # bInheritHandles
                                              win32con.CREATE_NEW_CONSOLE | win32con.CREATE_SUSPENDED, None,
                                              os.getcwd(), start_info)

        sub_process_id = prc_info[2]
        print("Suspend test: Attaching to pid=%d" % sub_process_id)

        tst_pydbg = pydbg.pydbg()
        tst_pydbg.attach(sub_process_id)

        function_name_create_file = b"CreateFileW" if is_py3 else b"CreateFileA"

        class Context:
            filename_in = None
            filename_out = None

        def callback_CreateFile_in(object_pydbg, args):
            Context.filename_in = object_pydbg.get_text_string(args[0])
            print("callback_CreateFile_in file_name=", Context.filename_in,
                  object_pydbg.dbg.dwProcessId, object_pydbg.dbg.dwThreadId)
            return defines.DBG_CONTINUE

        def callback_CreateFile_out(object_pydbg, args, function_result):
            Context.filename_out = object_pydbg.get_text_string(args[0])
            Context.result = function_result
            print("callback_CreateFile_out file_name=", Context.filename_out,
                  object_pydbg.dbg.dwProcessId, object_pydbg.dbg.dwThreadId,
                  "result=", function_result)
            return defines.DBG_CONTINUE

        object_hooks = utils.hook_container()

        # This is called for each loaded DLL. As soos as possible,
        # it sets a breakpoint on the Windows function for files creation.
        def load_dll_callback(object_pydbg):
            # self.dbg.u.LoadDll is _LOAD_DLL_DEBUG_INFO
            dll_filename = win32file.GetFinalPathNameByHandle(
                object_pydbg.dbg.u.LoadDll.hFile, win32con.FILE_NAME_NORMALIZED)
            if dll_filename.startswith("\\\\?\\"):
                dll_filename = dll_filename[4:]

            print("load_dll_callback dll_filename=", dll_filename)
            self.assertTrue(object_pydbg == tst_pydbg)
            if dll_filename.upper().endswith("KERNEL32.dll".upper()):
                # At this stage, the DLL cannot be enumerated yet: For an unknown reason,
                # it cannot be obtained with CreateToolhelp32Snapshot and Module32First/Module32Next,
                # so we cannot use func_resolve() with "KERNEL32.dll" as DLL name.
                hook_CreateFile = object_pydbg.func_resolve_from_dll(
                    object_pydbg.dbg.u.LoadDll.lpBaseOfDll,
                    function_name_create_file)

                object_hooks.add(tst_pydbg, hook_CreateFile, 1, callback_CreateFile_in, callback_CreateFile_out)
            return defines.DBG_CONTINUE

        # This event is received after the DLL is mapped into the address space of the debuggee.
        tst_pydbg.set_callback(defines.LOAD_DLL_DEBUG_EVENT, load_dll_callback)

        win32process.ResumeThread(prc_info[1])

        tst_pydbg.run()
        # A bit of extra time so the subprocess can do its work then finish.
        time.sleep(0.1)

        # The created subprocess must exit.
        try:
            sub_process_psutil = psutil.Process(sub_process_id)
            self.fail("This process should have left:%d" % sub_process_id)
        except psutil.NoSuchProcess:
            pass

        print("Context.filename_in=", Context.filename_in)
        print("Context.filename_out=", Context.filename_in)
        print("Context.result=", Context.result)
        print("temp_data_file_path=", temp_text_file_path)

        # The resumed process had time enough to create the file.
        with open(temp_text_file_path) as result_file:
            first_line = result_file.readlines()[0]
        print("first_line=", first_line)
        expected_line = 'Hello_%d_%d' % (root_process_id, sub_process_id)
        self.assertTrue(first_line == expected_line)

        os.remove(temp_text_file_path)
        os.remove(temp_python_path)

        # This is the last accessed file.
        self.assertTrue(Context.filename_in == temp_text_file_path)
        self.assertTrue(Context.filename_out == temp_text_file_path)

        # This does not work with Python 3.7 (Travis). Maybe this Python version uses another
        # Windows API function, such as CreateFile2 ??

    def test_win32_system_tasklist(self):
        """This tests a process created in suspended state, then creating a subprocess."""
        start_info = win32process.STARTUPINFO()
        start_info.dwFlags = win32con.STARTF_USESHOWWINDOW

        temp_text_file_path = unique_temporary_path("test_win32_system_tasklist", ".txt")
        temp_python_path = unique_temporary_path("test_win32_system_tasklist", ".py")

        result_message = "System_%d" % root_process_id
        # This script starts a DOS process which writes a string in a file, then its pid:
        # C:\Users\rchateau>tasklist /fi "IMAGENAME eq tasklist.exe" /nh /fo CSV /v
        # "tasklist.exe","7944","Console","1","7,428 K","Unknown","rchateau-HP\rchateau","0:00:00","N/A"
        #
        # After that, the main process appends another string to the same file.
        script_content = """
import os
os.system(r'echo %s > %s&tasklist /fi "IMAGENAME eq tasklist.exe" /nh /fo CSV /v >>%s')
with open(r'%s', "a") as append_file:
    append_file.write('Pid_%%d' %% os.getpid())
""" % (result_message, temp_text_file_path, temp_text_file_path, temp_text_file_path)
        with open(temp_python_path, "w") as temp_python_file:
            temp_python_file.write(script_content)
        # print("script_content=", script_content)

        python_command = "%s %s" % (sys.executable, temp_python_path)
        # CreateProcess returns a tuple (hProcess, hThread, dwProcessId, dwThreadId)
        prc_info = win32process.CreateProcess(None, python_command, None, None, False,  # bInheritHandles
                                              win32con.CREATE_NEW_CONSOLE | win32con.CREATE_SUSPENDED, None,
                                              os.getcwd(), start_info)

        sub_process_id = prc_info[2]
        print("Tasklist test: Attaching to pid=%d" % sub_process_id)

        tst_pydbg = pydbg.pydbg()
        tst_pydbg.attach(sub_process_id)

        class Context:
            lpApplicationName_in = None
            lpCommandLine_in = None
            dwProcessId_in = None
            lpApplicationName_out = None
            lpCommandLine_out = None
            dwProcessId_out = None

        object_hooks = utils.hook_container()

        def load_dll_callback(object_pydbg):
            # self.dbg.u.LoadDll is _LOAD_DLL_DEBUG_INFO
            dll_filename = win32file.GetFinalPathNameByHandle(
                object_pydbg.dbg.u.LoadDll.hFile, win32con.FILE_NAME_NORMALIZED)
            if dll_filename.startswith("\\\\?\\"):
                dll_filename = dll_filename[4:]
            # print("load_dll_callback dll_filename=", dll_filename)

            self.assertTrue(object_pydbg == tst_pydbg)

            if dll_filename.upper().endswith("KERNEL32.dll".upper()):
                function_name_create_process = b"CreateProcessW" if is_py3 else b"CreateProcessA"

                # At this stage, the DLL cannot be enumerated yet: For an unknown reason,
                # it cannot be obtained with CreateToolhelp32Snapshot and Module32First/Module32Next
                hook_CreateProcessW = object_pydbg.func_resolve_from_dll(
                    object_pydbg.dbg.u.LoadDll.lpBaseOfDll,
                    function_name_create_process)
                print("load_dll_callback hook_CreateProcessW=", hook_CreateProcessW)

                def callback_CreateProcessW_in(object_pydbg, args):
                    Context.lpApplicationName_in = object_pydbg.get_text_string(args[0])
                    print("lpApplicationName_in=", Context.lpApplicationName_in)
                    Context.lpCommandLine_in = object_pydbg.get_text_string(args[1])
                    print("lpCommandLine_in=", Context.lpCommandLine_in)
                    Context.dwProcessId_in = object_pydbg.dbg.dwProcessId
                    return defines.DBG_CONTINUE

                def callback_CreateProcessW_out(object_pydbg, args, function_result):
                    Context.lpApplicationName_out = object_pydbg.get_text_string(args[0])
                    print("lpApplicationName_out=", Context.lpApplicationName_out)
                    Context.lpCommandLine_out = object_pydbg.get_text_string(args[1])
                    print("lpCommandLine_out=", Context.lpCommandLine_out)
                    Context.dwProcessId_out = object_pydbg.dbg.dwProcessId
                    return defines.DBG_CONTINUE

                object_hooks.add(tst_pydbg, hook_CreateProcessW, 2, callback_CreateProcessW_in,
                                 callback_CreateProcessW_out)

            return defines.DBG_CONTINUE

        # This event is received after the DLL is mapped into the address space of the debuggee.
        tst_pydbg.set_callback(defines.LOAD_DLL_DEBUG_EVENT, load_dll_callback)

        win32process.ResumeThread(prc_info[1])

        tst_pydbg.run()
        # A bit of extra time so the subprocess can do its work then finish.
        time.sleep(0.1)

        # The created subprocess must exit.
        try:
            sub_process_psutil = psutil.Process(sub_process_id)
            self.fail("This process should have left:%d" % sub_process_id)
        except psutil.NoSuchProcess:
            pass

        # print("Context.filename_in=", Context.filename_in, type(Context.filename_in))
        print("temp_data_file_path=", temp_text_file_path)

        # The resumed process had time enough to create the file.
        with open(temp_text_file_path) as result_file:
            written_lines = result_file.readlines()
        # written_lines= ['System_32436 \n', '"tasklist.exe","16828","Console","1","7,784 K","Unknown","user\\domain","0:00:00","N/A"\n', 'Pid_22600']
        print("written_lines=", written_lines)
        result_message_nl = result_message + " \n"
        self.assertTrue(written_lines[0] == result_message_nl)
        split_tasklist = written_lines[1].split(",")
        self.assertTrue(split_tasklist[0] == '"tasklist.exe"')
        # In Pycharm: "Console, on Travis: "Services".
        self.assertTrue(split_tasklist[2] in ['"Console"', '"Services"'])
        self.assertTrue(written_lines[2] == "Pid_%d" % sub_process_id)

        print("test_win32_system_tasklist Context.lpApplicationName_in=", Context.lpApplicationName_in)
        self.assertTrue(Context.lpApplicationName_in == windows_system32_cmd_exe)
        self.assertTrue(Context.lpCommandLine_in.startswith(windows_system32_cmd_exe))
        self.assertTrue(Context.dwProcessId_in == sub_process_id)
        self.assertTrue(Context.lpApplicationName_out == windows_system32_cmd_exe)
        self.assertTrue(Context.lpCommandLine_out.startswith(windows_system32_cmd_exe))
        self.assertTrue(Context.dwProcessId_out == sub_process_id)

        os.remove(temp_text_file_path)
        os.remove(temp_python_path)

    def test_win32_system_echo_to_file(self):
        """This attempts to catch the file creation of a DOS process started by Python."""
        start_info = win32process.STARTUPINFO()
        start_info.dwFlags = win32con.STARTF_USESHOWWINDOW

        temp_text_file_path = unique_temporary_path("test_win32_system_echo_to_file", ".txt")
        temp_python_path = unique_temporary_path("test_win32_system_echo_to_file", ".py")

        result_message = "System_%d" % root_process_id
        # This script starts a DOS process which writes a string in a file.
        #
        # After that, the main process appends another string to the same file.
        script_content = """
import os
os.system(r'echo %s > %s')
with open(r'%s', "a") as append_file:
    append_file.write('Pid_%%d' %% os.getpid())
""" % (result_message, temp_text_file_path, temp_text_file_path)
        with open(temp_python_path, "w") as temp_python_file:
            temp_python_file.write(script_content)
        # print("script_content=", script_content)

        python_command = "%s %s" % (sys.executable, temp_python_path)
        # CreateProcess returns a tuple (hProcess, hThread, dwProcessId, dwThreadId)
        prc_info = win32process.CreateProcess(None, python_command, None, None, False,  # bInheritHandles
                                              win32con.CREATE_NEW_CONSOLE | win32con.CREATE_SUSPENDED, None,
                                              os.getcwd(), start_info)

        sub_process_id = prc_info[2]
        print("Echo test: Attaching to pid=%d" % sub_process_id)

        tst_pydbg = pydbg.pydbg()
        tst_pydbg.attach(sub_process_id)

        class Context:
            lpApplicationName_in = None
            lpCommandLine_in = None
            dwProcessId_in = None
            lpApplicationName_out = None
            lpCommandLine_out = None
            dwProcessId_out = None

        object_hooks = utils.hook_container()

        def load_dll_callback(object_pydbg):
            # self.dbg.u.LoadDll is _LOAD_DLL_DEBUG_INFO
            dll_filename = win32file.GetFinalPathNameByHandle(
                object_pydbg.dbg.u.LoadDll.hFile, win32con.FILE_NAME_NORMALIZED)
            if dll_filename.startswith("\\\\?\\"):
                dll_filename = dll_filename[4:]
            # print("load_dll_callback dll_filename=", dll_filename)

            self.assertTrue(object_pydbg == tst_pydbg)

            if dll_filename.upper().endswith("KERNEL32.dll".upper()):
                function_name_create_process = b"CreateProcessW" if is_py3 else b"CreateProcessA"

                # At this stage, the DLL cannot be enumerated yet: For an unknown reason,
                # it cannot be obtained with CreateToolhelp32Snapshot and Module32First/Module32Next
                hook_CreateProcessW = object_pydbg.func_resolve_from_dll(
                    object_pydbg.dbg.u.LoadDll.lpBaseOfDll,
                    function_name_create_process)
                print("load_dll_callback hook_CreateProcessW=", hook_CreateProcessW)

                def callback_CreateProcessW_in(object_pydbg, args):
                    Context.lpApplicationName_in = object_pydbg.get_text_string(args[0])
                    print("lpApplicationName_in=", Context.lpApplicationName_in)
                    Context.lpCommandLine_in = object_pydbg.get_text_string(args[1])
                    print("lpCommandLine_in=", Context.lpCommandLine_in)
                    Context.dwProcessId_in = object_pydbg.dbg.dwProcessId
                    return defines.DBG_CONTINUE

                def callback_CreateProcessW_out(object_pydbg, args, function_result):
                    Context.lpApplicationName_out = object_pydbg.get_text_string(args[0])
                    print("lpApplicationName_out=", Context.lpApplicationName_out)
                    Context.lpCommandLine_out = object_pydbg.get_text_string(args[1])
                    print("lpCommandLine_out=", Context.lpCommandLine_out)
                    Context.dwProcessId_out = object_pydbg.dbg.dwProcessId
                    return defines.DBG_CONTINUE

                object_hooks.add(tst_pydbg, hook_CreateProcessW, 2, callback_CreateProcessW_in,
                                 callback_CreateProcessW_out)

            return defines.DBG_CONTINUE

        # This event is received after the DLL is mapped into the address space of the debuggee.
        tst_pydbg.set_callback(defines.LOAD_DLL_DEBUG_EVENT, load_dll_callback)

        win32process.ResumeThread(prc_info[1])

        tst_pydbg.run()
        # A bit of extra time so the subprocess can do its work then finish.
        time.sleep(0.1)

        # The created subprocess must exit.
        try:
            sub_process_psutil = psutil.Process(sub_process_id)
            self.fail("This process should have left:%d" % sub_process_id)
        except psutil.NoSuchProcess:
            pass

        # print("Context.filename_in=", Context.filename_in, type(Context.filename_in))
        print("temp_data_file_path=", temp_text_file_path)

        # The resumed process had time enough to create the file.
        with open(temp_text_file_path) as result_file:
            written_lines = result_file.readlines()
        # written_lines= ['System_32436 \n', '"tasklist.exe","16828","Console","1","7,784 K","Unknown","user\\domain","0:00:00","N/A"\n', 'Pid_22600']
        print("written_lines=", written_lines)
        result_message_nl = result_message + " \n"
        self.assertTrue(written_lines[0] == result_message_nl)
        self.assertTrue(written_lines[1] == "Pid_%d" % sub_process_id)

        print("test_win32_system_echo_to_file Context.lpApplicationName_in=", Context.lpApplicationName_in)
        self.assertTrue(Context.lpApplicationName_in == windows_system32_cmd_exe)
        self.assertTrue(Context.lpCommandLine_in.startswith(windows_system32_cmd_exe))
        self.assertTrue(Context.dwProcessId_in == sub_process_id)
        self.assertTrue(Context.lpApplicationName_out == windows_system32_cmd_exe)
        self.assertTrue(Context.lpCommandLine_out.startswith(windows_system32_cmd_exe))
        self.assertTrue(Context.dwProcessId_out == sub_process_id)

        os.remove(temp_text_file_path)
        os.remove(temp_python_path)


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

