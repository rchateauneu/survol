#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import subprocess
import tempfile
import platform
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
class PydbgBasicTest(unittest.TestCase):
    """
    Test basic features
    """

    # This tests the callbacks which are used for good in other tests.
    # It starts a DOS process which attempts to remove a directory.
    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    @unittest.skipIf(platform.architecture()[0] != '64bit', "Only on 64 bits machines.")
    def test_pydbg_Wow64_Self(self):
        import pydbg

        is_wow64 = pydbg.process_is_wow64(pid=None)
        print("is_wow64=", is_wow64)
        print("platform.architecture()=", platform.architecture())

        if sys.maxsize > 2 ** 32:
            self.assertTrue(is_wow64 == False)
        else:
            self.assertTrue(is_wow64 == True)

    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    @unittest.skipIf(platform.architecture()[0] != '64bit', "Only on 64 bits machines.")
    def test_pydbg_Wow64_Other(self):
        """This starts a 32 bits process on a 64 bits platform"""
        import pydbg

        tst_pydbg = create_pydbg()

        cmd32_command = r"C:\Windows\SysWOW64\cmd.exe"

        created_process = subprocess.Popen(cmd32_command, shell=False)
        print("Created process:%d" % created_process.pid)

        time.sleep(0.5)

        print("Attaching to created_process.pid=%d" % created_process.pid)
        tst_pydbg.attach(created_process.pid)

        is_wow64 = pydbg.process_is_wow64(pid=created_process.pid)
        print("is_wow64=", is_wow64)

        self.assertTrue(is_wow64 == True)

    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_listdlls(self):
        # This is just for debugging.
        os.system('listdlls %d' % os.getpid())

    # 0x000000001d000000  0xb000    C:\Python27\python.exe
    # 0x0000000076fd0000  0x1aa000  C:\windows\SYSTEM32\ntdll.dll
    # 0x0000000076eb0000  0x11f000  C:\windows\system32\kernel32.dll
    # 0x00000000fcf20000  0x6a000   C:\windows\system32\KERNELBASE.dll
    # 0x000000001e000000  0x2f3000  C:\windows\system32\python27.dll
    # 0x0000000076db0000  0xfa000   C:\windows\system32\USER32.dll
    # 0x00000000fd080000  0x67000   C:\windows\system32\GDI32.dll
    # 0x00000000fea90000  0xe000    C:\windows\system32\LPK.dll
    # 0x00000000feca0000  0xcb000   C:\windows\system32\USP10.dll
    # 0x00000000fe8f0000  0x9f000   C:\windows\system32\msvcrt.dll
    # 0x00000000fe760000  0xdb000   C:\windows\system32\ADVAPI32.dll
    # 0x00000000ff210000  0x1f000   C:\windows\SYSTEM32\sechost.dll
    # 0x00000000fe1f0000  0x12d000  C:\windows\system32\RPCRT4.dll
    # 0x00000000fd0f0000  0xd8a000  C:\windows\system32\SHELL32.dll
    # 0x00000000fe9f0000  0x71000   C:\windows\system32\SHLWAPI.dll
    # 0x0000000072e90000  0xa3000   C:\windows\WinSxS\amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.6161_none_08e61857a83bc251\MSVCR90.dll
    # 0x00000000fe8c0000  0x2e000   C:\windows\system32\IMM32.DLL
    # 0x00000000fe650000  0x109000  C:\windows\system32\MSCTF.dll
    # 0x0000000080000000  0x184000  C:\Python27\DLLs\_hashlib.pyd
    # 0x00000000fc4b0000  0x18000   C:\windows\system32\CRYPTSP.dll
    # 0x00000000fc1b0000  0x47000   C:\windows\system32\rsaenh.dll
    # 0x00000000fcac0000  0xf000    C:\windows\system32\CRYPTBASE.dll
    # 0x00000000003f0000  0xf000    C:\Python27\DLLs\_socket.pyd
    # 0x00000000ff0e0000  0x4d000   C:\windows\system32\WS2_32.dll
    # 0x00000000ff2d0000  0x8000    C:\windows\system32\NSI.dll
    # 0x0000000002b50000  0x225000  C:\Python27\DLLs\_ssl.pyd
    # 0x00000000fcd50000  0x16d000  C:\windows\system32\CRYPT32.dll
    # 0x00000000fccc0000  0xf000    C:\windows\system32\MSASN1.dll
    # 0x0000000001d60000  0x11000   C:\Python27\lib\site-packages\psutil\_psutil_windows.pyd
    # 0x00000000771a0000  0x7000    C:\windows\system32\PSAPI.DLL
    # 0x00000000f9fb0000  0x27000   C:\windows\system32\IPHLPAPI.DLL
    # 0x00000000f9fa0000  0xb000    C:\windows\system32\WINNSI.DLL
    # 0x00000000facb0000  0x11000   C:\windows\system32\WTSAPI32.dll
    # 0x00000000fb160000  0x2c000   C:\windows\system32\POWRPROF.dll
    # 0x00000000fef00000  0x1d7000  C:\windows\system32\SETUPAPI.dll
    # 0x00000000fcec0000  0x36000   C:\windows\system32\CFGMGR32.dll
    # 0x00000000ff130000  0xda000   C:\windows\system32\OLEAUT32.dll
    # 0x00000000feaa0000  0x1fc000  C:\windows\system32\ole32.dll
    # 0x00000000fcd30000  0x1a000   C:\windows\system32\DEVOBJ.dll
    # 0x00000000fa620000  0x15000   C:\windows\system32\NLAapi.dll
    # 0x00000000f6f50000  0x15000   C:\windows\system32\napinsp.dll
    # 0x00000000f6e50000  0x19000   C:\windows\system32\pnrpnsp.dll
    # 0x00000000fc450000  0x55000   C:\windows\System32\mswsock.dll
    # 0x00000000fc2d0000  0x5b000   C:\windows\system32\DNSAPI.dll
    # 0x00000000f6e40000  0xb000    C:\windows\System32\winrnr.dll
    # 0x0000000072d90000  0x26000   C:\Program Files\Bonjour\mdnsNSP.dll
    # 0x00000000f6e30000  0x10000   C:\windows\system32\wshbth.dll
    # 0x000000001e8c0000  0x24000   C:\Python27\lib\site-packages\win32\win32api.pyd
    # 0x00000000fbda0000  0xc000    C:\windows\system32\VERSION.dll
    # 0x000000001e7a0000  0x26000   C:\windows\system32\pywintypes27.dll
    # 0x00000000fca60000  0xb000    C:\windows\system32\secur32.dll
    # 0x00000000fca90000  0x25000   C:\windows\system32\SSPICLI.DLL
    # 0x000000001d100000  0x2c000   C:\Python27\DLLs\_elementtree.pyd
    # 0x0000000002a30000  0x2c000   C:\Python27\DLLs\pyexpat.pyd
    # 0x000000001d1a0000  0x1f000   C:\Python27\DLLs\_ctypes.pyd
    # 0x0000000003930000  0xab000   C:\Python27\DLLs\unicodedata.pyd
    # 0x00000000f9e40000  0x53000   C:\windows\System32\fwpuclnt.dll
    # 0x00000000f7900000  0x8000    C:\windows\system32\rasadhlp.dll
    # 0x00000000fc440000  0x7000    C:\windows\System32\wship6.dll
    # 0x00000000fbe70000  0x7000    C:\windows\System32\wshtcpip.dll
    # 0x00000000fcb70000  0x57000   C:\windows\system32\apphelp.dll

    # C:\windows\system32\WS2_32.dll is loaded but maybe not at the same address than in the subprocess.


    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_psutil_memory_maps(self):
        # This is just for debugging.
        import psutil
        p = psutil.Process(os.getpid())
        for dll in p.memory_maps():
            print(dll.path)

    # C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\tests\init.pyc Fixed sys.executableC:\Windows\System32\wshbth.dll
    # C:\Windows\System32\oleaut32.dll
    # C:\Windows\System32\devobj.dll
    # C:\Windows\System32\secur32.dll
    # C:\Windows\System32\advapi32.dll
    # C:\Windows\System32\msvcrt.dll
    # C:\Windows\System32\ws2_32.dll
    # C:\Windows\System32\en-US\KernelBase.dll.mui
    # C:\Windows\winsxs\amd64_microsoft.vc90.crt_1fc8b3b9a1e18e3b_9.0.30729.6161_none_08e61857a83bc251\msvcr90.dll
    # C:\Windows\System32\python27.dll
    # C:\Windows\System32\winnsi.dll
    # C:\Windows\System32\sspicli.dll
    # C:\Windows\System32\locale.nls
    # C:\Windows\System32\pywintypes27.dll
    # C:\Windows\System32\cryptsp.dll
    # C:\Windows\System32\nlaapi.dll
    # C:\Windows\System32\shlwapi.dll
    # C:\Python27\DLLs\_ssl.pyd
    # C:\Windows\System32\winrnr.dll
    # C:\Windows\System32\IPHLPAPI.DLL
    # C:\Windows\System32\setupapi.dll
    # C:\Python27\python.exe
    # C:\Windows\System32\wtsapi32.dll
    # C:\Python27\DLLs\_elementtree.pyd
    # C:\Windows\System32\version.dll
    # C:\Windows\System32\pnrpnsp.dll
    # C:\Windows\System32\ole32.dll
    # C:\Python27\DLLs\unicodedata.pyd
    # C:\Windows\System32\imm32.dll
    # C:\Windows\System32\NapiNSP.dll
    # C:\Windows\System32\powrprof.dll
    # C:\Windows\System32\usp10.dll
    # C:\Windows\System32\user32.dll
    # C:\Python27\DLLs\_hashlib.pyd
    # C:\Windows\System32\shell32.dll
    # C:\Windows\System32\ntdll.dll
    # C:\Windows\System32\psapi.dll
    # C:\Python27\DLLs\_socket.pyd
    # C:\Windows\System32\rasadhlp.dll
    # C:\Windows\System32\rpcrt4.dll
    # C:\Windows\System32\apisetschema.dll
    # C:\Windows\System32\lpk.dll
    # C:\Python27\DLLs\_ctypes.pyd
    # C:\Windows\System32\crypt32.dll
    # C:\Windows\System32\dnsapi.dll
    # C:\Windows\System32\mswsock.dll
    # C:\Python27\Lib\site-packages\win32\win32api.pyd
    # C:\Windows\System32\WSHTCPIP.DLL
    # C:\Program Files\Bonjour\mdnsNSP.dll
    # C:\Windows\System32\wship6.dll
    # C:\Windows\System32\FWPUCLNT.DLL
    # C:\Windows\System32\cryptbase.dll
    # C:\Windows\System32\sechost.dll
    # C:\Windows\System32\gdi32.dll
    # C:\Python27\DLLs\pyexpat.pyd
    # C:\Python27\Lib\site-packages\psutil\_psutil_windows.pyd
    # C:\Windows\Globalization\Sorting\SortDefault.nls
    # C:\Windows\System32\msctf.dll
    # C:\Windows\System32\nsi.dll
    # C:\Windows\System32\msasn1.dll
    # C:\Windows\System32\rsaenh.dll
    # C:\Windows\System32\kernel32.dll
    # C:\Windows\System32\cfgmgr32.dll
    # C:\Windows\System32\KernelBase.dll

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
            if object_pydbg.is_wow64:
                self.assertTrue(file_name == non_existent_file)
            else:
                self.assertTrue(file_name in [non_existent_file, r"C:\Windows\SysWOW64\cmd.exe"])
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

        # This is converted to lower-case because of different behaviour of Windows versions.
        ping_program_path = r"C:\windows\system32\PING.EXE"

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
            assert lpApplicationName.lower() == ping_program_path.lower()
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
            assert lpApplicationName.lower() == ping_program_path.lower()
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

        # Same error messages with these functions:
        # "Only part of a ReadProcessMemory or WriteProcessMemory request was completed"
        # socket, WSAConnectByNameA, WSAConnectByNameW, WSAStringToAddressA
        # hook_address_socket = tst_pydbg.func_resolve_experimental(u"Ws2_32.dll", b"socket")
        # hook_address_socket = tst_pydbg.func_resolve_experimental(u"C:\\Windows\\System32\\ws2_32.dll", b"socket")
        #
        # This is a x64 library:
        #
        # hook_address_socket = tst_pydbg.func_resolve_experimental(u"C:\\Windows\\System32\\ws2_32.dll", b"WSAStringToAddressA")
        hook_address_socket = tst_pydbg.func_resolve_experimental(u"ws2_32.dll", b"WSAStringToAddressA")

        # The specified module could not be found
        # hook_address_socket = tst_pydbg.func_resolve("ws2_32.dll", b"WSAStringToAddressA")
        #
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

        tst_pydbg = create_pydbg()

        dir_path = os.path.dirname(__file__)
        sys.path.append(dir_path)

        temp_file_name = "tmp.txt"
        python_command = 'import time;time.sleep(5.0);f=open(u"%s", "w");f.close()' % temp_file_name
        creation_file_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
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
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_create_file_entry file_name=", file_name)
            self.assertTrue(file_name == temp_file_name)
            return defines.DBG_CONTINUE

        def callback_create_file_exit(object_pydbg, args, function_result):
            file_name = object_pydbg.get_wstring(args[0])
            print("callback_create_file_exit file_name=", file_name)
            self.assertTrue(file_name == temp_file_name)
            return pydbg.defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address_create_file_w,
            10,
            callback_create_file_entry,
            callback_create_file_exit)

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


    @unittest.skipIf(is_travis_machine(), "Does not work on Travis.")
    def test_pydbg_Python_socket(self):
        import pydbg
        from pydbg import defines
        from pydbg import utils

        tst_pydbg = create_pydbg()

        dir_path = os.path.dirname(__file__)
        sys.path.append(dir_path)

        python_command = "import time;time.sleep(2.0);"
        python_command += "import urllib2;response = urllib2.urlopen('http://python.org/');html = response.read();print(html)"
        url_process = subprocess.Popen(
            [sys.executable, '-c', python_command],
            stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)

        print("creation_file_process ", url_process.pid)
        sys.stdout.flush()

        # A bit of delay so the process can start.
        time.sleep(0.5)

        print("Root pid=%d" % root_process_id)
        print("Attaching to pid=%d" % url_process.pid)
        tst_pydbg.attach(url_process.pid)

        object_hooks = pydbg.utils.hook_container()

        # "C:\Windows\System32\ws2_32.dll"
        # Windows Socket 2.0 32-Bit DLL
        # Dump of file C:\Windows\System32\ws2_32.dll
        #             8664 machine (x64)

        # "C:\Windows\System32\kernel32.dll"
        # Windows NT BASE API Client DLL

        # Same error messages with these functions:
        # "Only part of a ReadProcessMemory or WriteProcessMemory request was completed"
        # socket, WSAConnectByNameA, WSAConnectByNameW, WSAStringToAddressA
        # hook_address_socket = tst_pydbg.func_resolve_experimental(u"Ws2_32.dll", b"socket")
        # hook_address_socket = tst_pydbg.func_resolve_experimental(u"C:\\Windows\\System32\\ws2_32.dll", b"socket")
        #
        # This is a x64 library:
        #
        # hook_address_socket = tst_pydbg.func_resolve_experimental(u"C:\\Windows\\System32\\ws2_32.dll", b"WSAStringToAddressA")
        # hook_address = tst_pydbg.func_resolve_experimental(u"kernel32.dll", b"CreateProcessW")
        hook_address = tst_pydbg.func_resolve_experimental(u"ws2_32.dll", b"WSAStringToAddressA")

        # The specified module could not be found
        # hook_address_socket = tst_pydbg.func_resolve("ws2_32.dll", b"WSAStringToAddressA")
        #
        assert hook_address
        print("hook_address_socket=%016x" % hook_address)


        # 0x0000000076eb0000  0x11f000  C:\windows\system32\kernel32.dll
        # CreateProcessW=0000000076ed05e0 OK
        print("CreateProcessW=%016x" % tst_pydbg.func_resolve_experimental(u"kernel32.dll", b"CreateProcessW"))

        # 0x00000000ff0e0000  0x4d000   C:\windows\system32\WS2_32.dll
        # WSAStringToAddressA             =000007feff109360 Broken.
        print("WSAStringToAddressA=%016x" % tst_pydbg.func_resolve_experimental(u"ws2_32.dll", b"WSAStringToAddressA"))
        # socket                          =000007feff0ed910
        print("socket=%016x" % tst_pydbg.func_resolve_experimental(u"ws2_32.dll", b"socket"))

        # ws2_32 are not correct.

        # WHY 7fe ????? Is it always the same value ?
        # Is this the address in the debugged process???
        # Maybe using func_resolve_debuggee ?
        # Try with other DLLs ?
        # Try masking the address ?



        tst_pydbg.count_entry = 0
        tst_pydbg.count_exit = 0

        def callback_entry(object_pydbg, args):
            object_pydbg.count_entry += 1
            print("callback_entry args=", args)
            return defines.DBG_CONTINUE

        def callback_exit(object_pydbg, args, function_result):
            object_pydbg.count_exit += 1
            print("callback_exit args=", args, function_result)

            is_invalid_handle = function_result % (1 + defines.INVALID_HANDLE_VALUE) == defines.INVALID_HANDLE_VALUE
            self.assertTrue(is_invalid_handle)
            return defines.DBG_CONTINUE

        object_hooks.add(
            tst_pydbg,
            hook_address,
            3,
            callback_entry,
            callback_exit)

        tst_pydbg.run()

        print("END", tst_pydbg.count_entry, tst_pydbg.count_exit)
        # The first call might be missed.



if __name__ == '__main__':
    unittest.main()
