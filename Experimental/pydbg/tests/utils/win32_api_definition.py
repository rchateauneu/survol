from __future__ import print_function

__author__      = "Remi Chateauneu"
__copyright__   = "Primhill Computers, 2018-2020"
__credits__ = ["","",""]
__license__ = "GPL"
__version__ = "0.0.1"
__maintainer__ = "Remi Chateauneu"
__email__ = "contact@primhillcomputers.com"
__status__ = "Development"

import re
import pydbg
from pydbg import defines

################################################################################
class Win32Hook_BaseClass(object):
    object_pydbg = None
    object_hooks = None
    object_report_callback = None

    # The API signature is taken "as is" from Microsoft web site.
    def _parse_text_definition(self, api_definition):
        match_one = re.match("\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*\((.*)\)\s*;", api_definition, re.DOTALL)
        self.return_type = match_one.group(1)
        self.function_name = match_one.group(2)

        # '\nHANDLE hFile,\nLPCVOID lpBuffer,\nDWORD nNumberOfBytesToWrite,\nLPDWORD lpNumberOfBytesWritten,\nLPOVERLAPPED lpOverlapped\n'
        self.args_list = []
        for one_arg_pair in match_one.group(3).split(","):
            match_pair = re.match("\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*", one_arg_pair)
            self.args_list.append((match_pair.group(1), match_pair.group(2)))

        # function_name = b"WriteFile"
        self.hook_address = Win32Hook_BaseClass.object_pydbg.func_resolve(b"kernel32.dll", self.function_name)
        assert self.hook_address

    def __init__(self, api_definition):
        self._parse_text_definition(api_definition)
        self.hook_address = Win32Hook_BaseClass.object_pydbg.func_resolve(b"kernel32.dll", self.function_name)
        assert self.hook_address

        def hook_function_adapter_entry(object_pydbg, args):
            self.hook_function_entry(args)
            return defines.DBG_CONTINUE

        def hook_function_adapter_exit(object_pydbg, args, function_result):
            self.hook_function_exit(args, function_result)
            return defines.DBG_CONTINUE

        Win32Hook_BaseClass.object_hooks.add(
            Win32Hook_BaseClass.object_pydbg,
            self.hook_address,
            len(self.args_list),
            hook_function_adapter_entry,
            hook_function_adapter_exit)

    def report_cim_object(self, cim_class_name, **cim_arguments):
        print("report_cim_object", self.__class__.__name__, cim_class_name, cim_arguments)
        self.object_report_callback(cim_class_name, cim_arguments)

    def hook_function_entry(self, args):
        print("hook_function_entry", self.__class__.__name__, args)

    def hook_function_exit(self, args, function_result):
        print("hook_function_exit", self.__class__.__name__, args, function_result)



class Win32Hook_CreateProcessA(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateProcessA, self).__init__("""
        BOOL CreateProcessA(
            LPCSTR                lpApplicationName,
            LPSTR                 lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL                  bInheritHandles,
            DWORD                 dwCreationFlags,
            LPVOID                lpEnvironment,
            LPCSTR                lpCurrentDirectory,
            LPSTARTUPINFOA        lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation
        );""")

class Win32Hook_CreateProcessAsUserA(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateProcessAsUserA, self).__init__("""
        BOOL CreateProcessAsUserA(
            HANDLE                hToken,
            LPCSTR                lpApplicationName,
            LPSTR                 lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL                  bInheritHandles,
            DWORD                 dwCreationFlags,
            LPVOID                lpEnvironment,
            LPCSTR                lpCurrentDirectory,
            LPSTARTUPINFOA        lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation
        );""")

class Win32Hook_CreateProcessAsUserW(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateProcessAsUserW, self).__init__("""
        BOOL CreateProcessAsUserW(
            HANDLE                hToken,
            LPCWSTR               lpApplicationName,
            LPWSTR                lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL                  bInheritHandles,
            DWORD                 dwCreationFlags,
            LPVOID                lpEnvironment,
            LPCWSTR               lpCurrentDirectory,
            LPSTARTUPINFOW        lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation
        );""")

class Win32Hook_CreateProcessW(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateProcessW, self).__init__("""
        BOOL CreateProcessW(
            LPCWSTR               lpApplicationName,
            LPWSTR                lpCommandLine,
            LPSECURITY_ATTRIBUTES lpProcessAttributes,
            LPSECURITY_ATTRIBUTES lpThreadAttributes,
            BOOL                  bInheritHandles,
            DWORD                 dwCreationFlags,
            LPVOID                lpEnvironment,
            LPCWSTR               lpCurrentDirectory,
            LPSTARTUPINFOW        lpStartupInfo,
            LPPROCESS_INFORMATION lpProcessInformation
        );""")

class Win32Hook_ExitProcess(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_ExitProcess, self).__init__("""
        void ExitProcess(
            UINT uExitCode
        );""")

class Win32Hook_CreateThread(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateThread, self).__init__("""
        HANDLE CreateThread(
            LPSECURITY_ATTRIBUTES   lpThreadAttributes,
            SIZE_T                  dwStackSize,
            LPTHREAD_START_ROUTINE  lpStartAddress,
            __drv_aliasesMem LPVOID lpParameter,
            DWORD                   dwCreationFlags,
            LPDWORD                 lpThreadId
        );""")

class Win32Hook_CreateRemoteThread(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateRemoteThread, self).__init__("""
        HANDLE CreateRemoteThread(
            HANDLE                 hProcess,
            LPSECURITY_ATTRIBUTES  lpThreadAttributes,
            SIZE_T                 dwStackSize,
            LPTHREAD_START_ROUTINE lpStartAddress,
            LPVOID                 lpParameter,
            DWORD                  dwCreationFlags,
            LPDWORD                lpThreadId
        );""")

class Win32Hook_CreateRemoteThreadEx(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateRemoteThreadEx, self).__init__("""
        HANDLE CreateRemoteThreadEx(
            HANDLE                       hProcess,
            LPSECURITY_ATTRIBUTES        lpThreadAttributes,
            SIZE_T                       dwStackSize,
            LPTHREAD_START_ROUTINE       lpStartAddress,
            LPVOID                       lpParameter,
            DWORD                        dwCreationFlags,
            LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
            LPDWORD                      lpThreadId
        );""")

class Win32Hook_TerminateProcess(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_TerminateProcess, self).__init__("""
        BOOL TerminateProcess(
            HANDLE hProcess,
            UINT   uExitCode
        );""")

class Win32Hook_TerminateThread(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_TerminateThread, self).__init__("""
        BOOL TerminateThread(
            HANDLE hThread,
            DWORD  dwExitCode
        );""")

class Win32Hook_CreateDirectoryA(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateDirectoryA, self).__init__("""
        BOOL CreateDirectoryA(
            LPCWSTR               lpPathName,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes
        );""")

class Win32Hook_CreateDirectoryW(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateDirectoryW, self).__init__("""
        BOOL CreateDirectoryW(
            LPCWSTR               lpPathName,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes
        );""")

class Win32Hook_RemoveDirectoryA(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_RemoveDirectoryA, self).__init__("""
        BOOL RemoveDirectoryA(
            LPCSTR lpPathName
        );""")

    def hook_function_entry(self, args):
        print("hook_function_RemoveDirectoryA args=", args)
        dirname = Win32Hook_BaseClass.object_pydbg.get_string(args[0])
        print("hook_function_RemoveDirectoryA dirname=", dirname)
        self.report_cim_object("CIM_Directory", Name=dirname)

class Win32Hook_RemoveDirectoryW(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_RemoveDirectoryW, self).__init__("""
        BOOL RemoveDirectoryW(
            LPCWSTR lpPathName
        );""")

    def hook_function_entry(self, args):
        print("hook_function_RemoveDirectoryW args=", args)
        dirname = Win32Hook_BaseClass.object_pydbg.get_wstring(args[0])
        print("hook_function_RemoveDirectoryW dirname=", dirname)
        self.report_cim_object("CIM_Directory", Name=dirname)

class Win32Hook_CreateFileA(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateFileA, self).__init__("""
        HANDLE CreateFileA(
            LPCSTR                lpFileName,
            DWORD                 dwDesiredAccess,
            DWORD                 dwShareMode,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            DWORD                 dwCreationDisposition,
            DWORD                 dwFlagsAndAttributes,
            HANDLE                hTemplateFile
        );""")

    def hook_function_entry(self, args):
        dirname = Win32Hook_BaseClass.object_pydbg.get_string(args[0])
        self.report_cim_object("CIM_DataFile", Name=dirname)

class Win32Hook_CreateFileW(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateFileW, self).__init__("""
        HANDLE CreateFileW(
            LPCWSTR               lpFileName,
            DWORD                 dwDesiredAccess,
            DWORD                 dwShareMode,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            DWORD                 dwCreationDisposition,
            DWORD                 dwFlagsAndAttributes,
            HANDLE                hTemplateFile
        );""")

    def hook_function_entry(self, args):
        dirname = Win32Hook_BaseClass.object_pydbg.get_string(args[0])
        self.report_cim_object("CIM_DataFile", Name=dirname)

class Win32Hook_CreateFile2(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_CreateFile2, self).__init__("""
        HANDLE CreateFile2(
            LPCWSTR                           lpFileName,
            DWORD                             dwDesiredAccess,
            DWORD                             dwShareMode,
            DWORD                             dwCreationDisposition,
            LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams
        );""")

class Win32Hook_DeleteFileA(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_DeleteFileA, self).__init__("""
        BOOL DeleteFileA(
            LPCSTR lpFileName
        );""")

class Win32Hook_DeleteFileW(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_DeleteFileW, self).__init__("""
        BOOL DeleteFileW(
            LPCWSTR lpFileName
        );""")

class Win32Hook_WriteFile(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_WriteFile, self).__init__("""
        BOOL WriteFile(
            HANDLE       hFile,
            LPCVOID      lpBuffer,
            DWORD        nNumberOfBytesToWrite,
            LPDWORD      lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped
        );""")

    def hook_function_entry(self, args):
        print("hook_function_WriteFile args=", args)

        lpBuffer = args[1]
        nNumberOfBytesToWrite = args[2]
        # print("lpBuffer=", lpBuffer, "nNumberOfBytesToWrite=", nNumberOfBytesToWrite)
        buffer = Win32Hook_BaseClass.object_pydbg.get_string_size(lpBuffer, nNumberOfBytesToWrite)
        print("Buffer=", buffer)


class Win32Hook_WriteFileEx(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_WriteFileEx, self).__init__("""
        BOOL WriteFileEx(
            HANDLE                          hFile,
            LPCVOID                         lpBuffer,
            DWORD                           nNumberOfBytesToWrite,
            LPOVERLAPPED                    lpOverlapped,
            LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );""")

class Win32Hook_WriteFileGather(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_WriteFileGather, self).__init__("""
        BOOL WriteFileGather(
            HANDLE                  hFile,
            FILE_SEGMENT_ELEMENT [] aSegmentArray,
            DWORD                   nNumberOfBytesToWrite,
            LPDWORD                 lpReserved,
            LPOVERLAPPED            lpOverlapped
        );""")

class Win32Hook_ReadFile(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_ReadFile, self).__init__("""
        BOOL ReadFile(
            HANDLE       hFile,
            LPVOID       lpBuffer,
            DWORD        nNumberOfBytesToRead,
            LPDWORD      lpNumberOfBytesRead,
            LPOVERLAPPED lpOverlapped
        );""")

class Win32Hook_ReadFileEx(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_ReadFileEx, self).__init__("""
        BOOL ReadFileEx(
            HANDLE                          hFile,
            LPVOID                          lpBuffer,
            DWORD                           nNumberOfBytesToRead,
            LPOVERLAPPED                    lpOverlapped,
            LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );""")

class Win32Hook_ReadFileScatter(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_ReadFileScatter, self).__init__("""
        BOOL ReadFileScatter(
            HANDLE                  hFile,
            FILE_SEGMENT_ELEMENT [] aSegmentArray,
            DWORD                   nNumberOfBytesToRead,
            LPDWORD                 lpReserved,
            LPOVERLAPPED            lpOverlapped
        );""")


############### JUST FOR TESTING


class Win32Hook_MulDiv(Win32Hook_BaseClass):
    def __init__(self):
        super(Win32Hook_MulDiv, self).__init__("""
        int MulDiv(
            int nNumber,
            int nNumerator,
            int nDenominator 
        );""")

    def hook_function_entry(self, args):
        print("hook_function_MulDiv args=", args)
        assert args[0] == 20
        assert args[1] == 30
        assert args[2] == 6

