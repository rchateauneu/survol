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
import six
import pydbg
from pydbg import defines
from pydbg import windows_h

################################################################################

class Win32Hook_BaseClass(object):
    object_pydbg = None
    object_hooks = None
    callback_create_call = None
    callback_create_object = None

    # The style tells if this is a native call or an aggregate of function
    # calls, made with some style: Factorization etc...
    def __init__(self):
        self.m_core = "Something"

    # The API signature is taken "as is" from Microsoft web site.
    @staticmethod
    def _parse_text_definition(the_class):
        match_one = re.match("\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*\((.*)\)\s*;", the_class.api_definition, re.DOTALL)
        the_class.return_type = match_one.group(1)
        the_class.function_name = match_one.group(2)

        # '\nHANDLE hFile,\nLPCVOID lpBuffer,\nDWORD nNumberOfBytesToWrite,\nLPDWORD lpNumberOfBytesWritten,\nLPOVERLAPPED lpOverlapped\n'
        the_class.args_list = []
        for one_arg_pair in match_one.group(3).split(","):
            match_pair = re.match("\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*", one_arg_pair)
            the_class.args_list.append((match_pair.group(1), match_pair.group(2)))

        assert isinstance(the_class.function_name, six.binary_type )
        the_class.hook_address = Win32Hook_BaseClass.object_pydbg.func_resolve(b"kernel32.dll", the_class.function_name)
        assert the_class.hook_address

    #subclass_dict = {}

    def set_arguments(self, args, function_result):
        self.m_parsedArgs = args
        self.m_retValue = function_result

    @classmethod
    def add_subclass(the_class, the_subclass):
        Win32Hook_BaseClass._parse_text_definition(the_subclass)
        #Win32Hook_BaseClass.subclass_dict[the_subclass.function_name] = the_subclass

        #def hook_function_adapter_entry(object_pydbg, args):
        #    return defines.DBG_CONTINUE

        def hook_function_adapter_exit(object_pydbg, args, function_result):
            subclass_instance = the_subclass()
            subclass_instance.set_arguments(args, function_result)
            subclass_instance.process_arguments()
            Win32Hook_BaseClass.callback_create_call(subclass_instance)
            return defines.DBG_CONTINUE

        Win32Hook_BaseClass.object_hooks.add(
            Win32Hook_BaseClass.object_pydbg,
            the_subclass.hook_address,
            len(the_subclass.args_list),
            None,
            hook_function_adapter_exit)

    def report_cim_object(self, cim_class_name, **cim_arguments):
        print("report_cim_object", self.__class__.__name__, cim_class_name, cim_arguments)
        self.callback_create_object(cim_class_name, cim_arguments)


class Win32Hook_CreateProcessA(Win32Hook_BaseClass):
    api_definition = """
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
        );"""

    def process_arguments(self):
        lpApplicationName = Win32Hook_BaseClass.object_pydbg.get_string(self.m_parsedArgs[0])
        lpCommandLine = Win32Hook_BaseClass.object_pydbg.get_string(self.m_parsedArgs[1])
        lpProcessInformation = self.m_parsedArgs[9]

        # _PROCESS_INFORMATION {
        #   HANDLE hProcess;
        #   HANDLE hThread;
        #   DWORD  dwProcessId;
        #   DWORD  dwThreadId;
        # }
        offset_dwProcessId = windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.HANDLE)
        dwProcessId = Win32Hook_BaseClass.object_pydbg.get_long(lpProcessInformation + offset_dwProcessId)

        print("Win32Hook_CreateProcessA m_parsedArgs=", self.m_parsedArgs)
        print("Win32Hook_CreateProcessA m_retValue=", self.m_retValue)
        print("Win32Hook_CreateProcessA Handle=", dwProcessId)
        self.callback_create_object("CIM_Process", Handle=dwProcessId)


class Win32Hook_CreateProcessAsUserA(Win32Hook_BaseClass):
    api_definition = """
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
        );"""

class Win32Hook_CreateProcessAsUserW(Win32Hook_BaseClass):
    api_definition = """
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
        );"""

class Win32Hook_CreateProcessW(Win32Hook_BaseClass):
    api_definition = """
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
        );"""

class Win32Hook_ExitProcess(Win32Hook_BaseClass):
    api_definition = """
        void ExitProcess(
            UINT uExitCode
        );"""

class Win32Hook_CreateThread(Win32Hook_BaseClass):
    api_definition = """
        HANDLE CreateThread(
            LPSECURITY_ATTRIBUTES   lpThreadAttributes,
            SIZE_T                  dwStackSize,
            LPTHREAD_START_ROUTINE  lpStartAddress,
            __drv_aliasesMem LPVOID lpParameter,
            DWORD                   dwCreationFlags,
            LPDWORD                 lpThreadId
        );"""

class Win32Hook_CreateRemoteThread(Win32Hook_BaseClass):
    api_definition = """
        HANDLE CreateRemoteThread(
            HANDLE                 hProcess,
            LPSECURITY_ATTRIBUTES  lpThreadAttributes,
            SIZE_T                 dwStackSize,
            LPTHREAD_START_ROUTINE lpStartAddress,
            LPVOID                 lpParameter,
            DWORD                  dwCreationFlags,
            LPDWORD                lpThreadId
        );"""

class Win32Hook_CreateRemoteThreadEx(Win32Hook_BaseClass):
    api_definition = """
        HANDLE CreateRemoteThreadEx(
            HANDLE                       hProcess,
            LPSECURITY_ATTRIBUTES        lpThreadAttributes,
            SIZE_T                       dwStackSize,
            LPTHREAD_START_ROUTINE       lpStartAddress,
            LPVOID                       lpParameter,
            DWORD                        dwCreationFlags,
            LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
            LPDWORD                      lpThreadId
        );"""

class Win32Hook_TerminateProcess(Win32Hook_BaseClass):
    api_definition = """
            BOOL TerminateProcess(
                HANDLE hProcess,
                UINT   uExitCode
            );"""

class Win32Hook_TerminateThread(Win32Hook_BaseClass):
    api_definition = """
        BOOL TerminateThread(
            HANDLE hThread,
            DWORD  dwExitCode
        );"""

class Win32Hook_CreateDirectoryA(Win32Hook_BaseClass):
    api_definition = """
        BOOL CreateDirectoryA(
            LPCWSTR               lpPathName,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes
        );"""

class Win32Hook_CreateDirectoryW(Win32Hook_BaseClass):
    api_definition = """
        BOOL CreateDirectoryW(
            LPCWSTR               lpPathName,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes
        );"""

class Win32Hook_RemoveDirectoryA(Win32Hook_BaseClass):
    api_definition = """
        BOOL RemoveDirectoryA(
            LPCSTR lpPathName
        );"""
    def process_arguments(self):
        print("hook_function_RemoveDirectoryA args=", self.m_parsedArgs)
        dirname = Win32Hook_BaseClass.object_pydbg.get_string(self.m_parsedArgs[0])
        print("hook_function_RemoveDirectoryA dirname=", dirname)
        self.callback_create_object("CIM_Directory", Name=dirname)

class Win32Hook_RemoveDirectoryW(Win32Hook_BaseClass):
    api_definition = """
        BOOL RemoveDirectoryW(
            LPCWSTR lpPathName
        );"""
    def process_arguments(self):
        print("hook_function_RemoveDirectoryW args=", self.m_parsedArgs)
        dirname = Win32Hook_BaseClass.object_pydbg.get_wstring(self.m_parsedArgs[0])
        print("hook_function_RemoveDirectoryW dirname=", dirname)
        self.callback_create_object("CIM_Directory", Name=dirname)

class Win32Hook_CreateFileA(Win32Hook_BaseClass):
    api_definition = """
        HANDLE CreateFileA(
            LPCSTR                lpFileName,
            DWORD                 dwDesiredAccess,
            DWORD                 dwShareMode,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            DWORD                 dwCreationDisposition,
            DWORD                 dwFlagsAndAttributes,
            HANDLE                hTemplateFile
        );"""
    def process_arguments(self):
        dirname = Win32Hook_BaseClass.object_pydbg.get_string(self.m_parsedArgs[0])
        self.callback_create_object("CIM_DataFile", Name=dirname)

class Win32Hook_CreateFileW(Win32Hook_BaseClass):
    api_definition = """
        HANDLE CreateFileW(
            LPCWSTR               lpFileName,
            DWORD                 dwDesiredAccess,
            DWORD                 dwShareMode,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            DWORD                 dwCreationDisposition,
            DWORD                 dwFlagsAndAttributes,
            HANDLE                hTemplateFile
        );"""
    def process_arguments(self):
        dirname = Win32Hook_BaseClass.object_pydbg.get_string(self.m_parsedArgs[0])
        self.callback_create_object("CIM_DataFile", Name=dirname)

class Win32Hook_CreateFile2(Win32Hook_BaseClass):
    api_definition = """
        HANDLE CreateFile2(
            LPCWSTR                           lpFileName,
            DWORD                             dwDesiredAccess,
            DWORD                             dwShareMode,
            DWORD                             dwCreationDisposition,
            LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams
        );"""

class Win32Hook_DeleteFileA(Win32Hook_BaseClass):
    api_definition = """
        BOOL DeleteFileA(
            LPCSTR lpFileName
        );"""

class Win32Hook_DeleteFileW(Win32Hook_BaseClass):
    api_definition = """
        BOOL DeleteFileW(
            LPCWSTR lpFileName
        );"""

class Win32Hook_WriteFile(Win32Hook_BaseClass):
    api_definition = """
        BOOL WriteFile(
            HANDLE       hFile,
            LPCVOID      lpBuffer,
            DWORD        nNumberOfBytesToWrite,
            LPDWORD      lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped
        );"""
    def process_arguments(self):
        print("hook_function_WriteFile args=", self.m_parsedArgs)

        lpBuffer = self.m_parsedArgs[1]
        nNumberOfBytesToWrite = self.m_parsedArgs[2]
        # print("lpBuffer=", lpBuffer, "nNumberOfBytesToWrite=", nNumberOfBytesToWrite)
        buffer = Win32Hook_BaseClass.object_pydbg.get_string_size(lpBuffer, nNumberOfBytesToWrite)
        print("Buffer=", buffer)


class Win32Hook_WriteFileEx(Win32Hook_BaseClass):
    api_definition = """
        BOOL WriteFileEx(
            HANDLE                          hFile,
            LPCVOID                         lpBuffer,
            DWORD                           nNumberOfBytesToWrite,
            LPOVERLAPPED                    lpOverlapped,
            LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );"""

class Win32Hook_WriteFileGather(Win32Hook_BaseClass):
    api_definition = """
        BOOL WriteFileGather(
            HANDLE                  hFile,
            FILE_SEGMENT_ELEMENT [] aSegmentArray,
            DWORD                   nNumberOfBytesToWrite,
            LPDWORD                 lpReserved,
            LPOVERLAPPED            lpOverlapped
        );"""

class Win32Hook_ReadFile(Win32Hook_BaseClass):
    api_definition = """
        BOOL ReadFile(
            HANDLE       hFile,
            LPVOID       lpBuffer,
            DWORD        nNumberOfBytesToRead,
            LPDWORD      lpNumberOfBytesRead,
            LPOVERLAPPED lpOverlapped
        );"""

class Win32Hook_ReadFileEx(Win32Hook_BaseClass):
    api_definition = """
        BOOL ReadFileEx(
            HANDLE                          hFile,
            LPVOID                          lpBuffer,
            DWORD                           nNumberOfBytesToRead,
            LPOVERLAPPED                    lpOverlapped,
            LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );"""

class Win32Hook_ReadFileScatter(Win32Hook_BaseClass):
    api_definition = """
        BOOL ReadFileScatter(
            HANDLE                  hFile,
            FILE_SEGMENT_ELEMENT [] aSegmentArray,
            DWORD                   nNumberOfBytesToRead,
            LPDWORD                 lpReserved,
            LPOVERLAPPED            lpOverlapped
        );"""
