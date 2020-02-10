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

if False:

    hooks_manager.define_function("""
    BOOL WriteFileEx(
    "HANDLE                          hFile,
    "LPCVOID                         lpBuffer,
    "DWORD                           nNumberOfBytesToWrite,
    "LPOVERLAPPED                    lpOverlapped,
    "LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    );""")
    hooks_manager.define_function("""
    BOOL WriteFileGather(
      HANDLE                  hFile,
      FILE_SEGMENT_ELEMENT [] aSegmentArray,
      DWORD                   nNumberOfBytesToWrite,
      LPDWORD                 lpReserved,
      LPOVERLAPPED            lpOverlapped
    );""")
    hooks_manager.define_function("""
    BOOL ReadFile(
      HANDLE       hFile,
      LPVOID       lpBuffer,
      DWORD        nNumberOfBytesToRead,
      LPDWORD      lpNumberOfBytesRead,
      LPOVERLAPPED lpOverlapped
    );""")
    hooks_manager.define_function("""
    BOOL ReadFileEx(
      HANDLE                          hFile,
      LPVOID                          lpBuffer,
      DWORD                           nNumberOfBytesToRead,
      LPOVERLAPPED                    lpOverlapped,
      LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    );""")
    hooks_manager.define_function("""
    BOOL ReadFileScatter(
      HANDLE                  hFile,
      FILE_SEGMENT_ELEMENT [] aSegmentArray,
      DWORD                   nNumberOfBytesToRead,
      LPDWORD                 lpReserved,
      LPOVERLAPPED            lpOverlapped
    );""")
    hooks_manager.define_function("""
    BOOL CreateDirectoryA(
      LPCSTR                lpPathName,
      LPSECURITY_ATTRIBUTES lpSecurityAttributes
    );""")
    hooks_manager.define_function("""
    BOOL DeleteFileA(
      LPCSTR lpFileName
    );""")
    hooks_manager.define_function("""
    BOOL DeleteFileW(
      LPCWSTR lpFileName
    );""")
    hooks_manager.define_function("""
    HANDLE CreateFile2(
      LPCWSTR                           lpFileName,
      DWORD                             dwDesiredAccess,
      DWORD                             dwShareMode,
      DWORD                             dwCreationDisposition,
      LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams
    );""")

################################################################################
class Win32HookBaseClass(object):
    object_pydbg = None
    object_hooks = None

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
        self.hook_address = Win32HookBaseClass.object_pydbg.func_resolve(b"kernel32.dll", self.function_name)
        assert self.hook_address

    def __init__(self, api_definition):
        self._parse_text_definition(api_definition)
        self.hook_address = Win32HookBaseClass.object_pydbg.func_resolve(b"kernel32.dll", self.function_name)
        assert self.hook_address

        def hook_function_adapter(object_pydbg, args):
            self.hook_function_core(args)
            return defines.DBG_CONTINUE

        Win32HookBaseClass.object_hooks.add(Win32HookBaseClass.object_pydbg, self.hook_address, len(self.args_list), hook_function_adapter, None)

    def report_cim_object(self, class_name, **cim_arguments):
        print("report_cim_object", class_name, cim_arguments)

class Win32HookCreateFileA(Win32HookBaseClass):
    def __init__(self):
        super(Win32HookCreateFileA, self).__init__("""
        HANDLE CreateFileA(
            LPCSTR                lpFileName,
            DWORD                 dwDesiredAccess,
            DWORD                 dwShareMode,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes,
            DWORD                 dwCreationDisposition,
            DWORD                 dwFlagsAndAttributes,
            HANDLE                hTemplateFile
        );""")

    def hook_function_core(self, args):
        dirname = Win32HookBaseClass.object_pydbg.get_string(args[0])
        self.report_cim_object("CIM_DataFile", Name=dirname)

class Win32HookCreateFileW(Win32HookBaseClass):
    def __init__(self):
        super(Win32HookCreateFileW, self).__init__("""
        HANDLE CreateFileW(
          LPCWSTR               lpFileName,
          DWORD                 dwDesiredAccess,
          DWORD                 dwShareMode,
          LPSECURITY_ATTRIBUTES lpSecurityAttributes,
          DWORD                 dwCreationDisposition,
          DWORD                 dwFlagsAndAttributes,
          HANDLE                hTemplateFile
        );""")

    def hook_function_core(self, args):
        dirname = Win32HookBaseClass.object_pydbg.get_string(args[0])
        self.report_cim_object("CIM_DataFile", Name=dirname)

class Win32HookWriteFile(Win32HookBaseClass):
    def __init__(self):
        super(Win32HookWriteFile, self).__init__("""
        BOOL WriteFile(
            HANDLE       hFile,
            LPCVOID      lpBuffer,
            DWORD        nNumberOfBytesToWrite,
            LPDWORD      lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped
        );""")

    def hook_function_core(self, args):
        print("hook_function_WriteFile args=", args)

        lpBuffer = args[1]
        nNumberOfBytesToWrite = args[2]
        # print("lpBuffer=", lpBuffer, "nNumberOfBytesToWrite=", nNumberOfBytesToWrite)
        buffer = Win32HookBaseClass.object_pydbg.get_string_size(lpBuffer, nNumberOfBytesToWrite)
        print("Buffer=", buffer)


class Win32HookRemoveDirectoryA(Win32HookBaseClass):
    def __init__(self):
        super(Win32HookRemoveDirectoryA, self).__init__("""
        BOOL RemoveDirectoryA(
            LPCSTR lpPathName
        );""")

    def hook_function_core(self, args):
        print("hook_function_RemoveDirectoryA args=", args)
        dirname = Win32HookBaseClass.object_pydbg.get_string(args[0])
        print("hook_function_RemoveDirectoryA dirname=", dirname)
        assert dirname == b"NonExistentDirBinary"


class Win32HookRemoveDirectoryW(Win32HookBaseClass):
    def __init__(self):
        super(Win32HookRemoveDirectoryW, self).__init__("""
        BOOL RemoveDirectoryW(
            LPCWSTR lpPathName
        );""")

    def hook_function_core(self, args):
        print("hook_function_RemoveDirectoryW args=", args)
        dirname = Win32HookBaseClass.object_pydbg.get_wstring(args[0])
        print("hook_function_RemoveDirectoryW dirname=", dirname)
        assert dirname == b"NonExistentDirUnicode"


class Win32HookMulDiv(Win32HookBaseClass):
    def __init__(self):
        super(Win32HookMulDiv, self).__init__("""
        int MulDiv(
            int nNumber,
            int nNumerator,
            int nDenominator 
        );""")

    def hook_function_core(self, args):
        print("hook_function_MulDiv args=", args)
        assert args[0] == 20
        assert args[1] == 30
        assert args[2] == 6

