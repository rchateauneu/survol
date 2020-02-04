"""
The intention is to port a subset of pydbg:
- It must be in pure Python.
- Python 2 and 3.
- Needed features: attach to a process, log calls to some system api funcitons,
with the arguments.

It would have been possible to fork pydbg but:
- This project is not maintained, not is OpenRCE http://www.openrce.org/ of which it is part.
- Not all features are needed
- Features which are unneeded are quite dangerous and it might be impossible to install
the package because of this reason.

Hence the choice of porting a ubset of pydbg
"""

from __future__ import print_function

import sys
import six
import platform
import os
import time
import multiprocessing

sys.path.append(".")
sys.path.append("pydbg")

import pydbg
from pydbg import pydbg
from pydbg import defines
import pydbg.tests.utils

class HookManager:
    def __init__(self):
        self.hooks = pydbg.tests.utils.hook_container()

    def define_function(self, api_definition):
        return
        function_name = b"WriteFile"
        hook_address = tst_pydbg.func_resolve(b"kernel32.dll", function_name)
        assert hook_address

        def hook_function():
            pass
        self.hooks.add(tst_pydbg, hook_address, 5, hook_function, None)


hooks_manager = HookManager()

hooks_manager.define_function("""
BOOL WriteFile(
HANDLE       hFile,
LPCVOID      lpBuffer,
DWORD        nNumberOfBytesToWrite,
LPDWORD      lpNumberOfBytesWritten,
LPOVERLAPPED lpOverlapped
);""")
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
BOOL RemoveDirectoryA(
  LPCSTR lpPathName
);""")
hooks_manager.define_function("""
BOOL RemoveDirectoryW(
  LPCWSTR lpPathName
);""")
hooks_manager.define_function("""
HANDLE CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);""")
hooks_manager.define_function("""
HANDLE CreateFileW(
  LPCWSTR               lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
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

def hook_function_WriteFile(dbg, args):
    print("hook_function_WriteFile args=", args)
    big_val = dbg.read_process_memory(dbg.context.Rsp, 48)
    assert isinstance(big_val, six.binary_type)
    print("hook_function_WriteFile big_val=", ''.join('{:02x}'.format(ord(x)) for x in big_val))
    return defines.DBG_CONTINUE

def hook_function_RemoveDirectoryA(dbg, args ):
    print("hook_function_RemoveDirectoryA args=", args)
    big_val = dbg.read_process_memory(dbg.context.Rsp, 16)
    assert isinstance(big_val, six.binary_type)
    print("hook_function_RemoveDirectoryA big_val=", ''.join('{:02x}'.format(ord(x)) for x in big_val))
    return defines.DBG_CONTINUE

def hook_function_RemoveDirectoryW(dbg, args ):
    print("hook_function_RemoveDirectoryW args=", args)
    big_val = dbg.read_process_memory(dbg.context.Rsp, 16)
    assert isinstance(big_val, six.binary_type)
    print("hook_function_RemoveDirectoryW big_val=", ''.join('{:02x}'.format(ord(x)) for x in big_val))
    return defines.DBG_CONTINUE


def processing_function(one_argument):
    print('processing_function START.')
    while True:
        print('Subprocess hello. Sleeping ', one_argument)
        time.sleep(one_argument)
        #continue
        try:
            os.rmdir("Tralala")
        except:
            pass

if __name__ == '__main__':
    architecture = platform.architecture()
    print("Architecture:", architecture)
    assert architecture[0] == '64bit'

    sleep_time = 3.0
    created_process = multiprocessing.Process(target=processing_function, args=(sleep_time,))
    created_process.start()
    print("created_process=", created_process.pid)

    time.sleep(1)

    if sys.version_info < (3,):
        tst_pydbg = pydbg.pydbg()
    elif sys.version_info < (3, 7):
        tst_pydbg = pydbg
    else:
        tst_pydbg = pydbg.pydbg.pydbg()
    time.sleep(1.0)

    print("getpid=", os.getpid())
    print("Attaching")
    tst_pydbg.attach(created_process.pid)

    hooks = pydbg.tests.utils.hook_container()
    hook_address_WriteFile = tst_pydbg.func_resolve(b"kernel32.dll", b"WriteFile")
    assert hook_address_WriteFile
    hooks.add(tst_pydbg, hook_address_WriteFile, 5, hook_function_WriteFile, None)

    hook_address_RemoveDirectoryA = tst_pydbg.func_resolve(b"kernel32.dll", b"RemoveDirectoryA")
    assert hook_address_RemoveDirectoryA
    hooks.add(tst_pydbg, hook_address_RemoveDirectoryA, 1, hook_function_RemoveDirectoryA, None)

    hook_address_RemoveDirectoryW = tst_pydbg.func_resolve(b"kernel32.dll", b"RemoveDirectoryW")
    assert hook_address_RemoveDirectoryW
    hooks.add(tst_pydbg, hook_address_RemoveDirectoryW, 1, hook_function_RemoveDirectoryW, None)

    tst_pydbg.run()

    time.sleep(10.0)
    print("Detaching")
    tst_pydbg.detach()
    created_process.join()
    time.sleep(2.0)
    print("Finished")
