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

import struct


def get_string(dbg, address):
    buffer  = b""
    offset  = 0
    while 1:
        byte = dbg.read_process_memory(address + offset, 1 )
        if byte != b"\x00":
            buffer  += byte
            offset  += 1
            continue
        else:
            break
    return buffer

def get_long(dbg, address):
    ret_bytes = dbg.read_process_memory(address, 4)
    assert len(ret_bytes) == 4
    assert isinstance(ret_bytes, six.binary_type)
    return long(struct.unpack("<L", ret_bytes)[0])

def get_longlong(dbg, address):
    ret_bytes = dbg.read_process_memory(address, 8)
    assert len(ret_bytes) == 8
    assert isinstance(ret_bytes, six.binary_type)
    return long(struct.unpack("<Q", ret_bytes)[0])


def hook_function_WriteFile(dbg, args):
    print("hook_function_WriteFile args=", args)

    address_start = dbg.context.Rsp + 8
    hFile = get_longlong(dbg, address_start)
    lpBuffer = get_longlong(dbg, address_start+8)
    nNumberOfBytesToWrite = get_long(dbg, address_start+8+8)
    lpNumberOfBytesWritten = get_longlong(dbg, address_start+8+8+4)
    lpOverlapped = get_longlong(dbg, address_start+8+8+4+8)
    print("Args=", hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)


    big_val = dbg.read_process_memory(dbg.context.Rsp, 48)
    assert isinstance(big_val, six.binary_type)
    print("hook_function_WriteFile big_val=", ''.join('{:02x}'.format(ord(x)) for x in big_val))
    return defines.DBG_CONTINUE

def hook_function_RemoveDirectoryA(dbg, args ):
    print("hook_function_RemoveDirectoryA args=", args)
    dirname = get_string(dbg, args[0])
    print("hook_function_RemoveDirectoryA dirname=", dirname)
    return defines.DBG_CONTINUE

def hook_function_RemoveDirectoryW(dbg, args ):
    print("hook_function_RemoveDirectoryW args=", args)
    dirname = get_string(dbg, args[0])
    print("hook_function_RemoveDirectoryW dirname=", dirname)
    return defines.DBG_CONTINUE

def hook_function_MulDiv(dbg, args ):
    print("hook_function_MulDiv args=", args)
    assert args[0] == 20
    assert args[1] == 30
    assert args[2] == 6
    big_val = dbg.read_process_memory(dbg.context.Rsp, 16)
    assert isinstance(big_val, six.binary_type)
    print("hook_function_MulDiv big_val=", ''.join('{:02x}'.format(ord(x)) for x in big_val))
    return defines.DBG_CONTINUE


# DWORD GetEnvironmentVariable(
#   LPCTSTR lpName,
#   LPTSTR  lpBuffer,
#   DWORD   nSize
# );
def hook_function_GetEnvironmentVariableW(dbg, args ):
    print("hook_function_GetEnvironmentVariableW args=", args)
    big_val = dbg.read_process_memory(dbg.context.Rsp, 16)
    assert isinstance(big_val, six.binary_type)
    print("hook_function_GetEnvironmentVariableW big_val=", ''.join('{:02x}'.format(ord(x)) for x in big_val))
    return defines.DBG_CONTINUE

def processing_function(one_argument):
    print('processing_function START.')
    while True:
        print('Subprocess hello. Sleeping ', one_argument)
        time.sleep(one_argument)
        try:
            if False:
                os.rmdir(six.b("NonExistentDirBinary")) # RemoveDirectoryA
                os.rmdir(six.u("NonExistentDirUnicode")) # RemoveDirectoryW
            else:
                ctypes.windll.kernel32.RemoveDirectoryA(six.b("NonExistentDirBinary"))
                ctypes.windll.kernel32.RemoveDirectoryW(six.u("NonExistentDirUnicode"))
        except:
            pass

        resu = ctypes.windll.kernel32.MulDiv(20, 30, 6)
        assert resu == 100
        print("resu=%d" % resu)


import ctypes

if __name__ == '__main__':
    architecture = platform.architecture()
    print("Architecture:", architecture)
    assert architecture[0] == '64bit'

    print("ctypes.windll.kernel32.MulDiv.argtypes=", ctypes.windll.kernel32.MulDiv.argtypes) # None
    resu = ctypes.windll.kernel32.MulDiv(20, 30, 6)
    assert resu == 100

    buflen = 200
    read_buf = ctypes.create_string_buffer(buflen)
    expected_environment_value = os.environ["USERNAME"]
    resu = ctypes.windll.kernel32.GetEnvironmentVariableA(b"USERNAME", read_buf, ctypes.c_size_t(buflen))
    print("resu=", resu, expected_environment_value)
    assert resu == len(expected_environment_value)
    print("read_buf.raw=", read_buf.raw)
    assert len(read_buf.raw) == buflen
    assert read_buf.raw[:resu] == expected_environment_value
    print("read_buf.value=", read_buf.value)
    assert read_buf.value == expected_environment_value

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

    print("RemoveDirectoryA=", ctypes.windll.kernel32.RemoveDirectoryA)
    print("RemoveDirectoryW=", ctypes.windll.kernel32.RemoveDirectoryW)

    hook_address_RemoveDirectoryA = tst_pydbg.func_resolve(b"kernel32.dll", b"RemoveDirectoryA")
    assert hook_address_RemoveDirectoryA
    hooks.add(tst_pydbg, hook_address_RemoveDirectoryA, 1, hook_function_RemoveDirectoryA, None)

    hook_address_RemoveDirectoryW = tst_pydbg.func_resolve(b"kernel32.dll", b"RemoveDirectoryW")
    assert hook_address_RemoveDirectoryW
    hooks.add(tst_pydbg, hook_address_RemoveDirectoryW, 1, hook_function_RemoveDirectoryW, None)

    hook_address_MulDiv = tst_pydbg.func_resolve(b"kernel32.dll", b"MulDiv")
    assert hook_address_MulDiv
    hooks.add(tst_pydbg, hook_address_MulDiv, 3, hook_function_MulDiv, None)

    hook_address_GetEnvironmentVariableW = tst_pydbg.func_resolve(b"kernel32.dll", b"GetEnvironmentVariableW")
    assert hook_address_GetEnvironmentVariableW
    hooks.add(tst_pydbg, hook_address_GetEnvironmentVariableW, 1, hook_function_GetEnvironmentVariableW, None)

    tst_pydbg.run()

    time.sleep(10.0)
    print("Detaching")
    tst_pydbg.detach()
    created_process.join()
    time.sleep(2.0)
    print("Finished")
