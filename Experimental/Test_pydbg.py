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
import ctypes
import re
import os
import time
import multiprocessing

sys.path.append(".")
sys.path.append("pydbg")

import pydbg
from pydbg import pydbg
from pydbg import defines
import pydbg.tests.utils


def hook_function_WriteFile(dbg, args):
    print("hook_function_WriteFile args=", args)

    lpBuffer = args[1]
    nNumberOfBytesToWrite = args[2]
    #print("lpBuffer=", lpBuffer, "nNumberOfBytesToWrite=", nNumberOfBytesToWrite)
    buffer = dbg.get_string_size(lpBuffer, nNumberOfBytesToWrite)
    print("Buffer=", buffer)
    #assert buffer == b"This is a nice message"

    return defines.DBG_CONTINUE

def hook_function_RemoveDirectoryA(dbg, args ):
    print("hook_function_RemoveDirectoryA args=", args)
    dirname = dbg.get_string(args[0])
    print("hook_function_RemoveDirectoryA dirname=", dirname)
    assert dirname == b"NonExistentDirBinary"
    return defines.DBG_CONTINUE

def hook_function_RemoveDirectoryW(dbg, args):
    print("hook_function_RemoveDirectoryW args=", args)
    dirname = dbg.get_wstring(args[0])
    print("hook_function_RemoveDirectoryW dirname=", dirname)
    assert dirname == b"NonExistentDirUnicode"
    return defines.DBG_CONTINUE

def hook_function_MulDiv(dbg, args):
    print("hook_function_MulDiv args=", args)
    assert args[0] == 20
    assert args[1] == 30
    assert args[2] == 6
    return defines.DBG_CONTINUE

def create_pydbg():
    if sys.version_info < (3,):
        tst_pydbg = pydbg.pydbg()
    elif sys.version_info < (3, 7):
        tst_pydbg = pydbg
    else:
        tst_pydbg = pydbg.pydbg.pydbg()
    return tst_pydbg


class MetaStuff(object):
    object_pydbg = None
    object_hooks = None

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
        self.hook_address = MetaStuff.object_pydbg.func_resolve(b"kernel32.dll", self.function_name)
        assert self.hook_address

    def __init__(self, api_definition):
        self._parse_text_definition(api_definition)
        self.hook_address = tst_pydbg.func_resolve(b"kernel32.dll", self.function_name)
        assert self.hook_address

        def hook_function_adapter(object_pydbg, args):
            self.hook_function_core(args)
            return defines.DBG_CONTINUE

        MetaStuff.object_hooks.add(MetaStuff.object_pydbg, self.hook_address, len(self.args_list), hook_function_adapter, None)

    def report_cim_object(self, class_name, **cim_arguments):
        print("report_cim_object", class_name, cim_arguments)
        exit(0)

class StuffCreateFileA(MetaStuff):
    def __init__(self):
        super(StuffCreateFileA, self).__init__("""
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
        dirname = MetaStuff.object_pydbg.get_string(args[0])
        self.report_cim_object("CIM_DataFile", Name=dirname)



def processing_function(one_argument):
    print('processing_function START.')
    while True:
        print("This is a nice message")
        time.sleep(one_argument)
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

        resu = ctypes.windll.kernel32.MulDiv(20, 30, 6)
        assert resu == 100



if __name__ == '__main__':
    # The intention is to check that Windows gets the argument.
    try:
        os.rmdir(six.u("NonExistentDirUnicode"))  # RemoveDirectoryW
    except WindowsError as exc:
        str_exc = str(exc)
        print("As expected:(%s)" % str_exc)
        assert str_exc == "[Error 2] The system cannot find the file specified: u'NonExistentDirUnicode'"

    # The intention is to check that Windows gets the argument.
    try:
        os.rmdir(six.b("NonExistentDirBinary"))  # RemoveDirectoryA
    except WindowsError as exc:
        str_exc = str(exc)
        print("As expected:(%s)" % str_exc)
        assert str_exc == "[Error 2] The system cannot find the file specified: 'NonExistentDirBinary'"

    print("ctypes.windll.kernel32.MulDiv.argtypes=", ctypes.windll.kernel32.MulDiv.argtypes) # None
    resu = ctypes.windll.kernel32.MulDiv(20, 30, 6)
    assert resu == 100

    sleep_time = 3.0
    created_process = multiprocessing.Process(target=processing_function, args=(sleep_time,))
    created_process.start()
    print("created_process=", created_process.pid)

    time.sleep(1)

    tst_pydbg = create_pydbg()
    MetaStuff.object_pydbg = tst_pydbg
    time.sleep(1.0)

    print("getpid=", os.getpid())
    print("Attaching")
    tst_pydbg.attach(created_process.pid)

    hooks = pydbg.tests.utils.hook_container()
    MetaStuff.object_hooks = hooks

    hook_address_WriteFile = tst_pydbg.func_resolve(b"kernel32.dll", b"WriteFile")
    assert hook_address_WriteFile
    hooks.add(tst_pydbg, hook_address_WriteFile, 5, hook_function_WriteFile, None)

    hook_address_RemoveDirectoryA = tst_pydbg.func_resolve(b"kernel32.dll", b"RemoveDirectoryA")
    assert hook_address_RemoveDirectoryA
    hooks.add(tst_pydbg, hook_address_RemoveDirectoryA, 1, hook_function_RemoveDirectoryA, None)

    hook_address_RemoveDirectoryW = tst_pydbg.func_resolve(b"kernel32.dll", b"RemoveDirectoryW")
    assert hook_address_RemoveDirectoryW
    hooks.add(tst_pydbg, hook_address_RemoveDirectoryW, 1, hook_function_RemoveDirectoryW, None)

    hook_address_MulDiv = tst_pydbg.func_resolve(b"kernel32.dll", b"MulDiv")
    assert hook_address_MulDiv
    hooks.add(tst_pydbg, hook_address_MulDiv, 3, hook_function_MulDiv, None)

    #one_stuff_StuffCreateFileA = StuffCreateFileA()

    tst_pydbg.run()

    time.sleep(10.0)
    print("Detaching")
    tst_pydbg.detach()
    created_process.join()
    time.sleep(2.0)
    print("Finished")
