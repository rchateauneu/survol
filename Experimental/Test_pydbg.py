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
from pydbg.tests.utils import win32_api_definition

def create_pydbg():
    if sys.version_info < (3,):
        tst_pydbg = pydbg.pydbg()
    elif sys.version_info < (3, 7):
        tst_pydbg = pydbg
    else:
        tst_pydbg = pydbg.pydbg.pydbg()
    return tst_pydbg

################################################################################


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
    win32_api_definition.Win32HookBaseClass.object_pydbg = tst_pydbg
    time.sleep(1.0)

    print("getpid=", os.getpid())
    print("Attaching")
    tst_pydbg.attach(created_process.pid)

    hooks = pydbg.tests.utils.hook_container()
    win32_api_definition.Win32HookBaseClass.object_hooks = hooks

    one_win32hook_Win32HookWriteFile = win32_api_definition.Win32HookWriteFile()
    one_win32hook_Win32HookRemoveDirectoryA = win32_api_definition.Win32HookRemoveDirectoryA()
    one_win32hook_Win32HookRemoveDirectoryW = win32_api_definition.Win32HookRemoveDirectoryW()
    one_win32hook_Win32HookMulDiv = win32_api_definition.Win32HookMulDiv()
    one_win32hook_Win32HookCreateFileA = win32_api_definition.Win32HookCreateFileA()

    tst_pydbg.run()

    time.sleep(10.0)
    print("Detaching")
    tst_pydbg.detach()
    created_process.join()
    time.sleep(2.0)
    print("Finished")
