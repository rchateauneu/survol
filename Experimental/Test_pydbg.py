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
sys.path.append(".")
sys.path.append("pydbg")

import pydbg

from pydbg import pydbg
from pydbg import defines
from pydbg import hook_container

import os
import time
import multiprocessing

def processing_function(one_argument):
    while True:
        print('Subprocess hello. Sleeping ', one_argument)
        time.sleep(one_argument)
        print('Subprocess leaving after sleep=', one_argument)


# This is our entry hook callback function
def hook_function( dbg, args ):
    print("hook_function")
    print("hook_function type(dbg)", type(dbg))
    print("hook_function args=", args)

    if not args[1]:
        print("hook_function args ZERO")
        return defines.DBG_CONTINUE
    # we reach a NULL byte
    buffer  = ""
    offset  = 0
    try:
        while 1:
            print("hook_function offset=", offset)
            byte = dbg.read_process_memory( args[1] + offset, 1 )
            if byte != "\x00":
                buffer  += byte
                offset  += 1
                continue
            else:
                break
        print("buffer: %s" % buffer)
    except Exception as exc:
        print("Caught:", exc)
        raise
    return defines.DBG_CONTINUE

if __name__ == '__main__':
    the_argument = "Hello"
    if sys.version_info < (3,):
        tst_pydbg = pydbg()
    else:
        tst_pydbg = pydbg.pydbg()
    sleep_time = 3.0
    created_process = multiprocessing.Process(target=processing_function, args=(sleep_time,))
    created_process.start()
    print("created_process=", created_process.pid)
    time.sleep(1.0)

    print("getpid=", os.getpid())
    print("Attaching")
    tst_pydbg.attach(created_process.pid)

    # Common DLLs in Python
    # "c:/windows/system32/shell32.dll",
    # "c:/windows/system32/ole32.dll",
    # "c:/windows/system32/oleaut32.dll",
    # "c:/windows/system32/gdi32.dll"
    # kernel32.dll
    # user32.dll

    # Resolve the function address.

    """
    BOOL WriteFile(
      HANDLE       hFile,
      LPCVOID      lpBuffer,
      DWORD        nNumberOfBytesToWrite,
      LPDWORD      lpNumberOfBytesWritten,
      LPOVERLAPPED lpOverlapped
    );
    """
    hook_address = tst_pydbg.func_resolve(b"kernel32.dll", b"WriteFile")

    # https://gist.github.com/RobinDavid/9213868

    hooks = hook_container.hook_container()
    # Add the hook to the container. We aren't interested
    # in using an exit callback, so we set it to None.

    print("hook_address=%08x" % hook_address)
    assert hook_address
    hooks.add(tst_pydbg, hook_address, 5, hook_function, None)
    print("[*] Function hooked at: 0x%08x" % hook_address)

    tst_pydbg.run()

    time.sleep(10.0)
    print("Detaching")
    tst_pydbg.detach()
    created_process.join()
    time.sleep(2.0)
    print("Finished")
