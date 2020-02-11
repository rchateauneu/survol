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

nonexistent_file = "NonExistentFile.xyz"

# This procedure calls various win32 systems functions,
# which are hooked then tested: Arguments, return values etc...
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

        # This checks the opening of a file.
        try:
            opfil = open(nonexistent_file)
        except Exception as exc:
            pass

        try:
            # os.system("ThisCommandDoesNotWork")
            os.system("dir nothing_at_all")
        except Exception as exc:
            pass

def syscall_creation_callback(one_syscall):
    print("syscall=", one_syscall.function_name)


def cim_object_callback(calling_class_instance, cim_class_name, **cim_arguments):
    print("cim_object_callback", calling_class_instance.__class__.__name__, cim_class_name, cim_arguments)
    function_name = calling_class_instance.function_name
    if function_name == "RemoveDirectoryA":
        assert cim_arguments["Name"] == "NonExistentDirBinary"
    elif function_name == "RemoveDirectoryW":
        assert cim_arguments["Name"] == "NonExistentDirUnicode"
    elif function_name == "CreateFileA":
        assert cim_arguments["Name"] in [
            nonexistent_file,
            "C:\\Python27\\lib\\encodings\\unicode_escape.pyd",
            "C:\\Python27\\lib\\encodings\\unicode_escape.pyc",
            "C:\\Python27\\lib\\encodings\\unicode_escape.py"]
    elif function_name == "CreateFileW":
        assert cim_arguments["Name"] == "NonExistentDirUnicode"
    elif function_name == "CreateProcessA":
        print("cim_arguments=", cim_arguments)
    else:
        raise Exception("Unexpected API function:", function_name)


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
    win32_api_definition.Win32Hook_BaseClass.object_pydbg = tst_pydbg
    time.sleep(1.0)

    print("getpid=", os.getpid())
    print("Attaching")
    tst_pydbg.attach(created_process.pid)

    hooks = pydbg.tests.utils.hook_container()
    win32_api_definition.Win32Hook_BaseClass.object_hooks = hooks

    #def cim_object_callback(*args):
    #    print("report_cim_object", args)

    win32_api_definition.Win32Hook_BaseClass.callback_create_call = syscall_creation_callback
    win32_api_definition.Win32Hook_BaseClass.callback_create_object = cim_object_callback



    for subclass_definition in [
        win32_api_definition.Win32Hook_CreateProcessA,
        win32_api_definition.Win32Hook_CreateProcessW,
        win32_api_definition.Win32Hook_WriteFile,
        win32_api_definition.Win32Hook_RemoveDirectoryA,
        win32_api_definition.Win32Hook_RemoveDirectoryW,
        win32_api_definition.Win32Hook_MulDiv,
        win32_api_definition.Win32Hook_CreateFileA ]:
        win32_api_definition.Win32Hook_BaseClass.add_subclass(subclass_definition)

    tst_pydbg.run()

    time.sleep(10.0)
    print("Detaching")
    tst_pydbg.detach()
    created_process.join()
    time.sleep(2.0)
    print("Finished")




"""

Ne pas s'encombrer a utiliser le code Linux mais faire quelque chose de mieux au niveau de la generation des objets.
Et c'est le script Linux qui l utilisera ensuite.
Generer les objets dans une queue pour ne pas les stocker.
On va les chercher dans le While du debugger.

On n utilise pas BatchLetSequence, et meme il faut le separer du code Linux (Et a terme le virer,
Ou le changer: On ne s'en sert pas actuellement).

BatchFlow: execution flow, associated to a process / thread.
On n'a pas besoin de BatchFlow. FilterMatchedBatches

On a vraiment besoin de:
- Generation dockerfile.
- Generation summary.
Donc il faut arrive a les extraire: lib_dockerfile_generation.py dans le directory des scripts (Par defaut dans sys.path).
On peut convenir que l'interface est un ensemble d'objets CIM:

GenerateDockerFile.WriteProcessTree():
        for oneProc in CIM_Process.GetTopProcesses():
            WriteOneProcessSubTree( oneProc, 1 )

Extraire les definitions d'objets CIM ainsi que CIM_XmlMarshaller dans scripts/lib_cim_objects_definitions:
class CIM_ComputerSystem (CIM_XmlMarshaller,object): etc...
Ca doit etre completement separe de "BatchFlow" et autres.

Peut etre aussi FileAccess
Est-ce que "report_cim" va remplir G_mapCacheObjects[CIM_Process.__name__] ?

HttpTriplesClient


Donc:
BatchLinux et DebugWin32 ecrivent dans cim_objects
Docker et summary vont lire dans cim_objects.
"""