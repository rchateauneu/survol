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
import sys
import six
import time
import logging

if sys.version_info < (3,):
    import Queue as queue
else:
    import queue

from . import pydbg
from pydbg import defines
from pydbg import windows_h
from pydbg import utils

################################################################################
def create_pydbg():
    if sys.version_info < (3, 8):
        tst_pydbg = pydbg.pydbg()
    else:
        tst_pydbg = pydbg()
    return tst_pydbg

################################################################################

class Win32Hook_BaseClass(object):
    object_pydbg = None
    object_hooks = pydbg.utils.hook_container()
    callback_create_call = None
    callback_create_object = None

    # The style tells if this is a native call or an aggregate of function
    # calls, made with some style: Factorization etc...
    def __init__(self):
        self.m_core = None

    # The API signature is taken "as is" from Microsoft web site.
    @staticmethod
    def _parse_text_definition(the_class):
        match_one = re.match(br"\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*\((.*)\)\s*;", the_class.api_definition, re.DOTALL)
        the_class.return_type = match_one.group(1)
        the_class.function_name = match_one.group(2)
        logging.debug("_parse_text_definition %s %s" % (the_class.__name__, the_class.function_name))

        # '\nHANDLE hFile,\nLPCVOID lpBuffer,\nDWORD nNumberOfBytesToWrite,\nLPDWORD lpNumberOfBytesWritten,\nLPOVERLAPPED lpOverlapped\n'
        the_class.args_list = []
        for one_arg_pair in match_one.group(3).split(b","):
            match_pair = re.match(br"\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*", one_arg_pair)
            the_class.args_list.append((match_pair.group(1), match_pair.group(2)))

        assert isinstance(the_class.function_name, six.binary_type)
        # Beware: Use "br'c:\windows\System32\KERNEL32.dll'" on Travis, as it does not work without the directory.
        the_class.hook_address = Win32Hook_BaseClass.object_pydbg.func_resolve(b"KERNEL32.dll", the_class.function_name)
        if not the_class.hook_address:
            raise Exception("Cannot find address of %s" % the_class.function_name)

    def set_arguments(self, args, function_result):
        self.m_parsedArgs = args
        self.m_retValue = function_result

    @classmethod
    def add_subclass(the_class, the_subclass):
        logging.debug("add_subclass:%s" % (the_subclass.__name__))
        Win32Hook_BaseClass._parse_text_definition(the_subclass)
        logging.debug("add_subclass:%s" % (the_subclass.function_name))
        logging.debug("add_subclass:%016x" % (the_subclass.hook_address))

        def hook_function_adapter_entry(object_pydbg, args):
            logging.debug("hook_function_adapter_entry", args)

        def hook_function_adapter_exit(object_pydbg, args, function_result):
            logging.debug("hook_function_adapter_exit", args, function_result)
            subclass_instance = the_subclass()
            subclass_instance.set_arguments(args, function_result)
            subclass_instance.process_arguments()
            task_id = None
            Win32Hook_BaseClass.callback_create_call(subclass_instance, object_pydbg, task_id)
            return defines.DBG_CONTINUE

        Win32Hook_BaseClass.object_hooks.add(
            Win32Hook_BaseClass.object_pydbg,
            the_subclass.hook_address,
            len(the_subclass.args_list),
            hook_function_adapter_entry,
            hook_function_adapter_exit)

    def report_cim_object(self, cim_class_name, **cim_arguments):
        logging.debug("report_cim_object", self.__class__.__name__, cim_class_name, cim_arguments)
        self.callback_create_object(cim_class_name, cim_arguments)


class Win32Hook_CreateProcessA(Win32Hook_BaseClass):
    api_definition = b"""
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

        logging.debug("Win32Hook_CreateProcessA m_parsedArgs=", self.m_parsedArgs)
        logging.debug("Win32Hook_CreateProcessA m_retValue=", self.m_retValue)
        logging.debug("Win32Hook_CreateProcessA Handle=", dwProcessId)
        self.callback_create_object("CIM_Process", Handle=dwProcessId)


class Win32Hook_CreateProcessAsUserA(Win32Hook_BaseClass):
    api_definition = b"""
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
    api_definition = b"""
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
    api_definition = b"""
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

    def process_arguments(self):
        lpApplicationName = Win32Hook_BaseClass.object_pydbg.get_wstring(self.m_parsedArgs[0])
        lpCommandLine = Win32Hook_BaseClass.object_pydbg.get_wstring(self.m_parsedArgs[1])
        lpProcessInformation = self.m_parsedArgs[9]
        offset_dwProcessId = windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.HANDLE)
        dwProcessId = Win32Hook_BaseClass.object_pydbg.get_long(lpProcessInformation + offset_dwProcessId)

        logging.debug("Win32Hook_CreateProcessW m_parsedArgs=", self.m_parsedArgs)
        logging.debug("Win32Hook_CreateProcessW m_retValue=", self.m_retValue)
        logging.debug("Win32Hook_CreateProcessW Handle=", dwProcessId)
        self.callback_create_object("CIM_Process", Handle=dwProcessId)


class Win32Hook_ExitProcess(Win32Hook_BaseClass):
    api_definition = b"""
        void ExitProcess(
            UINT uExitCode
        );"""

class Win32Hook_CreateThread(Win32Hook_BaseClass):
    api_definition = b"""
        HANDLE CreateThread(
            LPSECURITY_ATTRIBUTES   lpThreadAttributes,
            SIZE_T                  dwStackSize,
            LPTHREAD_START_ROUTINE  lpStartAddress,
            __drv_aliasesMem LPVOID lpParameter,
            DWORD                   dwCreationFlags,
            LPDWORD                 lpThreadId
        );"""

class Win32Hook_CreateRemoteThread(Win32Hook_BaseClass):
    api_definition = b"""
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
    api_definition = b"""
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
    api_definition = b"""
            BOOL TerminateProcess(
                HANDLE hProcess,
                UINT   uExitCode
            );"""

class Win32Hook_TerminateThread(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL TerminateThread(
            HANDLE hThread,
            DWORD  dwExitCode
        );"""

class Win32Hook_CreateDirectoryA(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL CreateDirectoryA(
            LPCWSTR               lpPathName,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes
        );"""

class Win32Hook_CreateDirectoryW(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL CreateDirectoryW(
            LPCWSTR               lpPathName,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes
        );"""

class Win32Hook_RemoveDirectoryA(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL RemoveDirectoryA(
            LPCSTR lpPathName
        );"""
    def process_arguments(self):
        logging.debug("hook_function_RemoveDirectoryA args=", self.m_parsedArgs)
        dirname = Win32Hook_BaseClass.object_pydbg.get_string(self.m_parsedArgs[0])
        logging.debug("hook_function_RemoveDirectoryA dirname=", dirname)
        self.callback_create_object("CIM_Directory", Name=dirname)

class Win32Hook_RemoveDirectoryW(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL RemoveDirectoryW(
            LPCWSTR lpPathName
        );"""
    def process_arguments(self):
        logging.debug("hook_function_RemoveDirectoryW args=", self.m_parsedArgs)
        dirname = Win32Hook_BaseClass.object_pydbg.get_wstring(self.m_parsedArgs[0])
        logging.debug("hook_function_RemoveDirectoryW dirname=", dirname)
        self.callback_create_object("CIM_Directory", Name=dirname)

class Win32Hook_CreateFileA(Win32Hook_BaseClass):
    api_definition = b"""
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
    api_definition = b"""
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
        dirname = Win32Hook_BaseClass.object_pydbg.get_wstring(self.m_parsedArgs[0])
        self.callback_create_object("CIM_DataFile", Name=dirname)

class Win32Hook_CreateFile2(Win32Hook_BaseClass):
    api_definition = b"""
        HANDLE CreateFile2(
            LPCWSTR                           lpFileName,
            DWORD                             dwDesiredAccess,
            DWORD                             dwShareMode,
            DWORD                             dwCreationDisposition,
            LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams
        );"""

class Win32Hook_DeleteFileA(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL DeleteFileA(
            LPCSTR lpFileName
        );"""
    def process_arguments(self):
        dirname = Win32Hook_BaseClass.object_pydbg.get_string(self.m_parsedArgs[0])
        self.callback_create_object("CIM_DataFile", Name=dirname)

class Win32Hook_DeleteFileW(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL DeleteFileW(
            LPCWSTR lpFileName
        );"""
    def process_arguments(self):
        dirname = Win32Hook_BaseClass.object_pydbg.get_wstring(self.m_parsedArgs[0])
        self.callback_create_object("CIM_DataFile", Name=dirname)

class Win32Hook_WriteFile(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL WriteFile(
            HANDLE       hFile,
            LPCVOID      lpBuffer,
            DWORD        nNumberOfBytesToWrite,
            LPDWORD      lpNumberOfBytesWritten,
            LPOVERLAPPED lpOverlapped
        );"""
    def process_arguments(self):
        logging.debug("hook_function_WriteFile args=", self.m_parsedArgs)

        lpBuffer = self.m_parsedArgs[1]
        nNumberOfBytesToWrite = self.m_parsedArgs[2]
        # logging.debug("lpBuffer=", lpBuffer, "nNumberOfBytesToWrite=", nNumberOfBytesToWrite)
        buffer = Win32Hook_BaseClass.object_pydbg.get_string_size(lpBuffer, nNumberOfBytesToWrite)
        logging.debug("Buffer=", buffer)


class Win32Hook_WriteFileEx(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL WriteFileEx(
            HANDLE                          hFile,
            LPCVOID                         lpBuffer,
            DWORD                           nNumberOfBytesToWrite,
            LPOVERLAPPED                    lpOverlapped,
            LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );"""

class Win32Hook_WriteFileGather(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL WriteFileGather(
            HANDLE                  hFile,
            FILE_SEGMENT_ELEMENT [] aSegmentArray,
            DWORD                   nNumberOfBytesToWrite,
            LPDWORD                 lpReserved,
            LPOVERLAPPED            lpOverlapped
        );"""

class Win32Hook_ReadFile(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL ReadFile(
            HANDLE       hFile,
            LPVOID       lpBuffer,
            DWORD        nNumberOfBytesToRead,
            LPDWORD      lpNumberOfBytesRead,
            LPOVERLAPPED lpOverlapped
        );"""

class Win32Hook_ReadFileEx(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL ReadFileEx(
            HANDLE                          hFile,
            LPVOID                          lpBuffer,
            DWORD                           nNumberOfBytesToRead,
            LPOVERLAPPED                    lpOverlapped,
            LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );"""

class Win32Hook_ReadFileScatter(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL ReadFileScatter(
            HANDLE                  hFile,
            FILE_SEGMENT_ELEMENT [] aSegmentArray,
            DWORD                   nNumberOfBytesToRead,
            LPDWORD                 lpReserved,
            LPOVERLAPPED            lpOverlapped
        );"""

################################################################################

class Win32BatchCore:
    def __init__(self, task_id, function_name):
        self._task_id = task_id
        self._function_name = function_name

def hook_functions():
    for subclass_definition in [
        Win32Hook_CreateProcessA,
        Win32Hook_CreateProcessW,
        Win32Hook_RemoveDirectoryA,
        Win32Hook_RemoveDirectoryW,
        Win32Hook_CreateFileA,
        Win32Hook_CreateFileW,
        Win32Hook_DeleteFileA,
        Win32Hook_DeleteFileW]:
        Win32Hook_BaseClass.add_subclass(subclass_definition)

class Win32Tracer:
    def LogFileStream(self, extCommand, aPid):
        if not aPid:
            raise Exception("LogFileStream: process id should not be None")
        if extCommand:
            raise Exception("LogFileStream: command should not None")

        self._root_pid = aPid

        Win32Tracer._queue = queue.Queue()

        time.sleep(1.0)

        hook_functions()

        def _win32_tracer_syscall_creation_callback(one_syscall, object_pydbg, task_id):
            logging.info("syscall=%s" % one_syscall.function_name)
            # Different logic of objects creation.
            # COMMENT ON VA FAIRE DOCKERFILE ?


            # See in hooking.py pydbg.dbg.dwThreadId
            # See in hooking.py pydbg.dbg.dwThreadId
            # See in hooking.py pydbg.dbg.dwThreadId
            # See in hooking.py pydbg.dbg.dwThreadId


            batch_core = Win32BatchCore(task_id, one_syscall.function_name)

            Win32Tracer._queue.put(batch_core)

        def _win32_tracer_cim_object_callback(calling_class_instance, cim_class_name, **cim_arguments):
            logging.debug("win32_tracer_cim_object_callback", calling_class_instance.__class__.__name__, cim_class_name,
                  cim_arguments)
            function_name = calling_class_instance.function_name

        Win32Hook_BaseClass.callback_create_call = _win32_tracer_syscall_creation_callback
        Win32Hook_BaseClass.callback_create_object = _win32_tracer_cim_object_callback

        return (self._root_pid, self._queue)

    def CreateFlowsFromLogger(self, verbose, logStream):

        assert isinstance(logStream, queue.Queue)

        queue_timeout = 10.0 # Seconds.

        def thread_function():
            Win32Hook_BaseClass.object_pydbg.attach(aPid)
            Win32Hook_BaseClass.object_pydbg.run()
            #         On veut se mettre a la place de pydbg.debug_event_loop equivalent a run())
            #         qui appelle debug_event_iteration qui appelle WaitForDebugEvent
            ######        self._pydbg.detach()
            Win32Hook_BaseClass.object_pydbg.terminate()

        # Not finished yet.
        start_thread(thread_function)

        while True:
            try:
                # We could use the queue to signal the end of the loop.
                batch_core = logStream.get(True, timeout = queue_timeout)
            except queue.Empty:
                logging.info("Win32Tracer.CreateFlowsFromLogger timeout. Waiting.")
                continue

            assert isinstance(batch_core, Win32BatchCore)

            yield batch_core

    def Version(self):
        return str("pydbg " + str(pydbg.__version__))
