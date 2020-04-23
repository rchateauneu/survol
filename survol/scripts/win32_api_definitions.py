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
import os
import sys
import six
import time
import logging
import collections

import win32file
import win32con

if sys.version_info < (3,):
    import Queue as queue
else:
    import queue

if __package__:
    from . import pydbg
    from .pydbg import defines
    from .pydbg import windows_h
    from .pydbg import utils
else:
    import pydbg
    from pydbg import defines
    from pydbg import windows_h
    from pydbg import utils

################################################################################

# class Win32BatchCore:
#     def __init__(self, task_id, function_name):
#         self._task_id = task_id
#         self._function_name = function_name
#
# class Win32Tracer(TracerBase):
#     def LogFileStream(self, extCommand, aPid):
#         if not aPid:
#             raise Exception("LogFileStream: process id should not be None")
#         if extCommand:
#             raise Exception("LogFileStream: command should not be None")
#
#         self._root_pid = aPid
#
#         Win32Tracer._queue = queue.Queue()
#
#         time.sleep(1.0)
#
#         hook_functions()
#
#         def report_function_call(one_syscall, task_id):
#             logging.info("syscall=%s" % one_syscall.function_name)
#             # Different logic of objects creation.
#             # COMMENT ON VA FAIRE DOCKERFILE ?
#
#             batch_core = Win32BatchCore(task_id, one_syscall.function_name)
#
#             Win32Tracer._queue.put(batch_core)
#
#         def report_object_creation(calling_class_instance, cim_class_name, **cim_arguments):
#             logging.debug("win32_tracer_cim_object_callback", calling_class_instance.__class__.__name__, cim_class_name,
#                   cim_arguments)
#             function_name = calling_class_instance.function_name
#
#         return (self._root_pid, self._queue)
#
#     def create_flows_from_calls_stream(self, verbose, logStream):
#
#         assert isinstance(logStream, queue.Queue)
#
#         queue_timeout = 10.0 # Seconds.
#
#         def thread_function():
#             Win32Hook_BaseClass.object_pydbg.attach(aPid)
#             Win32Hook_BaseClass.object_pydbg.run()
#             #         On veut se mettre a la place de pydbg.debug_event_loop equivalent a run())
#             #         qui appelle debug_event_iteration qui appelle WaitForDebugEvent
#             ######        self._pydbg.detach()
#             Win32Hook_BaseClass.object_pydbg.terminate()
#
#         # Not finished yet.
#         start_thread(thread_function)
#
#         while True:
#             try:
#                 # We could use the queue to signal the end of the loop.
#                 batch_core = logStream.get(True, timeout = queue_timeout)
#             except queue.Empty:
#                 logging.info("Win32Tracer.create_flows_from_calls_stream timeout. Waiting.")
#                 continue
#
#             assert isinstance(batch_core, Win32BatchCore)
#
#             yield batch_core
#
#     def Version(self):
#         return str("pydbg " + str(pydbg.__version__))

class TracerBase(object):
    def report_function_call(self, function_name, task_id):
        logging.debug("report_cim_object %s %s %s" % (self.__class__.__name__, function_name, task_id))
        # For testing, it just stores the function name.
        # In Survol, it stores the function name in a queue,
        # and this event can be forwarded to a RDF semantic database.

    def report_object_creation(self, cim_class_name, **cim_arguments):
        logging.debug("report_cim_object %s %s %s" % (self.__class__.__name__, cim_class_name, cim_arguments))
        # For testing, it just stores the object where it can be read for testing.
        # In Survol, it stores the object in a queue,
        # and this event can be forwarded to a RDF semantic database.

# This must be replaced by an object of a derived class.
tracer_object = None # TracerBase()

################################################################################
class Win32Hook_Manager(object):
    # The style tells if this is a native call or an aggregate of function
    # calls, made with some style: Factorization etc...
    def __init__(self):
        self.m_core = None
        self.object_pydbg = pydbg.pydbg()

        # So it can be found from the callbacks.
        self.object_pydbg.hook_manager = self

        # TODO: Replace by a map: Process id -> hook_container
        self.object_hooks = utils.hook_container()

        # This event is received after the DLL is mapped into the address space of the debuggee.
        self.object_pydbg.set_callback(defines.LOAD_DLL_DEBUG_EVENT, self.load_dll_callback)

        self.unhooked_functions_by_dll = collections.defaultdict(list)

    def add_one_function_from_dll_address(self, dll_address, the_subclass):

        the_subclass.function_address = self.object_pydbg.func_resolve_from_dll(dll_address, the_subclass.function_name)

        # There is one such function per class associated to an API function.
        # The arguments are stored per thread, and implictly form a stack.
        def hook_function_adapter_entry(object_pydbg, function_arguments):
            logging.debug("hook_function_adapter_entry", the_subclass.__name__, function_arguments)
            subclass_instance = the_subclass()
            subclass_instance.current_pydbg = object_pydbg
            # This instance object has the same visibility and scope than the arguments.
            # Therefore, they are stored together with a hack of appending the instance
            # at the arguments'end.
            # This instance is a context for the results of anything done before the function call.
            subclass_instance.callback_before(function_arguments)
            function_arguments.append(subclass_instance)
            tracer_object.report_function_call(the_subclass.function_name, object_pydbg.dbg.dwThreadId)
            return defines.DBG_CONTINUE

        # There is one such function per class associated to an API function.
        def hook_function_adapter_exit(object_pydbg, function_arguments, function_result):
            logging.debug("hook_function_adapter_exit", the_subclass.__name__, function_arguments, function_result)
            subclass_instance = function_arguments[-1]
            function_arguments.pop()
            # So we can use arguments stored before the actual function call.
            subclass_instance.callback_after(function_arguments, function_result)
            return defines.DBG_CONTINUE

        self.object_hooks.add(self.object_pydbg,
                         the_subclass.function_address,
                         len(the_subclass.args_list),
                         hook_function_adapter_entry,
                         hook_function_adapter_exit)

    @staticmethod
    def load_dll_callback(object_pydbg):
        # self.dbg.u.LoadDll is _LOAD_DLL_DEBUG_INFO
        dll_filename = win32file.GetFinalPathNameByHandle(
            object_pydbg.dbg.u.LoadDll.hFile, win32con.FILE_NAME_NORMALIZED)
        if dll_filename.startswith("\\\\?\\"):
            dll_filename = dll_filename[4:]
        assert isinstance(dll_filename, six.text_type)
        print("load_dll_callback dll_filename=", dll_filename)

        dll_canonic_name = object_pydbg.canonic_dll_name(dll_filename.encode('utf-8'))

        # At this stage, the library cannot be found with CreateToolhelp32Snapshot,
        #  and Module32First/Module32Next. But the dll object is passed to the callback.
        dll_address = object_pydbg.dbg.u.LoadDll.lpBaseOfDll
        for one_subclass in object_pydbg.hook_manager.unhooked_functions_by_dll.get(dll_canonic_name, []):
            self.add_one_function_from_dll_address(dll_address, one_subclass)

        return defines.DBG_CONTINUE

    # This is called when looping on the list of semantically interesting functions.
    def hook_api_function(self, the_subclass):
        logging.debug("hook_api_function:%s" % the_subclass.__name__)
        the_subclass._parse_text_definition(the_subclass)

        dll_canonic_name = os.path.basename(the_subclass.dll_name).upper()

        dll_address = self.object_pydbg.find_dll_base_address(dll_canonic_name)

        # If the DLL is already loaded.
        if dll_address:
            self.add_one_function_from_dll_address(dll_address, the_subclass)
        else:
            self.unhooked_functions_by_dll[dll_canonic_name].append(the_subclass)

hooks_manager = Win32Hook_Manager()

################################################################################

# Each derived class must have:
# - The string api_definition="" which contains the signature of the Windows API
#   function in Windows web site format.
class Win32Hook_BaseClass(object):
    # The style tells if this is a native call or an aggregate of function
    # calls, made with some style: Factorization etc...
    def __init__(self):
        self.m_core = None

    # Possible optimisation: If this function is not implemented,
    # no need to create a subclass instance.
    def callback_before(self, function_arguments):
        pass

    def callback_after(self, function_arguments, function_result):
        pass

    # The API signature is taken "as is" from Microsoft web site.
    # There are many functions and copying their signature is error-prone.
    # Therefore, one just needs to copy-paste the zweb site text.
    @staticmethod
    def _parse_text_definition(the_class):
        match_one = re.match(br"\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*\((.*)\)\s*;", the_class.api_definition, re.DOTALL)
        the_class.return_type = match_one.group(1)
        the_class.function_name = match_one.group(2)
        logging.debug("_parse_text_definition %s %s" % (the_class.__name__, the_class.function_name))

        the_class.args_list = []
        for one_arg_pair in match_one.group(3).split(b","):
            match_pair = re.match(br"\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*", one_arg_pair)
            the_class.args_list.append((match_pair.group(1), match_pair.group(2)))

        assert isinstance(the_class.function_name, six.binary_type)

    def callback_create_object(self, cim_class_name, **cim_arguments):
        tracer_object.report_object_creation(cim_class_name, **cim_arguments)

################################################################################

class Win32Hook_GenericProcessCreation(Win32Hook_BaseClass):

    # API functions which create process have a specific behaviour:
    # - They set the process as suspended.
    # - Wait until it is created.
    # - Once the subprocess is created, the necessary environment for hooking a process is re-created
    #   inside this function call which is then uniquely associated to a process.
    #   This data structure associated to a process also contains the hook logic to interrupt API functions calls.
    def process_creation_before(self):

        # Change dwCreationFlags in the stack, the way its value was read.

        raise NotImplementedYet()

    def process_creation_after(self, process_id):
        raise NotImplementedYet()


################################################################################

class Win32Hook_CreateProcessA(Win32Hook_GenericProcessCreation):
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
    dll_name = b"KERNEL32.dll"
    def callback_after(self, function_arguments, function_result):
        lpApplicationName = self.current_pydbg.get_bytes_string(function_arguments[0])
        lpCommandLine = self.current_pydbg.get_bytes_string(function_arguments[1])
        lpProcessInformation = function_arguments[9]

        # _PROCESS_INFORMATION {
        #   HANDLE hProcess;
        #   HANDLE hThread;
        #   DWORD  dwProcessId;
        #   DWORD  dwThreadId;
        # }
        offset_dwProcessId = windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.HANDLE)
        dwProcessId = self.current_pydbg.get_long(lpProcessInformation + offset_dwProcessId)

        logging.debug("Win32Hook_CreateProcessA m_parsedArgs=", function_arguments)
        logging.debug("Win32Hook_CreateProcessA m_retValue=", function_result)
        logging.debug("Win32Hook_CreateProcessA Handle=", dwProcessId)
        self.callback_create_object("CIM_Process", Handle=dwProcessId)


class Win32Hook_CreateProcessAsUserA(Win32Hook_GenericProcessCreation):
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
    dll_name = b"KERNEL32.dll"

class Win32Hook_CreateProcessAsUserW(Win32Hook_GenericProcessCreation):
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
    dll_name = b"KERNEL32.dll"

class Win32Hook_CreateProcessW(Win32Hook_GenericProcessCreation):
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
    dll_name = b"KERNEL32.dll"
    def callback_after(self, function_arguments, function_result):
        lpApplicationName = self.current_pydbg.get_unicode_string(function_arguments[0])
        lpCommandLine = self.current_pydbg.get_unicode_string(function_arguments[1])
        lpProcessInformation = function_arguments[9]
        offset_dwProcessId = windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.HANDLE)
        dwProcessId = self.current_pydbg.get_long(lpProcessInformation + offset_dwProcessId)

        logging.debug("Win32Hook_CreateProcessW m_parsedArgs=", function_arguments)
        logging.debug("Win32Hook_CreateProcessW m_retValue=", function_result)
        logging.debug("Win32Hook_CreateProcessW Handle=", dwProcessId)
        self.callback_create_object("CIM_Process", Handle=dwProcessId)

class Win32Hook_ExitProcess(Win32Hook_BaseClass):
    api_definition = b"""
        void ExitProcess(
            UINT uExitCode
        );"""
    dll_name = b"KERNEL32.dll"
    # TODO: Must find the data structure associated to its process at creation time.

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
    dll_name = b"KERNEL32.dll"

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
    dll_name = b"KERNEL32.dll"

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
    dll_name = b"KERNEL32.dll"

class Win32Hook_TerminateProcess(Win32Hook_BaseClass):
    api_definition = b"""
            BOOL TerminateProcess(
                HANDLE hProcess,
                UINT   uExitCode
            );"""
    dll_name = b"KERNEL32.dll"

class Win32Hook_TerminateThread(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL TerminateThread(
            HANDLE hThread,
            DWORD  dwExitCode
        );"""
    dll_name = b"KERNEL32.dll"

class Win32Hook_CreateDirectoryA(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL CreateDirectoryA(
            LPCWSTR               lpPathName,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes
        );"""
    dll_name = b"KERNEL32.dll"

class Win32Hook_CreateDirectoryW(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL CreateDirectoryW(
            LPCWSTR               lpPathName,
            LPSECURITY_ATTRIBUTES lpSecurityAttributes
        );"""
    dll_name = b"KERNEL32.dll"

class Win32Hook_RemoveDirectoryA(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL RemoveDirectoryA(
            LPCSTR lpPathName
        );"""
    dll_name = b"KERNEL32.dll"
    def callback_after(self, function_arguments, function_result):
        logging.debug("hook_function_RemoveDirectoryA args=", function_arguments)
        dirname = self.current_pydbg.get_bytes_string(function_arguments[0])
        logging.debug("hook_function_RemoveDirectoryA dirname=", dirname)
        self.callback_create_object("CIM_Directory", Name=dirname)

class Win32Hook_RemoveDirectoryW(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL RemoveDirectoryW(
            LPCWSTR lpPathName
        );"""
    dll_name = b"KERNEL32.dll"
    def callback_after(self, function_arguments, function_result):
        logging.debug("hook_function_RemoveDirectoryW args=", function_arguments)
        dirname = self.current_pydbg.get_unicode_string(function_arguments[0])
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
    dll_name = b"KERNEL32.dll"
    def callback_after(self, function_arguments, function_result):
        dirname = self.current_pydbg.get_bytes_string(function_arguments[0])
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
    dll_name = b"KERNEL32.dll"
    def callback_after(self, function_arguments, function_result):
        dirname = self.current_pydbg.get_unicode_string(function_arguments[0])
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
    dll_name = b"KERNEL32.dll"

class Win32Hook_DeleteFileA(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL DeleteFileA(
            LPCSTR lpFileName
        );"""
    dll_name = b"KERNEL32.dll"
    def callback_after(self, function_arguments, function_result):
        dirname = self.current_pydbg.get_bytes_string(function_arguments[0])
        self.callback_create_object("CIM_DataFile", Name=dirname)

class Win32Hook_DeleteFileW(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL DeleteFileW(
            LPCWSTR lpFileName
        );"""
    dll_name = b"KERNEL32.dll"
    def callback_after(self, function_arguments, function_result):
        dirname = self.current_pydbg.get_unicode_string(function_arguments[0])
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
    dll_name = b"KERNEL32.dll"
    def callback_after(self, function_arguments, function_result):
        logging.debug("hook_function_WriteFile args=", function_arguments)

        lpBuffer = function_arguments[1]
        nNumberOfBytesToWrite = function_arguments[2]
        # logging.debug("lpBuffer=", lpBuffer, "nNumberOfBytesToWrite=", nNumberOfBytesToWrite)
        buffer = self.object_pydbg.get_bytes_size(lpBuffer, nNumberOfBytesToWrite)
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
    dll_name = b"KERNEL32.dll"

class Win32Hook_WriteFileGather(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL WriteFileGather(
            HANDLE                  hFile,
            FILE_SEGMENT_ELEMENT [] aSegmentArray,
            DWORD                   nNumberOfBytesToWrite,
            LPDWORD                 lpReserved,
            LPOVERLAPPED            lpOverlapped
        );"""
    dll_name = b"KERNEL32.dll"

class Win32Hook_ReadFile(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL ReadFile(
            HANDLE       hFile,
            LPVOID       lpBuffer,
            DWORD        nNumberOfBytesToRead,
            LPDWORD      lpNumberOfBytesRead,
            LPOVERLAPPED lpOverlapped
        );"""
    dll_name = b"KERNEL32.dll"

class Win32Hook_ReadFileEx(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL ReadFileEx(
            HANDLE                          hFile,
            LPVOID                          lpBuffer,
            DWORD                           nNumberOfBytesToRead,
            LPOVERLAPPED                    lpOverlapped,
            LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
        );"""
    dll_name = b"KERNEL32.dll"

class Win32Hook_ReadFileScatter(Win32Hook_BaseClass):
    api_definition = b"""
        BOOL ReadFileScatter(
            HANDLE                  hFile,
            FILE_SEGMENT_ELEMENT [] aSegmentArray,
            DWORD                   nNumberOfBytesToRead,
            LPDWORD                 lpReserved,
            LPOVERLAPPED            lpOverlapped
        );"""
    dll_name = b"KERNEL32.dll"

################################################################################

def hook_all_functions():
    # Loop on all lead subclasses of Win32Hook_BaseClass.
    for subclass_definition in [
        Win32Hook_CreateProcessA,
        Win32Hook_CreateProcessW,
        Win32Hook_RemoveDirectoryA,
        Win32Hook_RemoveDirectoryW,
        Win32Hook_CreateFileA,
        Win32Hook_CreateFileW,
        Win32Hook_DeleteFileA,
        Win32Hook_DeleteFileW]:
        hooks_manager.hook_api_function(subclass_definition)

