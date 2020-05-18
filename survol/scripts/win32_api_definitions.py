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
import struct
import logging
import platform
import threading
import collections

import win32file
import win32con
import win32process
import pywintypes
import win32api

if __package__:
    from . import cim_objects_definitions
else:
    import cim_objects_definitions

is_py3 = sys.version_info >= (3,)
if is_py3:
    import queue
else:
    import Queue as queue

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

# This models what can be done with the detection of function calls
# in a running program. It is possible to report the function,
# and also report the creation or update of an object, modelled with CIM,
# or an extension of CIM.
class TracerBase(object):
    def report_function_call(self, function_name, process_id):
        raise NotImplementedError("To be implemented")

    def report_object_creation(self, cim_objects_context, cim_class_name, **cim_arguments):
        raise NotImplementedError("To be implemented")


# This uses duck typing to behave like a BatchLetCore.
class PseudoTraceLineCore:
    def __init__(self, process_id, function_name):
        self.m_pid = process_id
        # This is not applicable to Windows, yet.
        self.m_status = 999999
        self.m_funcNam = function_name
        self.m_retValue = 0
        self.m_timeStart = time.time()
        self.m_timeEnd = self.m_timeStart

    # TODO: Finish this list.
    _functions_creating_processes = set(["CreateProcessW", "CreateProcessA"])

    def is_creating_process(self):
        return self.m_funcNam in self._functions_creating_processes

class PseudoTraceLine:
    def __init__(self, process_id, function_name):
        assert isinstance(function_name, six.binary_type)
        self.m_core = PseudoTraceLineCore(process_id, function_name)
        # So, consecutive calls can be aggregated.
        # This compresses consecutive calls, in a loop, to the same function.
        self.m_occurrences = 1
        # The style tells if this is a native call or an aggregate of function calls.
        self.m_style = "Breakpoint"

    def write_to_file(self, file_descriptor):
        assert isinstance(self.m_core.m_funcNam, six.binary_type)
        file_descriptor.write("%d %s\n" % (self.m_core.m_pid, self.m_core.m_funcNam.decode('utf-8)')))

    @staticmethod
    def read_from_file(file_descriptor):
        function_call_line = file_descriptor.readline().split()
        process_id = int(function_call_line[0])
        function_name = function_call_line[1].encode()
        return PseudoTraceLine(process_id, function_name)

    # Process creations or setup are not aggregated.
    def is_same_call(self, another_object):
        return self.m_core.m_funcNam == another_object.m_core.m_funcNam \
               and not self.m_core.is_creating_process() \
               and not another_object.m_core.is_creating_process()

    def get_significant_args(self):
        return []


class Win32Tracer(TracerBase):

    # This is a convention to indicate the program end.
    _function_name_process_start = b"PYDBG_PROCESS_START"
    _function_name_process_exit = b"PYDBG_PROCESS_EXIT"

    def _callback_process_creation(self, created_process_id):
        logging.error("_callback_process_creation created_process_id=%d" % created_process_id)
        # The first message of this queue is a conventional function call which contains the created process id.
        # After that, it contains only genuine function calls, plus the last one,
        # also conventional, which indicates the process end, and releases the main process.
        batch_core = PseudoTraceLine(created_process_id, self._function_name_process_start)
        self._queue.put(batch_core)

    def _start_debugging(self):
        if self._input_process_id > 0:
            logging.error("_start_debugging self._input_process_id=%d" % self._input_process_id)
            assert not self._command_line
            self._hooks_manager.attach_to_pid(self._input_process_id)
        elif self._command_line:
            logging.error("_start_debugging self._command_line=%s" % self._command_line)
            command_as_string = " ".join(self._command_line)
            self._root_pid = self._hooks_manager.attach_to_command(command_as_string, self._callback_process_creation)
        else:
            raise Exception("_start_debugging: command should not be None")

        logging.error("Win32Tracer._start_debugging FINISHED")
        self.report_function_call(self._function_name_process_exit, 0)
        # created_process.terminate()
        # created_process.join()

    def tee_calls_stream(self, log_stream, output_files_prefix):
        assert isinstance(log_stream, queue.Queue)

        class TeeQueue:
            def __init__(self):
                self._log_stream = log_stream
                assert output_files_prefix[-1] != '.'
                log_filename = output_files_prefix + ".log"
                self._out_file_descriptor = open(log_filename, "w")
                print("Creating log file:%s" % log_filename)

            def get(self, block=True, timeout=None):
                next_function_call = self._log_stream.get(block, timeout)
                assert isinstance(next_function_call, PseudoTraceLine)
                # When replaying, each line is deserialized into a PseudoTraceLine.
                next_function_call.write_to_file(self._out_file_descriptor)
                return next_function_call

        return TeeQueue()

    def create_logfile_stream(self, command_line, process_id):
        print("Win32Tracer.create_logfile_stream")
        print("Win32Tracer.create_logfile_stream command_line=", command_line)
        print("Win32Tracer.create_logfile_stream process_id=", process_id)
        assert isinstance(command_line, list)
        assert isinstance(process_id, int)
        assert (command_line == []) ^ (process_id < 0)
        logging.error("create_logfile_stream command_line=%s process_id=%d" % (command_line, process_id))

        self._hooks_manager = Win32Hook_Manager()
        self._command_line = command_line
        self._queue = queue.Queue()

        self._input_process_id = process_id
        if self._input_process_id < 0:
            # It is possible to start the process in a Python thread and resume it in another,
            # because these are not real threads. It might be possible to do that
            # in different threads, but it is better not to take the risk.
            logging.error("create_logfile_stream process will be started in thread")
            self._top_process_id = process_id * 100
            self._debugging_thread = threading.Thread(target=self._start_debugging, args=())
            self._debugging_thread.start()
            logging.error("Waiting for process id to be set")
            process_start_timeout = 10.0
            first_function_call = self._queue.get(True, timeout=process_start_timeout)
            assert isinstance(first_function_call, PseudoTraceLine)
            assert first_function_call.m_core.m_funcNam == self._function_name_process_start
            self._top_process_id = first_function_call.m_core.m_pid
        else:
            self._top_process_id = process_id

        # return self._top_process_id, self.QueueToStreamAdapter(self._queue)
        return self._top_process_id, self._queue

    # Used when replaying a trace session. This returns an object, on which each read access
    # return a conceptual function call, similar to what is returned when monitoring a process.
    def logfile_pathname_to_stream(self, input_log_file):
        class ReplayStream:
            def __init__(self):
                self._in_file_descriptor = open(input_log_file)

            def get(self, block=True, timeout=None):
                next_function_call = PseudoTraceLine.read_from_file(self._in_file_descriptor)
                return next_function_call

        return ReplayStream()

    # This yields objects which model a function call.
    def create_flows_from_calls_stream(self, log_stream):
        # TODO: So why not simply returning self instead of the queue ?
        logging.error("create_flows_from_calls_stream log_stream=%s" % log_stream.__class__.__name__)
        #exit(0)
        # TeeStream
        # assert isinstance(log_stream, self.QueueToStreamAdapter)

        #self._debugging_thread = threading.Thread(target=self._start_debugging, args=())
        #self._debugging_thread.start()

        queue_timeout = 10.0  # Seconds.

        while True:
            try:
                # We could use the queue to signal the end of the loop.
                pseudo_trace_line = log_stream.get(True, timeout=queue_timeout)
            except queue.Empty:
                logging.info("Win32Tracer.create_flows_from_calls_stream timeout. Waiting.")
                continue
            print("create_flows_from_calls_stream Function=", pseudo_trace_line.m_core.m_funcNam)
            assert isinstance(pseudo_trace_line, PseudoTraceLine)

            if pseudo_trace_line.m_core.m_funcNam == self._function_name_process_exit:
                print("create_flows_from_calls_stream LEAVING")
                return

            yield pseudo_trace_line

    def report_function_call(self, function_name, task_id):
        logging.info("function_name=%s" % function_name)

        batch_core = PseudoTraceLine(task_id, function_name)
        self._queue.put(batch_core)

    def report_object_creation(self, cim_objects_context, cim_class_name, **cim_arguments):
        logging.debug("report_object_creation", cim_class_name, cim_arguments)
        cim_objects_context.attributes_to_cim_object(cim_class_name, **cim_arguments)


# This must be replaced by an object of a derived class.
tracer_object = None # Win32Tracer()

################################################################################
class Win32Hook_Manager(object):
    # The style tells if this is a native call or an aggregate of function
    # calls, made with some style: Factorization etc...
    def __init__(self):
        self.m_core = None
        self.object_pydbg = pydbg.pydbg()

        # So it can be found from the callbacks.
        self.object_pydbg.hook_manager = self

        self.object_hooks = utils.hook_container()

        self.unhooked_functions_by_dll = collections.defaultdict(list)

        # This event is received after the DLL is mapped into the address space of the debuggee.
        self.object_pydbg.set_callback(defines.LOAD_DLL_DEBUG_EVENT, self._functions_hooking_load_dll_callback)

        # This is a dict of Win32Hook_Manager indxed by the subprocess id.
        self.subprocesses_managers = dict()

    def add_one_function_from_dll_address(self, dll_address, the_subclass):

        the_subclass.function_address = self.object_pydbg.func_resolve_from_dll(dll_address, the_subclass.function_name)
        assert the_subclass.function_address

        # There is one such function per class associated to an API function.
        # The arguments are stored per thread, and implictly form a stack.
        def hook_function_adapter_entry(object_pydbg, function_arguments):
            logging.debug("hook_function_adapter_entry", the_subclass.__name__, function_arguments)
            subclass_instance = the_subclass()
            subclass_instance.set_current_pydbg(object_pydbg)

            # This instance object has the same visibility and scope than the arguments.
            # Therefore, they are stored together with a hack of appending the instance
            # at the arguments'end.
            # This instance is a context for the results of anything done before the function call.
            subclass_instance.callback_before(function_arguments)
            function_arguments.append(subclass_instance)
            tracer_object.report_function_call(the_subclass.function_name, object_pydbg.dbg.dwProcessId)
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
    def _functions_hooking_load_dll_callback(object_pydbg):
        # self.dbg.u.LoadDll is _LOAD_DLL_DEBUG_INFO
        dll_filename = win32file.GetFinalPathNameByHandle(
            object_pydbg.dbg.u.LoadDll.hFile, win32con.FILE_NAME_NORMALIZED)
        if dll_filename.startswith("\\\\?\\"):
            dll_filename = dll_filename[4:]
        assert isinstance(dll_filename, six.text_type)
        print("_functions_hooking_load_dll_callback dll_filename=", dll_filename)

        dll_canonic_name = object_pydbg.canonic_dll_name(dll_filename.encode('utf-8'))

        # At this stage, the library cannot be found with CreateToolhelp32Snapshot,
        #  and Module32First/Module32Next. But the dll object is passed to the callback.
        dll_address = object_pydbg.dbg.u.LoadDll.lpBaseOfDll
        for one_subclass in object_pydbg.hook_manager.unhooked_functions_by_dll.get(dll_canonic_name, []):
            object_pydbg.hook_manager.add_one_function_from_dll_address(dll_address, one_subclass)

        return defines.DBG_CONTINUE

    # This is called when looping on the list of semantically interesting functions.
    def _hook_api_function(self, the_subclass):
        logging.debug("hook_api_function:%s" % the_subclass.__name__)
        the_subclass._parse_text_definition(the_subclass)

        # dll_canonic_name = os.path.basename(the_subclass.dll_name).upper()
        dll_canonic_name = self.object_pydbg.canonic_dll_name(the_subclass.dll_name)

        dll_address = self.object_pydbg.find_dll_base_address(dll_canonic_name)

        # If the DLL is already loaded.
        if dll_address:
            self.add_one_function_from_dll_address(dll_address, the_subclass)
        else:
            self.unhooked_functions_by_dll[dll_canonic_name].append(the_subclass)

    def _hook_api_functions_list(self):
        for the_subclass in _functions_list:
            self._hook_api_function(the_subclass)

    def attach_to_pid(self, process_id):
        self.object_pydbg.attach(process_id)
        self._hook_api_functions_list()
        self.object_pydbg.run()

    # This receives a command line, starts the process in suspended mode,
    # stores the desired breakpoints, in a map indexed by the DLL name,
    # then resumes the process.
    # When the DLLs are loaded, a callback sets their breakpoints.
    def attach_to_command(self, command_line, callback_process_creation = None):
        logging.error("attach_to_command command_line=%s" % command_line)
        start_info = win32process.STARTUPINFO()
        start_info.dwFlags = win32con.STARTF_USESHOWWINDOW

        hProcess, hThread, dwProcessId, dwThreadId = win32process.CreateProcess(
            None, command_line, None, None, False,
            win32con.CREATE_SUSPENDED, None,
            os.getcwd(), start_info)
        logging.error("attach_to_command dwProcessId=%s" % dwProcessId)

        if callback_process_creation:
            callback_process_creation(dwProcessId)

        cim_objects_definitions.G_topProcessId = dwProcessId
        self.object_pydbg.attach(dwProcessId)
        self._hook_api_functions_list()
        win32process.ResumeThread(hThread)
        self.object_pydbg.run()
        return dwProcessId

################################################################################

# Each derived class must have:
# - The string api_definition="" which contains the signature of the Windows API
#   function in Windows web site format.
class Win32Hook_BaseClass(object):
    # The style tells if this is a native call or an aggregate of function
    # calls, made with some style: Factorization etc...
    def __init__(self):
        self.m_core = None
        self.current_pydbg = None

    # Possible optimisation: If this function is not implemented,
    # no need to create a subclass instance.
    def callback_before(self, function_arguments):
        pass

    def callback_after(self, function_arguments, function_result):
        pass

    def cim_context(self):
        return cim_objects_definitions.ObjectsContext(self.current_pydbg.dbg.dwProcessId)

    def set_current_pydbg(self, current_pydbg):
        self.current_pydbg = current_pydbg

    # The API signature is taken "as is" from Microsoft web site.
    # There are many functions and copying their signature is error-prone.
    # Therefore, one just needs to copy-paste the zweb site text.
    @staticmethod
    def _parse_text_definition(the_class):
        match_one = re.match(br"\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*\((.*)\)\s*;", the_class.api_definition, re.DOTALL)
        if not match_one:
            raise Exception("Cannot parse api definition:%s" % the_class.api_definition)
        the_class.return_type = match_one.group(1)
        the_class.function_name = match_one.group(2)
        logging.debug("_parse_text_definition %s %s" % (the_class.__name__, the_class.function_name))

        the_class.args_list = []
        for one_arg_pair in match_one.group(3).split(b","):
            match_pair = re.match(br"\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s*", one_arg_pair)
            the_class.args_list.append((match_pair.group(1), match_pair.group(2)))

        assert isinstance(the_class.function_name, six.binary_type)

    def callback_create_object(self, cim_class_name, **cim_arguments):
        tracer_object.report_object_creation(self.cim_context(), cim_class_name, **cim_arguments)

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

    def __init__(self):
        print("Win32Hook_CreateProcessW.__init__")

    def callback_before(self, function_arguments):
        dwCreationFlags = function_arguments[5]
        print("Win32Hook_CreateProcessW.callback_before dwCreationFlags = %0x." % dwCreationFlags)
        # This should be the case most of times,
        # because it is very rare that a user process starts in suspended state.
        self.process_is_not_suspended = ~(dwCreationFlags & win32con.CREATE_SUSPENDED)
        if self.process_is_not_suspended:
            print("Win32Hook_CreateProcessW.callback_before : Suspending process")
            dwCreationFlagsSuspended = dwCreationFlags | win32con.CREATE_SUSPENDED
            self.current_pydbg.set_arg(5, dwCreationFlagsSuspended)


    def callback_after(self, function_arguments, function_result):
        lpApplicationName = self.current_pydbg.get_unicode_string(function_arguments[0])
        lpCommandLine = self.current_pydbg.get_unicode_string(function_arguments[1])
        print("callback_after lpCommandLine=", lpCommandLine, "function_result", function_result)

        # typedef struct _PROCESS_INFORMATION {
        #   HANDLE hProcess;
        #   HANDLE hThread;
        #   DWORD  dwProcessId;
        #   DWORD  dwThreadId;
        # } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
        lpProcessInformation = function_arguments[9]

        hProcess = self.current_pydbg.get_pointer(lpProcessInformation)

        offset_hThread = windows_h.sizeof(windows_h.HANDLE)
        hThread = self.current_pydbg.get_pointer(lpProcessInformation + offset_hThread)

        offset_dwProcessId = windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.HANDLE)
        dwProcessId = self.current_pydbg.get_long(lpProcessInformation + offset_dwProcessId)

        offset_dwThreadId = windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.HANDLE) + windows_h.sizeof(windows_h.DWORD)
        dwThreadId = self.current_pydbg.get_long(lpProcessInformation + offset_dwThreadId)

        self.callback_create_object("CIM_Process", Handle=dwProcessId)

        if self.process_is_not_suspended:
            print("Win32Hook_CreateProcessW: Setting breakpoints in suspended thread:", dwThreadId)

            if True:
                sub_hooks_manager = Win32Hook_Manager()
                # The same breakpoints are used by all threads of the same subprocess.
                self.current_pydbg.hook_manager.subprocesses_managers[dwProcessId] = sub_hooks_manager

                try:
                    sub_hooks_manager.attach_to_pid(dwProcessId)
                except Exception as exc:
                    # Cannot attach to some subprocesses:
                    # ping  -n 1 127.0.0.1
                    #
                    print("CANNOT ATTACH TO", dwProcessId, lpCommandLine, exc)

            # FIXME: It is not possible to call pywin32 with these handles. Why ??
            print("Win32Hook_CreateProcessW: Resuming thread:", dwThreadId)
            self.current_pydbg.resume_thread(dwThreadId)


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
        buffer = self.current_pydbg.get_bytes_size(lpBuffer, nNumberOfBytesToWrite)
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

class Win32Hook_connect(Win32Hook_BaseClass):
    api_definition = b"""
        int connect(
            SOCKET         s,
            sockaddr_cptr  name,
            int            namelen
        );"""
    dll_name = b"ws2_32.dll"
    def callback_after(self, function_arguments, function_result):
        logging.debug("Win32Hook_connect function_arguments=", function_arguments)
        sockaddr_address = function_arguments[1]

        sin_family_memory = self.current_pydbg.read_process_memory(sockaddr_address, 2)
        print("sin_family_memory=", sin_family_memory, len(sin_family_memory))

        sin_family = struct.unpack("<H", sin_family_memory)[0]

        print("sin_family=", sin_family)
        sockaddr_size = function_arguments[2]
        print("size=", function_arguments[2])

        # AF_INET = 2, if this is an IPV4 DNS server.
        if sin_family == defines.AF_INET:
            # struct sockaddr_in {
            #         short   sin_family;
            #         u_short sin_port;
            #         struct  in_addr sin_addr;
            #         char    sin_zero[8];
            # };
            # struct in_addr {
            #   union {
            #     struct {
            #       u_char s_b1;
            #       u_char s_b2;
            #       u_char s_b3;
            #       u_char s_b4;
            #     } S_un_b;
            #     struct {
            #       u_short s_w1;
            #       u_short s_w2;
            #     } S_un_w;
            #     u_long S_addr;
            #   } S_un;
            # };
            ip_port_memory = self.current_pydbg.read_process_memory(sockaddr_address + 2, 2)
            port_number = struct.unpack(">H", ip_port_memory)[0]

            assert sockaddr_size == 16

            s_addr_ipv4 = self.current_pydbg.read_process_memory(sockaddr_address + 4, 4)
            if is_py3:
                addr_ipv4 = ".".join(["%d" % int(one_byte) for one_byte in s_addr_ipv4])
            else:
                addr_ipv4 = ".".join(["%d" % ord(one_byte) for one_byte in s_addr_ipv4])
            self.callback_create_object("addr", Id="%s:%d" % (addr_ipv4, port_number))

        # AF_INET6 = 23, if this is an IPV6 DNS server.
        elif sin_family == defines.AF_INET6:
            # struct sockaddr_in6 {
            #      sa_family_t     sin6_family;   /* AF_INET6 */
            #      in_port_t       sin6_port;     /* port number */
            #      uint32_t        sin6_flowinfo; /* IPv6 flow information */
            #      struct in6_addr sin6_addr;     /* IPv6 address */
            #      uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
            #  };
            #
            # struct in6_addr {
            #      unsigned char   s6_addr[16];   /* IPv6 address */
            # };
            ip_port_memory = self.current_pydbg.read_process_memory(sockaddr_address + 2, 2)
            port_number = struct.unpack(">H", ip_port_memory)[0]

            assert sockaddr_size == 28

            s_addr_ipv6 = self.current_pydbg.read_process_memory(sockaddr_address + 8, 16)
            if is_py3:
                addr_ipv6 = str(s_addr_ipv6)
            else:
                addr_ipv6 = "".join(["%02x" % ord(one_byte) for one_byte in s_addr_ipv6])

            self.callback_create_object("addr", Id="%s:%d" % (addr_ipv6, port_number))

        else:
            raise Exception("Invalid sa_family:%d" % sin_family)

if False:
    class Win32Hook_ExitProcess(Win32Hook_BaseClass):
        # FIXME: This crashes with the message:
        # python.exe - Entry Point Not Found
        # The procedure entry point <utf8>DLL.RtlExitUserProcess could not be located
        # in the dynamic link library API-MS-Win-Core-ProcessThreads-L1-1-0.dll.
        api_definition = b"""
            void ExitProcess(
                UINT uExitCode
            );"""
        dll_name = b"KERNEL32.dll"
        # TODO: Must find the data structure associated to its process at creation time.

windows8_or_higher = os.sys.getwindowsversion() != (6, 1, 7601, 2, 'Service Pack 1')

if windows8_or_higher:

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


################################################################################

# This returns only leaf classes.
def all_subclasses(the_class):
    # Minimum supported client 	Windows 8 [desktop apps | UWP apps]
    # Minimum supported server 	Windows Server 2012 [desktop apps | UWP apps]
    # Travis is Windows Server 1809 (2019 ?)
    # os.sys.getwindowsversion()
    # (6, 0, 6002, 2, 'Service Pack 2')
    # platform.release()
    # 'Vista'
    # platform.win32_ver()
    # ('Vista', '6.0.6002', 'SP2', 'Multiprocessor Free')

# Travis:
# survol\scripts\wsgiserver.py server_name=packer-5e27ace7-7289-64cc-b5e7-c83abe164ad0
# Platform=win32
# Version:sys.version_info(major=3, minor=7, micro=5, releaselevel='final', serial=0)
# Server address:10.20.0.174

    current_subclasses = the_class.__subclasses__()
    return set([sub_class for sub_class in current_subclasses if not all_subclasses(sub_class)]).union(
        [sub_sub_class for sub_class in current_subclasses for sub_sub_class in all_subclasses(sub_class)])

_functions_list = all_subclasses(Win32Hook_BaseClass)

##### Kernel32.dll
# Many functions are very specific to old-style Windows applications.
# Still, this is the only way to track specific behaviour.
# Which function for opening files, is called by the Python interpreter on Travis ?
#
# CopyFileA
# CopyFileW
# CopyFileExA
# CopyFileExW
# CopyFileTransactedA
# CopyFileTransactedW
# CopyLZFile

# CreateHardLink A/W/TransactedA/TransactedW
# CreateNamedPipe A/W

# LoadLibrary

# MapViewOfIle ?

# MoveFile ...

# OpenFile, OpenFileById
# ReOpenFile

# ReplaceFile, A, W

# OpenJobObjects

##### KernelBase.dll
# Looks like a subset of Kernel32.dll

##### ntdll.dll
# NtOpenFile
# NtOpenDirectoryObject ?


