#!/usr/bin/env python

"""Monitors living processes and generates a dockerfile And much more."""

# NOTE: For convenience purpose, this script is standalone, and therefore quite big.
# Requires Python 2.7 or later.

from __future__ import print_function

__author__      = "Remi Chateauneu"
__copyright__   = "Primhill Computers, 2018-2023"
__credits__ = ["","",""]
__license__ = "GPL"
__version__ = "0.0.1"
__maintainer__ = "Remi Chateauneu"
__email__ = "contact@primhillcomputers.com"
__status__ = "Development"

import re
import sys
import getopt
import os
import subprocess
import time
import inspect
import socket
import json
import atexit
import shutil
import tempfile
import logging
import platform
import pkgutil

# This defines the CIM objects which are created when monitoring a running process.
if __package__:
    from . import cim_objects_definitions
else:
    import cim_objects_definitions

is_platform_windows = sys.platform.startswith("win32")
is_platform_linux = sys.platform.startswith("linux")
is_py3 = sys.version_info >= (3,)

# Another possible test is: pkgutil.find_loader('win32file')
is_pypy = platform.python_implementation() == "PyPy"

################################################################################

G_traceToTracer = {}

# TODO: Should be done on Linux only.
if __package__:
    from . import linux_api_definitions
else:
    import linux_api_definitions

# This contains the definitions of Linux system calls, and other things.
G_traceToTracer["strace"] = linux_api_definitions.STraceTracer()
G_traceToTracer["ltrace"] = linux_api_definitions.LTraceTracer()

if is_platform_windows and not is_pypy:
    # Definitions of Win32 systems calls to monitor.
    if __package__:
        from . import win32_api_definitions
    else:
        import win32_api_definitions
    win32_api_definitions.tracer_object = win32_api_definitions.Win32Tracer()
    G_traceToTracer["pydbg"] = win32_api_definitions.tracer_object

################################################################################


def print_dockit_usage(exit_code=1, error_message=None):
    if error_message:
        print(error_message)

    prog_nam = sys.argv[0]
    print("DockIT: %s <executable>" % prog_nam)
    print("Monitors and factorizes systems calls.")
    print("  -h,--help                       This message.")
    print("  -v,--verbose                    Verbose mode (Cumulative).")
    print("  -w,--warning                    Displays warnings (Cumulative).")
    print("  -s,--summary <CIM class>        Prints a summary at the end: Start end end time stamps, executable name,\n"
        + "                                  loaded libraries, read/written/created files and timestamps, subprocesses tree.\n"
        + "                                  Examples: -s 'Win32_LogicalDisk.DeviceID=\"C:\",Prop1=\"Value1\",Prop2=\"Value2\"'\n"
        + "                                            -s 'CIM_DataFile:Category=[\"Others\",\"Shared libraries\"]'" )
    print("  -D,--dockerfile                 Generates a dockerfile.")
    print("  -M,--makefile <makefile name>   Generates a makefile.")
    print("  -p,--pid <pid>                  Monitors a running process instead of starting an executable.")
    print("  -f,--format TXT|CSV|JSON        Output format. Default is TXT.")
    print("  -F,--summary-format TXT|XML     Summary output format. Default is XML.")
    print("  -i,--input <file name>          Trace input log file for replaying a session.")
    print("  -l,--log <filename prefix>      Directory and prefix of output files.")
    print("  -t,--tracer strace|ltrace|pydbg Set trace program.")
    print("  -S,--server <Url>               Survol url for CIM objects updates. Ex: http://127.0.0.1:80/survol/event_put.py")
    print("  -a,--aggregator <aggregator>    Aggregation method, e.g. 'clusterize' etc...")
    print("  -d,--log                        Duplicates session to a log file which can be replayed as input.")

    print("")

    if is_platform_linux:
        trace_ltrace = G_traceToTracer["ltrace"]
        print("ltrace command: " + " ".join(trace_ltrace.build_trace_command(["<command>"], None)))
        print("                " + " ".join(trace_ltrace.build_trace_command(None, "<pid>")))
        print("version       : " + str(trace_ltrace.trace_software_version()))
        print("")
        trace_strace = G_traceToTracer["strace"]
        print("strace command: " + " ".join(trace_strace.build_trace_command(["<command>"], None)))
        print("                " + " ".join(trace_strace.build_trace_command(None, "<pid>")))
        print("version       : " + str(trace_strace.trace_software_version()))
        if trace_strace.deprecated_version():
            print("strace version deprecated. Consider upgrading")
        print("")

    # Special value just for testing.
    if exit_code != 999:
        sys.exit(exit_code)

################################################################################


def _parse_filter_CIM(rgx_object_path):
    """
    This receives an array of WMI/WBEM/CIM object paths:
    'Win32_LogicalDisk.DeviceID="C:"'
    The values can be regular expressions.
    key-value pairs in the expressions are matched one-to-one with objects.

    Example: rgx_object_path = 'Win32_LogicalDisk.DeviceID="C:",Prop="Value",Prop="Regex"'
    """
    idx_dot = rgx_object_path.find(".")
    if idx_dot < 0:
        return rgx_object_path, {}

    obj_class_name = rgx_object_path[:idx_dot]

    # Maybe the input string is just the class name, with nothing after the dot.
    if idx_dot == len(rgx_object_path)-1:
        return obj_class_name, {}

    str_key_values = rgx_object_path[idx_dot + 1:]

    # This transforms the concatenation of key-value pairs into a function signature, and it is parsed by Python.
    # Example:
    #     def xxx(a='1',b='2')
    #     >>> inspect.getargspec(xxx)
    #     ArgSpec(args=['a', 'b'], varargs=None, keywords=None, defaults=('1', '2'))
    tmp_func = "def aTempFunc(%s) : pass" % str_key_values

    exec(tmp_func)
    local_temp_func = locals()["aTempFunc"]
    if is_py3:
        tmp_insp = inspect.getfullargspec(local_temp_func)
    else:
        tmp_insp = inspect.getargspec(local_temp_func)
    list_keys = tmp_insp.args
    list_vals = tmp_insp.defaults
    map_key_values = dict(zip(list_keys, list_vals))

    return obj_class_name, map_key_values


# TODO: Probably not needed because noone wants this output format..
def _generate_summary_txt(map_params_summary, fd_summary_file):
    for rgx_object_path in map_params_summary:
        cim_class_name, cim_key_value_pairs = _parse_filter_CIM(rgx_object_path)
        class_obj = getattr(cim_objects_definitions, cim_class_name)
        class_obj.DisplaySummary(fd_summary_file, cim_key_value_pairs)


def _generate_summary_xml(map_params_summary, fd_summary_file):
    """This stores various data related to the execution."""
    fd_summary_file.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fd_summary_file.write('<Dockit>\n')
    if map_params_summary:
        for rgx_object_path in map_params_summary:
            cim_class_name, cim_key_value_pairs = _parse_filter_CIM(rgx_object_path)
            class_obj = getattr(cim_objects_definitions, cim_class_name)
            class_obj.XMLSummary(fd_summary_file, cim_key_value_pairs)
    fd_summary_file.write('</Dockit>\n')


def _generate_summary(map_params_summary, summary_format, output_summary_file):
    if summary_format == "TXT":
        summary_generator = _generate_summary_txt
    elif summary_format == "XML":
        # The output format is very different.
        summary_generator = _generate_summary_xml
    elif summary_format == None:
        return
    else:
        raise Exception("Unsupported summary output format:%s" % summary_format)

    if output_summary_file:
        fd_summary_file = open(output_summary_file, "w")
        sys.stdout.write("Creating summary file:%s\n" % output_summary_file)
    else:
        fd_summary_file = sys.stdout

    summary_generator(map_params_summary, fd_summary_file)

    if output_summary_file:
        sys.stdout.write("Closing summary file:%s\n" % output_summary_file)
        fd_summary_file.close()


################################################################################

class FileToPackage:
    """
    This stores, on Linux, the package from where a file came from.
    So, in Docker, a file used by a process is not copied, but its package installed.
    """
    def __init__(self):
        the_temp_dir = tempfile.gettempdir()
        # This file stores and reuses the map from file name to Linux package.
        self.m_cacheFileName = the_temp_dir + "/" + "FileToPackageCache." + socket.gethostname() + ".txt"
        try:
            fd_cache = open(self.m_cacheFileName, "r")
        except:
            logging.info("Cannot open packages cache file:%s." % self.m_cacheFileName)
            self.m_cacheFilesToPackages = dict()
            self.m_dirtyCache = False
            return

        try:
            self.m_cacheFilesToPackages = json.load(fd_cache)
            fd_cache.close()
            self.m_dirtyCache = False
            logging.info("Loaded packages cache file:%s" % self.m_cacheFileName)
        except:
            logging.warning("Error reading packages cache file:%s. Resetting." % self.m_cacheFileName)
            self.m_cacheFilesToPackages = dict()
            self.m_dirtyCache = True

    def dump_cache_to_file(self):
        """Dump cache to a file. It does not use __del__()
        because it cannot access some global names in recent versions of Python."""
        if self.m_dirtyCache:
            try:
                fd_cache = open(self.m_cacheFileName, "w")
                logging.info("Dumping to packages cache file %s" % self.m_cacheFileName)
                json.dump(self.m_cacheFilesToPackages, fd_cache)
                fd_cache.close()
            except IOError:
                raise Exception("Cannot dump packages cache file to %s" % self.m_cacheFileName)

    @staticmethod
    def _one_file_to_linux_package_no_cache(one_fil_nam):
        if is_platform_linux:
            a_cmd = ['rpm', '-qf', one_fil_nam]

            try:
                a_pop = subprocess.Popen(a_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                an_out, an_err = a_pop.communicate()
                a_pack = an_out
                a_pack = a_pack.strip()
                if a_pack.endswith("is not owned by any package"):
                    lst_packs = []
                elif a_pack == "":
                    lst_packs = []
                else:
                    lst_packs = a_pack.split("\n")
                    if lst_packs[0] == "":
                        raise Exception("Inserting invalid package")
                return lst_packs
            except:
                return []
        else:
            return None

    unpackaged_prefixes = (
                             "/home/",
                             "/tmp/",
                             "/sys/",
                             "/var/cache/") + cim_objects_definitions.CIM_DataFile.m_non_file_prefixes

    @staticmethod
    def _cannot_be_packaged(fil_nam):
        """Some files cannot be packaged, ever: System files, devices etc..."""
        return fil_nam.startswith(FileToPackage.unpackaged_prefixes)

    def one_file_to_linux_package(self, one_fil_obj):
        one_fil_nam = one_fil_obj.Name

        # Very common case of a file which is only local.
        if FileToPackage._cannot_be_packaged(one_fil_nam):
            return []
        try:
            return self.m_cacheFilesToPackages[one_fil_nam]
        except KeyError:
            lst_packs= self._one_file_to_linux_package_no_cache(one_fil_nam)

            if lst_packs:
                self.m_dirtyCache = True

            # TODO: Optimisation: Once we have detected a file of a package,
            # TODO: this loads all files from this package because reasonably, there will be other files from it.
            # rpm -qf /usr/lib64/libselinux.so.1
            # rpm -q -l libselinux-2.6-6.fc26.x86_64
            self.m_cacheFilesToPackages[one_fil_nam] = lst_packs

            return lst_packs

    def get_packages_list(self, lst_packaged_files):

        # This command is very slow:
        # dnf provides /usr/bin/as

        # This is quite fast:
        # rpm -qf /bin/ls

        lst_packages = set()
        unknown_files = []

        for one_fil in lst_packaged_files:
            # sys.stdout.write("one_fil=%s tp=%s\n"%(one_fil,str(type(one_fil))))
            lst_packs = self.one_file_to_linux_package(one_fil)
            if lst_packs:
                # BEWARE: This takes the first pack, randomly.
                a_pack = lst_packs[0]
                if a_pack == "":
                    raise Exception("Invalid package for file=%s\n" % one_fil)
                lst_packages.add(a_pack)
            else:
                unknown_files.append(one_fil)
        return lst_packages, unknown_files


# We can keep the same cache for all simulations because
# they were all run on the same machine.
cim_objects_definitions.G_FilesToPackagesCache = FileToPackage()

atexit.register(FileToPackage.dump_cache_to_file, cim_objects_definitions.G_FilesToPackagesCache)


################################################################################

# Formatting function specific to TXT mode output file.ExceptionIsExit
def _format_time(a_timestamp):
    return a_timestamp


class BatchDumperBase:
    def document_start(self):
        return

    def document_end(self):
        return

    def flow_header(self, **flow_kwargs):
        return

    def flow_footer(self):
        return


class BatchDumperTXT(BatchDumperBase):
    def __init__(self, strm):
        self.m_strm = strm

    def flow_header(self, **flow_kwargs):
        for flow_key in sorted(flow_kwargs):
            flow_value = flow_kwargs[flow_key]
            self.m_strm.write("%s:%s\n" % (flow_key, flow_value))

    def dump_batch_to_stream(self, batchLet):
        self.m_strm.write("Pid=%6d {%4d/%s}%1s'%-20s' %s ==>> %s (%s,%s)\n" % (
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            linux_api_definitions.BatchStatus.chrDisplayCodes[batchLet.m_core.m_status],
            batchLet.m_core._function_name,
            batchLet.get_significant_args(),
            batchLet.m_core._return_value,
            _format_time(batchLet.m_core._time_start),
            _format_time(batchLet.m_core._time_end)))


class BatchDumperCSV(BatchDumperBase):
    def __init__(self, strm):
        self.m_strm = strm

    def flow_header(self, **flow_kwargs):
        for flow_key in sorted(flow_kwargs):
            flow_value = flow_kwargs[flow_key]
            self.m_strm.write("%s:%s\n" % (flow_key, flow_value))
        self.m_strm.write("Pid,Occurrences,Style,Function,Arguments,Return,Start,End\n")

    def dump_batch_to_stream(self, batchLet):
        self.m_strm.write("%d,%d,%s,%s,%s,%s,%s,%s,%s\n" % (
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            batchLet.m_core.m_status,
            batchLet.m_core._function_name,
            batchLet.get_significant_args(),
            batchLet.m_core._return_value,
            _format_time(batchLet.m_core._time_start),
            _format_time(batchLet.m_core._time_end)))


# TODO: Must use json package.
class BatchDumperJSON(BatchDumperBase):
    def __init__(self, strm):
        self.m_strm = strm

    def document_start(self):
        self.m_strm.write('[\n')
        self.m_top_delimiter = ""

    def document_end(self):
        self.m_strm.write(']\n')

    def flow_header(self, **flow_kwargs):
        self.m_strm.write(self.m_top_delimiter + '[\n')
        self.m_delimiter = ""
        self.m_top_delimiter = ","

    def dump_batch_to_stream(self, batchLet):
        # TODO: This is needed because function names are always binary_types in win32.
        # TODO: This should be changed to "str" on all platforms.
        unicode_class = str if is_py3 else unicode
        if isinstance(batchLet.m_core._function_name, unicode_class):
            function_name = batchLet.m_core._function_name
        else:
            function_name = batchLet.m_core._function_name.decode("utf-8")

        self.m_strm.write(
            self.m_delimiter + '{\n'
            '   "pid" : %d,\n'
            '   "occurrences" : %d,\n'
            '   "style" : "%s",\n'
            '   "status" : %d,\n'
            '   "function" : "%s",\n'
            '   "arguments" : %s,\n'
            '   "return_value" : %s,\n'
            '   "time_start" : "%s",\n'
            '   "time_end" : "%s"\n'
            '}\n' %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            batchLet.m_core.m_status,
            function_name,
            json.dumps([str(arg) for arg in batchLet.get_significant_args()]),
            json.dumps(batchLet.m_core._return_value), # It may contain double-quotes
            _format_time(batchLet.m_core._time_start),
            _format_time(batchLet.m_core._time_end)))
        self.m_delimiter = ","

    def flow_footer(self):
        self.m_strm.write(']\n')


################################################################################

__batch_dumpers_dictionary = {
    "TXT": BatchDumperTXT,
    "CSV": BatchDumperCSV,
    "JSON": BatchDumperJSON
}

################################################################################
# These global variables allow to better simulate the execution context
# when replaying a session.

G_Hostname = None

G_OSType = None

################################################################################


def ini_file_load(ini_pathname):
    """This file contains some extra details to replay a session with a log file."""
    assert ini_pathname.endswith(".ini")
    sys.stdout.write("Loading ini file:%s\n" % ini_pathname)
    ini_map_key_value_pairs = {}
    try:
        ini_file = open(ini_pathname)
        logging.info("Init " + ini_pathname)
    except IOError:
        sys.stdout.write("Error opening ini file:%s\n" % ini_pathname)
        return ini_map_key_value_pairs
    for line_key_value in ini_file.readlines():
        stripped_key_value = line_key_value.strip()
        if not stripped_key_value: continue
        if stripped_key_value[0] == ';': continue
        index_equal = stripped_key_value.find('=')
        if index_equal < 0: continue
        string_key = stripped_key_value[:index_equal]
        string_val = stripped_key_value[index_equal+1:]
        ini_map_key_value_pairs[string_key] = string_val
        sys.stdout.write("Init:%s=%s\n" % (string_key, string_val))
    sys.stdout.write("Closing ini file:%s\n" % ini_pathname)
    ini_file.close()
    return ini_map_key_value_pairs


def ini_file_check(ini_pathname):
    """This is purely for debugging and testing."""
    assert ini_pathname.endswith(".ini")
    ini_dict = ini_file_load(ini_pathname)
    assert int(ini_dict["TopProcessId"]) >= 0
    assert ini_dict["CurrentDirectory"]
    assert ini_dict["CurrentDate"] # Example "2020-05-17"
    assert ini_dict["CurrentHostname"]
    assert ini_dict["CurrentOSType"] in ["win32", "linux", "linux2"]
    return ini_dict


def _ini_file_create(output_files_prefix):
    ini_pathname = output_files_prefix + ".ini"
    sys.stdout.write("Creating ini file:%s\n" % ini_pathname)
    ini_file_descriptor = open(ini_pathname, "w")

    # At this stage, we know what is the top process id,
    # because the command is created, or the process attached.
    assert cim_objects_definitions.G_topProcessId >= 0
    ini_file_descriptor.write('TopProcessId=%s\n' % cim_objects_definitions.G_topProcessId)

    ini_file_descriptor.write('CurrentDirectory=%s\n' % os.getcwd())
    # Necessary because ltrace and strace do not write the date.
    # Done before testing in case the test stops next day.
    ini_file_descriptor.write('CurrentDate=%s\n' % cim_objects_definitions.G_Today)
    ini_file_descriptor.write('CurrentHostname=%s\n' % socket.gethostname())
    ini_file_descriptor.write('CurrentOSType=%s\n' % sys.platform)
    ini_file_descriptor.close()


################################################################################

def default_tracer(input_log_file, tracer=None):
    """Rule-of-thumb method to deduce the tracer type given the log file."""
    if not tracer:
        if input_log_file:
            # Maybe the pid is embedded in the log file.
            match_trace = re.match(r".*\.([^\.]*)\.[0-9]+\.log", input_log_file)
            if match_trace:
                tracer = match_trace.group(1)
            else:
                # The file format might be "xyzxyz.strace.log", "abcabc.ltrace.log", "123123.cdb.log"
                # depending on the tool which generated the log.
                match_trace = re.match(r".*\.([^\.]*)\.log", input_log_file)
                if not match_trace:
                    raise Exception("Cannot read tracer from log file name:%s" % input_log_file)
                tracer = match_trace.group(1)
        else:
            if is_platform_windows:
                tracer = "pydbg"
            elif is_platform_linux:
                # This could also be "ltrace", but "strace" is more usual.
                tracer = "strace"
            else:
                raise Exception("Unknown platform")
    logging.info("Tracer " + tracer)
    return tracer


def _create_calls_stream(command_line, input_process_id, input_log_file, tracer):
    """
    This returns a stream with each line written by strace or ltrace,
    or a mock "stream" when tracing Windows processes.
    This stream needs only the method readline(), exactly like reading from subprocess.communicate.
    """
    global G_Hostname
    global G_OSType

    logging.info("command_line=%s input_process_id=%d" % (command_line, input_process_id))
    # A command or a pid or an input log file, only one possibility.
    # A non-defined command is an empty list.
    assert isinstance(command_line, list)
    if command_line:
        if input_process_id > 0 or input_log_file:
            print_dockit_usage(1, "When providing command, must not specify process id or input log file")
        logging.info("_create_calls_stream command line mode")
    elif input_process_id > 0:
        if command_line:
            print_dockit_usage(1, "When providing process id, must not specify command or input log file")
        logging.info("_create_calls_stream command attach mode")
    elif input_log_file:
        if command_line:
            print_dockit_usage(1, "When providing input file, must not specify command or process id")
        # This is a replay from a log file, possibly on another machine or operating system.
        # It is not possible to enhance the log file information by querying the current machine.
        # Therefore, to replay the test, some extra information might be stored in the .ini file.
        # Also, it is not possible to control the line terminator of the log file which may be
        # a Unix or a Windows line terminator. This might be changed by GOT or a text editor.
        logging.info("_create_calls_stream command replay mode")
        cim_objects_definitions.local_standardized_file_path = cim_objects_definitions.standardized_file_path_syntax_only
    else:
        print_dockit_usage(1, "Must provide command, pid or input file")

    date_today_run = time.strftime("%Y-%m-%d")
    the_host_nam = socket.gethostname()
    the_ip_address = socket.gethostbyname(the_host_nam)
    the_platform = sys.platform

    curr_wrk_dir = os.getcwd()

    cim_objects_definitions.G_ReplayMode = True if input_log_file else False
    cim_objects_definitions.G_SameMachine = not cim_objects_definitions.G_ReplayMode or G_Hostname == socket.gethostname()

    with_warning = True # FIXME: Must be a parameter.

    current_tracer = G_traceToTracer[tracer]
    if cim_objects_definitions.G_ReplayMode:
        calls_stream = current_tracer.logfile_pathname_to_stream(input_log_file)
        logging.info("File " + input_log_file)
        logging.info("Logfile %s pid=%s" % (input_log_file, input_process_id))

        # There might be a context file with important information to reproduce the test.
        context_log_file = os.path.splitext(input_log_file)[0] + ".ini"
        map_env_init_values = ini_file_load(context_log_file)

        # The main process pid might be embedded in the log file name,
        # but preferably stored in the ini file.
        cim_objects_definitions.G_topProcessId     = int(map_env_init_values.get("TopProcessId", input_process_id))

        cim_objects_definitions.G_CurrentDirectory = map_env_init_values.get("CurrentDirectory", curr_wrk_dir)
        cim_objects_definitions.G_Today            = map_env_init_values.get("CurrentDate", date_today_run)
        G_Hostname                                 = map_env_init_values.get("CurrentHostname", the_host_nam)
        the_ip_address                             = map_env_init_values.get("CurrentIPAddress", the_ip_address)
        G_OSType                                   = map_env_init_values.get("CurrentOSType", the_platform)

        logging.info("G_topProcessId=%d" % cim_objects_definitions.G_topProcessId)
    else:
        cim_objects_definitions.G_topProcessId, calls_stream= current_tracer.create_logfile_stream(
            command_line,
            input_process_id)
        cim_objects_definitions.G_CurrentDirectory          = curr_wrk_dir
        cim_objects_definitions.G_Today                     = date_today_run
        G_Hostname                                          = the_host_nam
        G_OSType                                            = the_platform
        assert cim_objects_definitions.G_topProcessId >= 0, "_create_calls_stream G_topProcessId not set"

    logging.info("Before init_linux_globals")
    # Global variables which must be reinitialised before a run, possibly from a ".ini" file.
    linux_api_definitions.init_linux_globals(with_warning)

    logging.info("Before init_global_objects")
    cim_objects_definitions.init_global_objects(G_Hostname, the_ip_address)
    logging.info("After init_global_objects")

    # Another possibility is to start a process or a thread which will monitor
    # the target process, and will write output information in a stream.

    return calls_stream


################################################################################

def _calls_flow_class_factory(aggregator):
    """
    The role of an aggregator is to receive each function call and store it or not.
    It can aggregate the calls or process them in anyway, on the fly or at the end.
    There is one object for each execution flow, which is a process or a thread.
    This method returns a class.
    """

    logging.info("aggregator=%s" % aggregator)
    if not aggregator:
        # This is the required interface for aggregators.
        # The default base class does minimal statistics.
        class BatchFlowVoid(object):
            def __init__(self):
                self.m_calls_number = 0

            # For each function call.
            def append_batch_to_flow(self, oneBatch):
                self.m_calls_number += 1

            # At the end.
            def factorise_one_flow(self, verbose, batch_constructor):
                pass

            def dump_flow_constructor(self, batch_dump, flow_process_id=None):
                batch_dump.flow_header(process_id=flow_process_id, calls_number=self.m_calls_number)
                # TODO: Reformat this information for JSON, TXT and CSV
                # FIXME: extra_header is probably never used.
                # batchDump.m_strm.write("%s\n" % extra_header)
                # batchDump.m_strm.write("Number of function calls: %d\n" % self.m_calls_number)
                logging.info("self.m_calls_number=%d" % self.m_calls_number)
                batch_dump.flow_footer()

        return BatchFlowVoid

    # This is temporary. Do this for each aggregator.
    if aggregator == "clusterize":
        if __package__:
            from . import dockit_aggregate_clusterize
        else:
            import dockit_aggregate_clusterize
        return dockit_aggregate_clusterize.BatchFlow

    raise Exception("Invalid aggregator:%s", aggregator)

################################################################################


def _create_map_flow_from_stream(
        verbose,
        calls_stream, tracer, batch_constructor, aggregator):
    """
    This receives a stream of lines, each of them is a function call,
    possibly unfinished/resumed/interrupted by a signal.
    These lines might also be read from a log file, to replay a session.
    """

    # This is an event log as a stream, coming from a file (if testing), the output of strace or anything else.
    logging.info("tracer=%s" % tracer)

    map_flows = {}

    CallsFlowClass = _calls_flow_class_factory(aggregator)

    logging.info("Created aggregator class")

    # This generator creates individual BatchLet objects on-the-fly.
    # At this stage, "resumed" calls are matched with the previously received "unfinished" line for the same call.
    # Some calls, for some reason, might stay "unfinished": Though,
    # they are still needed to rebuild the processes tree.
    map_flows_generator = G_traceToTracer[tracer].create_flows_from_calls_stream(calls_stream)

    # Maybe, some system calls are unfinished, i.e. the "resumed" part of the call is never seen.
    # They might be matched later.
    for one_function_call in map_flows_generator:
        a_core = one_function_call.m_core
        the_pid = a_core.m_pid
        try:
            calls_flow = map_flows[the_pid]
        except KeyError:
            # This is the first system call of this process.
            calls_flow = CallsFlowClass()
            map_flows[the_pid] = calls_flow

        calls_flow.append_batch_to_flow(one_function_call)

    for the_pid in sorted(list(map_flows.keys()), reverse=True):
        calls_flow = map_flows[the_pid]
        assert isinstance(calls_flow, CallsFlowClass)
        if verbose > 0: sys.stdout.write("\n------------------ PID=%d\n" % the_pid)
        calls_flow.factorise_one_flow(verbose, batch_constructor)

    cim_objects_definitions.exit_global_objects()

    # TODO: Should go in create_flows_from_calls_stream
    linux_api_definitions.G_stackUnfinishedBatches.display_unfinished_unmerged_batches(sys.stdout)
    return map_flows

################################################################################


# All possible summaries. Data created for the summaries are also needed
# to generate a docker file. So, summaries are calculated if Dockerfile is asked.
full_map_params_summary = [
    "CIM_ComputerSystem",
    "CIM_OperatingSystem",
    "CIM_NetworkAdapter",
    "CIM_Process",
    "CIM_DataFile"]


def _analyse_functions_calls_stream(
        verbose, calls_stream, tracer, output_format,
        output_files_prefix, map_params_summary, summary_format,
        with_dockerfile, aggregator, output_makefile):
    if not output_files_prefix:
        output_files_prefix = "results"
    if summary_format:
        output_summary_file = output_files_prefix + ".summary." + summary_format.lower()
    else:
        output_summary_file = None

    if output_format:
        try:
            batch_constructor = __batch_dumpers_dictionary[output_format]
        except KeyError:
            raise Exception("Invalid output format:" + str(output_format))
    else:
        batch_constructor = None

    map_flows = _create_map_flow_from_stream(verbose, calls_stream, tracer, batch_constructor, aggregator)

    logging.info("_analyse_functions_calls_stream")
    if output_files_prefix and output_format:
        assert output_files_prefix[-1] != '.'
        assert output_format[0] != '.'
        print("output_files_prefix=", output_files_prefix)
        print("outputFormat=", output_format)
        out_file = output_files_prefix + "." + output_format.lower()
        sys.stdout.write("Creating flow file:%s. %d flows\n" % (out_file, len(map_flows)))
        output_stream = open(out_file, "w")
        batch_dump = batch_constructor(output_stream)
        batch_dump.document_start()

        for flow_process_id in sorted(list(map_flows.keys()),reverse=True):
            btchTree = map_flows[flow_process_id]
            btchTree.dump_flow_constructor(batch_dump, flow_process_id)
        batch_dump.document_end()
        sys.stdout.write("Closing flow file:%s\n" % out_file)
        output_stream.close()

        if verbose: sys.stdout.write("\n")

    # Generating a docker file needs some data calculated with the summaries.
    if with_dockerfile:
        map_params_summary = full_map_params_summary

    logging.info("Generating summary")

    _generate_summary(map_params_summary, summary_format, output_summary_file)
    
    if with_dockerfile:
        if out_file:
            output_files_prefix, fil_out_ext = os.path.splitext(out_file)
        elif output_summary_file:
            output_files_prefix, fil_out_ext = os.path.splitext(output_summary_file)
        else:
            output_files_prefix = "docker"
        assert output_files_prefix[-1] != '.'
        docker_dir_name = output_files_prefix + ".docker"
        if os.path.exists(docker_dir_name):
            shutil.rmtree(docker_dir_name)
        os.makedirs(docker_dir_name)

        docker_filename = docker_dir_name + "/Dockerfile"
        cim_objects_definitions.generate_dockerfile(docker_filename)

    if output_makefile:
        # Create a makefile with the generated files, the inputs and the commands.
        # For each process, have the two lists of the input and the output files.
        cim_objects_definitions.generate_makefile(output_makefile)

    return output_summary_file


def test_from_file(
        input_log_file, tracer, output_files_prefix=None, output_format=None,
        summary_format=None,
        map_params_summary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
        input_process_id=0,
        verbose=0, with_dockerfile=None, update_server=None, aggregator=None, output_makefile=None):
    """
    Function called for unit tests by unittest.py and only used for testing purpose.
    Its behaviour is very close to the command-line behaviour.
    """
    assert isinstance(input_process_id, int)

    logging.info("input_log_file=%s" % input_log_file)
    cim_objects_definitions.G_UpdateServer = update_server
    calls_stream = _create_calls_stream([], input_process_id, input_log_file, tracer)

    # Because a session is replayed with a log file, the target machine might be different.
    # So, this forbids attenpts to bring more information by querying the operating system.
    cim_objects_definitions.local_standardized_file_path = cim_objects_definitions.standardized_file_path_syntax_only

    # Check if there is a context file, which gives parameters such as the current directory,
    # necessary to reproduce the test in the same conditions.
    output_summary_file = _analyse_functions_calls_stream(
        verbose, calls_stream, tracer, output_format, output_files_prefix,
        map_params_summary, summary_format, with_dockerfile, aggregator, output_makefile)
    return output_summary_file


def start_processing(global_parameters):
    logging.info("Creating calls_stream")
    calls_stream = _create_calls_stream(
        global_parameters.command_line,
        global_parameters.input_process_id,
        global_parameters.input_log_file,
        global_parameters.tracer)

    logging.info("start_processing")
    assert cim_objects_definitions.G_topProcessId >= 0

    if global_parameters.duplicate_input_log:
        tracer_object = G_traceToTracer[global_parameters.tracer]
        calls_stream = tracer_object.tee_calls_stream(calls_stream, global_parameters.output_files_prefix)

    # If not replaying, saves all parameters in an ini file, with all parameters needed for a replay.
    assert cim_objects_definitions.G_ReplayMode in [False, True]
    if not cim_objects_definitions.G_ReplayMode:
        _ini_file_create(global_parameters.output_files_prefix)

    assert global_parameters.output_files_prefix[-1] != '.'

    # In normal usage, the summary output format is the same as the output format for calls.
    _analyse_functions_calls_stream(
        global_parameters.verbose,
        calls_stream,
        global_parameters.tracer,
        global_parameters.output_format,
        global_parameters.output_files_prefix,
        global_parameters.map_params_summary,
        global_parameters.summary_format,
        global_parameters.with_dockerfile,
        global_parameters.aggregator,
        global_parameters.output_makefile)


def dockit_entry_point():
    class G_parameters:
        verbose = 0
        with_warning = 0

        # By default, generates all summaries. The filter syntax is based on CIM object pathes:
        # -s 'Win32_LogicalDisk.DeviceID="C:",Prop="Value",Prop="Regex"'
        # -s "CIM+_DataFile:Category=['Others','Shared libraries']"
        #
        # At the moment, the summary generates only two sorts of objects: CIM_Process and CIM_DataFile.
        # mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"]
        map_params_summary = full_map_params_summary

        with_dockerfile = None
        output_makefile = None

        input_process_id = -1
        output_format = "TXT" # Default output format of the generated files.
        input_log_file = None
        summary_format = None
        output_files_prefix = "dockit_output"
        tracer = None
        aggregator = None
        duplicate_input_log = False

    logging.info("Startup")
    try:
        command_options, G_parameters.command_line = getopt.getopt(sys.argv[1:],
                "hvws:DM:p:f:F:i:l:t:S:a:d",
                [
                "help",
                "verbose",
                "warning",
                "summary=",
                "dockerfile", # Generates a dockerfile to rerun the session.
                "makefile=", # This generates a makefile for the files dependencies and the commands.
                "pid=", # Identifier of a process to attach to. Exclusive to a command and an input log file.
                "format=",
                "summary-format=",
                "input=", # Input log file to replay a session. Exclusive to pid and command.
                "log=", # Prefix of the generated output files.
                "tracer=", # strace, ltrace or pydbg. Software used to trace the execution of the process or the command.
                "server=", # Output server to store the events as a RDF-XML document. Might be an output RDF file.
                "aggregator=",
                "duplicate"
                ])
    except getopt.GetoptError as err:
        # print help information and exit:
        print_dockit_usage(2, err) # will print something like "option -a not recognized"

    for an_option, a_value in command_options:
        if an_option in ("-v", "--verbose"):
            G_parameters.verbose += 1
            # CRITICAL=50, NOTSET=0
            logging.getLogger().setLevel(50 - G_parameters.verbose * 10)
        elif an_option in ("-w", "--warning"):
            G_parameters.with_warning += 1
        elif an_option in ("-s", "--summary"):
            G_parameters.map_params_summary = G_parameters.map_params_summary + [a_value] if a_value else []
        elif an_option in ("-D", "--dockerfile"):
            G_parameters.with_dockerfile = True
        elif an_option in ("-M", "--makefile"):
            G_parameters.output_makefile = a_value
        elif an_option in ("-p", "--pid"):
            G_parameters.input_process_id = int(a_value)
        elif an_option in ("-f", "--format"):
            G_parameters.output_format = a_value.upper()
        elif an_option in ("-F", "--summary_format"):
            G_parameters.summary_format = a_value.upper()
        elif an_option in ("-i", "--input"):
            G_parameters.input_log_file = a_value
        elif an_option in ("-l", "--log"):
            G_parameters.output_files_prefix = a_value
        elif an_option in ("-t", "--tracer"):
            G_parameters.tracer = a_value
        elif an_option in ("-S", "--server"):
            cim_objects_definitions.G_UpdateServer = a_value
        elif an_option in ("-a", "--aggregator"):
            G_parameters.aggregator = a_value
        elif an_option in ("-d", "--duplicate"):
            G_parameters.duplicate_input_log = True
        elif an_option in ("-h", "--help"):
            print_dockit_usage(0)
        else:
            assert False, "Unhandled option"

    # For Linux, default value is "strace".
    G_parameters.tracer = default_tracer(G_parameters.input_log_file, G_parameters.tracer)

    start_processing(G_parameters)

    #logging.error("cim_objects_definitions.G_ReplayMode=%s" % cim_objects_definitions.G_ReplayMode)
    #print("cim_objects_definitions.G_ReplayMode=", cim_objects_definitions.G_ReplayMode)

if __name__ == '__main__':
    dockit_entry_point()


################################################################################
# The End.
################################################################################
