#!/usr/bin/env python

"""Monitors living processes and generates a dockerfile And much more."""

# NOTE: For convenience purpose, this script is standalone, and therefore quite big.
# Requires Python 2.7 or later.

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

# This defines the CIM objects which are created when monitoring
# a running process.
if __package__:
    from . import cim_objects_definitions
else:
    import cim_objects_definitions

is_platform_windows = sys.platform.startswith("win32")
is_platform_linux = sys.platform.startswith("linux")

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

if is_platform_windows:
    # Definitions of Win32 systems calls to monitor.
    if __package__:
        from . import win32_api_definitions
    else:
        import win32_api_definitions
    win32_api_definitions.tracer_object = win32_api_definitions.Win32Tracer()
    G_traceToTracer["pydbg"] = win32_api_definitions.tracer_object

################################################################################

def print_dockit_usage(exit_code = 1, error_message = None):
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
    print("  -p,--pid <pid>                  Monitors a running process instead of starting an executable.")
    print("  -f,--format TXT|CSV|JSON        Output format. Default is TXT.")
    print("  -F,--summary-format TXT|XML     Summary output format. Default is XML.")
    print("  -i,--input <file name>          Trace input log file for replaying a session.")
    print("  -l,--log <filename prefix>      Directory and prefix of output files.")
    print("  -t,--tracer strace|ltrace|pydbg Set trace program.")
    print("  -S,--server <Url>               Survol url for CIM objects updates. Ex: http://127.0.0.1:80/survol/event_put.py")
    print("  -a,--aggregator <aggregator>    Aggregation method, e.g. 'clusterize' etc...")
    print("  -d,--log                        Duplicates session to a log file which can be replayed as input...")

    print("")

    if is_platform_linux:
        print("strace command: " +" ".join(G_traceToTracer["strace"].build_trace_command(["<command>"], None)))
        print("                " +" ".join(G_traceToTracer["strace"].build_trace_command(None, "<pid>")))
        print("ltrace command: " +" ".join(G_traceToTracer["ltrace"].build_trace_command(["<command>"], None)))
        print("                " +" ".join(G_traceToTracer["ltrace"].build_trace_command(None, "<pid>")))
        print("")
        if G_traceToTracer["strace"].trace_software_version() < (4,21):
            # It needs the option "-y"
            print("strace version deprecated. Consider upgrading")

# Example to create a new unit test:
# ./dockit.py -D -l UnitTests/mineit_firefox  -t  ltrace bash firefox

    # Special value just for testing.
    if exit_code != 999:
        sys.exit(exit_code)

################################################################################


# This receives an array of WMI/WBEM/CIM object paths:
# 'Win32_LogicalDisk.DeviceID="C:"'
# The values can be regular expressions.
# key-value pairs in the expressions are matched one-to-one with objects.

# Example: rgx_object_path = 'Win32_LogicalDisk.DeviceID="C:",Prop="Value",Prop="Regex"'
def _parse_filter_CIM(rgx_object_path):
    idx_dot = rgx_object_path.find(".")
    if idx_dot < 0 :
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
    if sys.version_info >= (3,):
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
        (cim_class_name, cim_key_value_pairs) = _parse_filter_CIM(rgx_object_path)
        class_obj = getattr(cim_objects_definitions, cim_class_name)
        class_obj.DisplaySummary(fd_summary_file, cim_key_value_pairs)


# This stores various data related to the execution.
def _generate_summary_xml(map_params_summary, fd_summary_file):
    fd_summary_file.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fd_summary_file.write('<Dockit>\n')
    if map_params_summary:
        for rgx_object_path in map_params_summary:
            (cim_class_name, cim_key_value_pairs) = _parse_filter_CIM(rgx_object_path)
            class_obj = getattr(cim_objects_definitions, cim_class_name)
            class_obj.XMLSummary(fd_summary_file, cim_key_value_pairs)
    fd_summary_file.write('</Dockit>\n')


def _generate_summary(mapParamsSummary, summary_format, output_summary_file):
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

    summary_generator(mapParamsSummary,fd_summary_file)

    if output_summary_file:
        sys.stdout.write("Closing summary file:%s\n" % output_summary_file)
        fd_summary_file.close()


################################################################################

# This stores, on Linux, the package from where a file came from.
# So, in Docker, a file used by a process is not copied, but its package installed.
class FileToPackage:
    def __init__(self):
        tmpDir = tempfile.gettempdir()
        # This file stores and reuses the map from file name to Linux package.
        self.m_cacheFileName = tmpDir + "/" + "FileToPackageCache." + socket.gethostname() + ".txt"
        try:
            fdCache = open(self.m_cacheFileName,"r")
        except:
            logging.info("Cannot open packages cache file:%s." % self.m_cacheFileName)
            self.m_cacheFilesToPackages = dict()
            self.m_dirtyCache = False
            return

        try:
            self.m_cacheFilesToPackages = json.load(fdCache)
            fdCache.close()
            self.m_dirtyCache = False
            logging.info("Loaded packages cache file:%s" % self.m_cacheFileName)
        except:
            logging.warning("Error reading packages cache file:%s. Resetting." % self.m_cacheFileName)
            self.m_cacheFilesToPackages = dict()
            self.m_dirtyCache = True

    # Dump cache to a file. It does not use __del__()
    # because it cannot access some global names in recent versions of Python.
    def dump_cache_to_file(self):
        if self.m_dirtyCache:
            try:
                fdCache = open(self.m_cacheFileName,"w")
                logging.info("Dumping to packages cache file %s" % self.m_cacheFileName)
                json.dump(self.m_cacheFilesToPackages,fdCache)
                fdCache.close()
            except IOError:
                raise Exception("Cannot dump packages cache file to %s"%self.m_cacheFileName)

    @staticmethod
    def _one_file_to_linux_package_no_cache(oneFilNam):
        if is_platform_linux:
            aCmd = ['rpm', '-qf', oneFilNam]

            try:
                aPop = subprocess.Popen(aCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                anOut, anErr = aPop.communicate()
                aPack = anOut
                aPack = aPack.strip()
                if aPack.endswith("is not owned by any package"):
                    lstPacks = []
                elif aPack == "":
                    lstPacks = []
                else:
                    lstPacks = aPack.split("\n")
                    if lstPacks[0] == "":
                        raise Exception("Inserting invalid package")
                return lstPacks
            except:
                return []
        else:
            return None

    unpackagedPrefixes = ["/dev/","/home/","/proc/","/tmp/","/sys/","/var/cache/"] + cim_objects_definitions.CIM_DataFile.m_nonFilePrefixes

    @staticmethod
    def _cannot_be_packaged(filNam):
        # Some files cannot be packaged, ever.
        for pfx in FileToPackage.unpackagedPrefixes:
            if filNam.startswith(pfx):
                return True
        return False

    def one_file_to_linux_package(self, oneFilObj):
        oneFilNam = oneFilObj.Name

        # Very common case of a file which is only local.
        if FileToPackage._cannot_be_packaged(oneFilNam):
            return []
        try:
            return self.m_cacheFilesToPackages[oneFilNam]
        except KeyError:
            lstPacks= self._one_file_to_linux_package_no_cache(oneFilNam)

            if lstPacks:
                self.m_dirtyCache = True

            # TODO: Optimisation: Once we have detected a file of a package,
            # this loads all files from this package because reasonably,
            # there will be other files from it.
            # rpm -qf /usr/lib64/libselinux.so.1
            # rpm -q -l libselinux-2.6-6.fc26.x86_64
            self.m_cacheFilesToPackages[oneFilNam] = lstPacks

            return lstPacks

    def get_packages_list(self, lstPackagedFiles):

        # This command is very slow:
        # dnf provides /usr/bin/as

        # This is quite fast:
        # rpm -qf /bin/ls

        lstPackages = set()
        unknownFiles = []

        for oneFil in lstPackagedFiles:
            # sys.stdout.write("oneFil=%s tp=%s\n"%(oneFil,str(type(oneFil))))
            lstPacks = self.one_file_to_linux_package(oneFil)
            if lstPacks:
                # BEWARE: This takes the first pack, randomly.
                aPack = lstPacks[0]
                if aPack == "":
                    raise Exception("Invalid package for file=%s\n"%oneFil)
                lstPackages.add(aPack)
            else:
                unknownFiles.append(oneFil)
        return lstPackages, unknownFiles

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

    def dump_batch_to_stream(self,batchLet):
        self.m_strm.write("Pid=%6d {%4d/%s}%1s'%-20s' %s ==>> %s (%s,%s)\n" %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            linux_api_definitions.BatchStatus.chrDisplayCodes[batchLet.m_core.m_status],
            batchLet.m_core._function_name,
            batchLet.get_significant_args(),
            batchLet.m_core._return_value,
            _format_time(batchLet.m_core._time_start),
            _format_time(batchLet.m_core._time_end) ) )


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
            batchLet.m_core._function_name,
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



# This file contains some extra details to replay a session with a log file.
def ini_file_load(ini_pathname):
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
        sys.stdout.write("Ini line:%s %s=%s\n" % (line_key_value, string_key, string_val))
    sys.stdout.write("Closing ini file:%s\n" % ini_pathname)
    ini_file.close()
    return ini_map_key_value_pairs


# This is purely for debugging and testing.
def ini_file_check(ini_pathname):
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

# Rule-of-thumb method to deduce the tracer type given the log file.
def default_tracer(input_log_file, tracer=None):
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


# This returns a stream with each line written by strace or ltrace.
def _create_calls_stream(command_line, input_process_id, input_log_file, tracer):
    global G_Hostname
    global G_OSType

    # A command or a pid or an input log file, only one possibility.
    if command_line != []:
        if input_process_id > 0 or input_log_file:
            print_dockit_usage(1,"When providing command, must not specify process id or input log file")
    elif input_process_id> 0 :
        if command_line != []:
            print_dockit_usage(1,"When providing process id, must not specify command or input log file")
    elif input_log_file:
        if command_line != []:
            print_dockit_usage(1,"When providing input file, must not specify command or process id")
    else:
        print_dockit_usage(1,"Must provide command, pid or input file")

    date_today_run = time.strftime("%Y-%m-%d")
    the_host_nam = socket.gethostname()
    the_platform = sys.platform

    curr_wrk_dir = os.getcwd()

    cim_objects_definitions.G_ReplayMode = True if input_log_file else False
    cim_objects_definitions.G_SameMachine = not cim_objects_definitions.G_ReplayMode or G_Hostname == socket.gethostname()

    with_warning = True # FIXME: Must be a parameter.
    _init_globals(with_warning)

    current_tracer = G_traceToTracer[tracer]
    if cim_objects_definitions.G_ReplayMode:
        # calls_stream = open(input_log_file)
        calls_stream = current_tracer.logfile_pathname_to_stream(input_log_file)
        logging.info("File " + input_log_file)
        logging.info("Logfile %s pid=%s" % (input_log_file, input_process_id))

        # There might be a context file with important information to reproduce the test.
        context_log_file = os.path.splitext(input_log_file)[0] + ".ini"
        mapKV = ini_file_load(context_log_file)

        # The main process pid might be embedded in the log file name,
        # but preferably stored in the ini file.
        cim_objects_definitions.G_topProcessId     = int(mapKV.get("TopProcessId", input_process_id))

        cim_objects_definitions.G_CurrentDirectory = mapKV.get("CurrentDirectory", curr_wrk_dir)
        cim_objects_definitions.G_Today            = mapKV.get("CurrentDate", date_today_run)
        G_Hostname                                 = mapKV.get("CurrentHostname", the_host_nam)
        G_OSType                                   = mapKV.get("CurrentOSType", the_platform)

        sys.stdout.write("G_topProcessId=%d\n" % cim_objects_definitions.G_topProcessId)
    else:
        # FIXME: G_topProcessId is set elsewhere, at the creation of the subprocess ?
        cim_objects_definitions.G_topProcessId, calls_stream= current_tracer.create_logfile_stream(command_line, input_process_id)
        cim_objects_definitions.G_CurrentDirectory          = curr_wrk_dir
        cim_objects_definitions.G_Today                     = date_today_run
        G_Hostname                                          = the_host_nam
        G_OSType                                            = the_platform
        assert cim_objects_definitions.G_topProcessId >= 0, "_create_calls_stream G_topProcessId not set"

    # Another possibility is to start a process or a thread which will monitor
    # the target process, and will write output information in a stream.

    return calls_stream


# Global variables which must be reinitialised before a run.
def _init_globals(with_warning):
    linux_api_definitions.init_linux_globals(with_warning)

    cim_objects_definitions.init_global_objects()


# Called after a run.
def _exit_globals():
    cim_objects_definitions.exit_global_objects()

################################################################################

# The role of an aggregator is to receive each function call and store it or not.
# It can aggregate the calls or process them in anyway, on the fly or at the end.
# There is one object for each execution flow, which is a process or a thread.
# This method returns a class.
def _calls_flow_class_factory(aggregator):
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


# This receives a stream of lines, each of them is a function call,
# possibly unfinished/resumed/interrupted by a signal.
def _create_map_flow_from_stream(
        verbose,
        calls_stream, tracer, batch_constructor, aggregator):
    # This is an event log as a stream, coming from a file (if testing), the output of strace or anything else.
    logging.error("_create_map_flow_from_stream")

    map_flows = {}

    CallsFlowClass = _calls_flow_class_factory(aggregator)

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

    _exit_globals()

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
        with_dockerfile, aggregator):
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

        dockerFilename = docker_dir_name + "/Dockerfile"
        cim_objects_definitions.generate_dockerfile(dockerFilename)

    return output_summary_file


# Function called for unit tests by unittest.py
def test_from_file(
        input_log_file, tracer, input_process_id, output_files_prefix, output_format, verbose, map_params_summary,
        summary_format, with_warning, with_dockerfile, update_server, aggregator):
    assert isinstance(input_process_id, int)
    cim_objects_definitions.G_UpdateServer = update_server
    calls_stream = _create_calls_stream([], input_process_id, input_log_file, tracer)

    # Check if there is a context file, which gives parameters such as the current directory,
    # necessary to reproduce the test in the same conditions.

    output_summary_file = _analyse_functions_calls_stream(
        verbose, calls_stream, tracer, output_format, output_files_prefix,
        map_params_summary, summary_format, with_dockerfile, aggregator)
    return output_summary_file


def _start_processing(global_parameters):
    calls_stream = _create_calls_stream(
        global_parameters.command_line,
        global_parameters.input_process_id,
        global_parameters.input_log_file,
        global_parameters.tracer)

    assert cim_objects_definitions.G_topProcessId >= 0

    if global_parameters.duplicate_input_log:
        calls_stream = G_traceToTracer[global_parameters.tracer].tee_calls_stream(calls_stream, global_parameters.output_files_prefix)

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
        global_parameters.aggregator)

if __name__ == '__main__':
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

        input_process_id = -1
        output_format = "TXT" # Default output format of the generated files.
        input_log_file = None
        summary_format = None
        output_files_prefix = "dockit_output"
        tracer = None
        aggregator = None
        duplicate_input_log = False

    try:
        command_options, G_parameters.command_line = getopt.getopt(sys.argv[1:],
                "hvws:Dp:f:F:i:l:t:S:a:d",
                ["help","verbose","warning","summary=",
                 "dockerfile","pid=","format=","summary-format=","input=",
                 "log=","tracer=","server=","aggregator=","duplicate"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print_dockit_usage(2, err) # will print something like "option -a not recognized"

    for an_option, a_value in command_options:
        if an_option in ("-v", "--verbose"):
            G_parameters.verbose += 1
        elif an_option in ("-w", "--warning"):
            G_parameters.with_warning += 1
        elif an_option in ("-s", "--summary"):
            G_parameters.map_params_summary = G_parameters.map_params_summary + [a_value] if a_value else []
        elif an_option in ("-D", "--dockerfile"):
            G_parameters.with_dockerfile = True
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

    G_parameters.tracer = default_tracer(G_parameters.input_log_file, G_parameters.tracer)

    _start_processing(G_parameters)

    logging.error("cim_objects_definitions.G_ReplayMode=%s" % cim_objects_definitions.G_ReplayMode)
    print("cim_objects_definitions.G_ReplayMode=", cim_objects_definitions.G_ReplayMode)


################################################################################
# The End.
################################################################################
