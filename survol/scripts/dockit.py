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

################################################################################

G_traceToTracer = {}

# TODO: Should be done on Linux only.
if __package__:
    from . import linux_api_definitions
else:
    import linux_api_definitions

# This contains th definitions of Linux system calls, and other things.
G_traceToTracer["strace"] = linux_api_definitions.STraceTracer()
G_traceToTracer["ltrace"] = linux_api_definitions.LTraceTracer()

if sys.platform.startswith("win"):
    # Definitions of Win32 systems calls to monitor.
    if __package__:
        from . import win32_api_definitions
    else:
        import win32_api_definitions
    G_traceToTracer["pydbg"] = win32_api_definitions.Win32Tracer()

################################################################################

def print_dockit_usage(exitCode = 1, errMsg = None):
    if errMsg:
        print(errMsg)

    progNam = sys.argv[0]
    print("DockIT: %s <executable>"%progNam)
    print("Monitors and factorizes systems calls.")
    print("  -h,--help                       This message.")
    print("  -v,--verbose                    Verbose mode (Cumulative).")
    print("  -w,--warning                    Display warnings (Cumulative).")
    print("  -s,--summary <CIM class>        Prints a summary at the end: Start end end time stamps, executable name,\n"
        + "                                  loaded libraries, read/written/created files and timestamps, subprocesses tree.\n"
        + "                                  Examples: -s 'Win32_LogicalDisk.DeviceID=\"C:\",Prop1=\"Value1\",Prop2=\"Value2\"'\n"
        + "                                            -s 'CIM_DataFile:Category=[\"Others\",\"Shared libraries\"]'" )
    print("  -D,--dockerfile                 Generates a dockerfile.")
    print("  -p,--pid <pid>                  Monitors a running process instead of starting an executable.")
    print("  -f,--format TXT|CSV|JSON        Output format. Default is TXT.")
    print("  -F,--summary-format TXT|XML     Summary output format. Default is XML.")
    print("  -i,--input <file name>          trace input file.")
    print("  -l,--log <filename prefix>      prefix of output files.\n")
    print("  -t,--tracer strace|ltrace|pydbg command for generating trace log")
    print("  -S,--server <Url>               Survol url for CIM objects updates. Ex: http://127.0.0.1:80/survol/event_put.py")
    print("  -a,--aggregator <aggregator>    Aggregation method, e.g. clusterize etc...")

    print("")

    if sys.platform.startswith("lin"):
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
    if exitCode != 999:
        sys.exit(exitCode)

################################################################################

# This receives an array of WMI/WBEM/CIM object paths:
# 'Win32_LogicalDisk.DeviceID="C:"'
# The values can be regular expressions.
# key-value pairs in the expressions are matched one-to-one with objects.

# Example: rgxObjectPath = 'Win32_LogicalDisk.DeviceID="C:",Prop="Value",Prop="Regex"'
def _parse_filter_CIM(rgxObjectPath):
    idxDot = rgxObjectPath.find(".")
    if idxDot < 0 :
        return ( rgxObjectPath, {} )

    objClassName = rgxObjectPath[:idxDot]

    # Maybe there is nothing after the dot.
    if idxDot == len(rgxObjectPath)-1:
        return ( objClassName, {} )

    strKeyValues = rgxObjectPath[idxDot+1:]

    # def toto(a='1',b='2')
    # >>> inspect.getargspec(toto)
    # ArgSpec(args=['a', 'b'], varargs=None, keywords=None, defaults=('1', '2'))
    tmpFunc = "def aTempFunc(%s) : pass" % strKeyValues

    # OK with Python 3
    exec(tmpFunc)
    local_temp_func = locals()["aTempFunc"]
    if sys.version_info >= (3,):
        tmpInsp = inspect.getfullargspec(local_temp_func)
    else:
        tmpInsp = inspect.getargspec(local_temp_func)
    arrArgs = tmpInsp.args
    arrVals = tmpInsp.defaults
    mapKeyValues = dict( zip(arrArgs, arrVals) )

    return ( objClassName, mapKeyValues )

# TODO: Probably not needed because noone wants this output format..
def _generate_summary_txt(mapParamsSummary, fdSummaryFile):
    for rgxObjectPath in mapParamsSummary:
        ( cimClassName, cimKeyValuePairs ) = _parse_filter_CIM(rgxObjectPath)
        classObj = getattr(cim_objects_definitions, cimClassName)
        classObj.DisplaySummary(fdSummaryFile,cimKeyValuePairs)

# This stores various data related to the execution.
def _generate_summary_xml(mapParamsSummary,fdSummaryFile):
    fdSummaryFile.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fdSummaryFile.write('<Dockit>\n')
    if mapParamsSummary:
        for rgxObjectPath in mapParamsSummary:
            ( cimClassName, cimKeyValuePairs ) = _parse_filter_CIM(rgxObjectPath)
            classObj = getattr(cim_objects_definitions, cimClassName)
            classObj.XMLSummary(fdSummaryFile,cimKeyValuePairs)
    fdSummaryFile.write('</Dockit>\n')

def _generate_summary(mapParamsSummary, summaryFormat, outputSummaryFile):
    if summaryFormat == "TXT":
        summaryGenerator = _generate_summary_txt
    elif summaryFormat == "XML":
        # The output format is very different.
        summaryGenerator = _generate_summary_xml
    elif summaryFormat == None:
        return
    else:
        raise Exception("Unsupported summary output format:%s"%summaryFormat)

    if outputSummaryFile:
        fdSummaryFile = open(outputSummaryFile, "w")
        sys.stdout.write("Creating summary file:%s\n"%outputSummaryFile)
    else:
        fdSummaryFile = sys.stdout

    summaryGenerator(mapParamsSummary,fdSummaryFile)

    if outputSummaryFile:
        sys.stdout.write("Closing summary file:%s\n"%outputSummaryFile)
        fdSummaryFile.close()


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
        if sys.platform.startswith("linux"):
            aCmd = ['rpm','-qf',oneFilNam]

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
def FmtTim(aTim):
    return aTim

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
            batchLet.m_core.m_funcNam,
            batchLet.get_significant_args(),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )


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
            batchLet.m_core.m_funcNam,
            batchLet.get_significant_args(),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd)))


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
            batchLet.m_core.m_funcNam,
            json.dumps([str(arg) for arg in batchLet.get_significant_args()]),
            json.dumps(batchLet.m_core.m_retValue), # It may contain double-quotes
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd)))
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

def default_tracer(inputLogFile, tracer=None):
    if not tracer:
        if inputLogFile:
            # Maybe the pid is embedded in the log file.
            matchTrace = re.match(r".*\.([^\.]*)\.[0-9]+\.log", inputLogFile )
            if matchTrace:
                tracer = matchTrace.group(1)
            else:
                # The file format might be "xyzxyz.strace.log", "abcabc.ltrace.log", "123123.cdb.log"
                # depending on the tool which generated the log.
                matchTrace = re.match(r".*\.([^\.]*)\.log", inputLogFile )
                if not matchTrace:
                    raise Exception("Cannot read tracer from log file name:%s"%inputLogFile)
                tracer = matchTrace.group(1)
        else:
            if sys.platform.startswith("win32"):
                tracer = "pydbg"
            elif sys.platform.startswith("linux"):
                # This could also be "ltrace", but "strace" is more usual.
                tracer = "strace"
            else:
                raise Exception("Unknown platform")
    logging.info("Tracer " + tracer)
    return tracer


def _load_init_file(ini_pathname):
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


# This returns a stream with each line written by strace or ltrace.
def _create_calls_stream(argsCmd, aPid, inputLogFile, tracer):
    global G_Hostname
    global G_OSType

    # A command or a pid or an input log file, only one possibility.
    if argsCmd != []:
        if aPid > 0 or inputLogFile:
            print_dockit_usage(1,"When providing command, must not specify process id or input log file")
    elif aPid> 0 :
        if argsCmd != []:
            print_dockit_usage(1,"When providing process id, must not specify command or input log file")
    elif inputLogFile:
        if argsCmd != []:
            print_dockit_usage(1,"When providing input file, must not specify command or process id")
    else:
        print_dockit_usage(1,"Must provide command, pid or input file")

    dateTodayRun = time.strftime("%Y-%m-%d")
    theHostNam = socket.gethostname()
    thePlatform = sys.platform

    currWrkDir = os.getcwd()
    if inputLogFile:
        calls_stream = open(inputLogFile)
        logging.info("File "+inputLogFile)
        logging.info("Logfile %s pid=%s" % (inputLogFile,aPid) )

        # There might be a context file with important information to reproduce the test.
        contextLogFile = os.path.splitext(inputLogFile)[0]+".ini"
        mapKV = _load_init_file(contextLogFile)

        # The main process pid might be embedded in the log file name,
        # but preferably stored in the ini file.
        linux_api_definitions.G_topProcessId       = int(mapKV.get("TopProcessId",aPid))

        cim_objects_definitions.G_CurrentDirectory = mapKV.get("CurrentDirectory",currWrkDir)
        cim_objects_definitions.G_Today            = mapKV.get("CurrentDate",dateTodayRun)
        G_Hostname                                 = mapKV.get("CurrentHostname",theHostNam)
        G_OSType                                   = mapKV.get("CurrentOSType",thePlatform)

        cim_objects_definitions.G_ReplayMode = True

        sys.stdout.write("G_topProcessId=%d\n" % linux_api_definitions.G_topProcessId)
    else:

        (linux_api_definitions.G_topProcessId, calls_stream) = G_traceToTracer[tracer].create_logfile_stream(argsCmd,aPid)
        cim_objects_definitions.G_CurrentDirectory          = currWrkDir
        cim_objects_definitions.G_Today                     = dateTodayRun
        G_Hostname                                          = theHostNam
        G_OSType                                            = thePlatform

        cim_objects_definitions.G_ReplayMode = False

    cim_objects_definitions.G_SameMachine = not cim_objects_definitions.G_ReplayMode or G_Hostname == socket.gethostname()


    # Another possibility is to start a process or a thread which will monitor
    # the target process, and will write output information in a stream.

    return calls_stream


# Global variables which must be reinitialised before a run.
def _init_globals(withWarning):
    linux_api_definitions.init_linux_globals(withWarning)

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
            def factorise_one_flow(self, verbose, batchConstructor):
                pass

            def dump_flow_constructor(self, batchDump, flow_process_id=None):
                batchDump.flow_header(process_id=flow_process_id, calls_number=self.m_calls_number)
                # TODO: Reformat this information for JSON, TXT and CSV
                # FIXME: extra_header is probably never used.
                # batchDump.m_strm.write("%s\n" % extra_header)
                # batchDump.m_strm.write("Number of function calls: %d\n" % self.m_calls_number)
                batchDump.flow_footer()

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
        verbose, withWarning,
        calls_stream, tracer, batchConstructor, aggregator):
    # Here, we have an event log as a stream, which comes from a file (if testing),
    # the output of strace or anything else.

    _init_globals(withWarning)

    map_flows = {}

    CallsFlowClass = _calls_flow_class_factory(aggregator)

    # This generator creates individual BatchLet objects on-the-fly.
    # At this stage, "resumed" calls are matched with the previously received "unfinished"
    # line for the same call.
    # Some calls, for some reason, might stay "unfinished": Though,
    # they are still needed to rebuild the processes tree.
    map_flows_generator = G_traceToTracer[tracer].create_flows_from_calls_stream(verbose, calls_stream)

    # Maybe, some system calls are unfinished, i.e. the "resumed" part of the call
    # is never seen. They might be matched later.
    for one_function_call in map_flows_generator:
        aCore = one_function_call.m_core

        the_pid = aCore.m_pid
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
        calls_flow.factorise_one_flow(verbose, batchConstructor)

    _exit_globals()
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
        verbose, withWarning, calls_stream, tracer, outputFormat,
        output_files_prefix, mapParamsSummary, summaryFormat, withDockerfile, aggregator):
    if not output_files_prefix:
        output_files_prefix = "results"
    if summaryFormat:
        outputSummaryFile = output_files_prefix + ".summary." + summaryFormat.lower()
    else:
        outputSummaryFile = None

    if outputFormat:
        try:
            batchConstructor = __batch_dumpers_dictionary[outputFormat]
        except KeyError:
            raise Exception("Invalid output format:" + str(outputFormat))
    else:
        batchConstructor = None

    mapFlows = _create_map_flow_from_stream(verbose, withWarning, calls_stream, tracer, batchConstructor, aggregator)

    linux_api_definitions.G_stackUnfinishedBatches.display_unfinished_unmerged_batches(sys.stdout)

    if output_files_prefix and outputFormat:
        assert output_files_prefix[-1] != '.'
        assert outputFormat[0] != '.'
        print("output_files_prefix=", output_files_prefix)
        print("outputFormat=", outputFormat)
        outFile = output_files_prefix + "." + outputFormat.lower()
        ## outFile = output_files_prefix + "." + outputFormat.lower()
        sys.stdout.write("Creating flow file:%s. %d flows\n" % (outFile, len(mapFlows)))
        output_stream = open(outFile, "w")
        batchDump = batchConstructor(output_stream)
        batchDump.document_start()

        for flow_process_id in sorted(list(mapFlows.keys()),reverse=True):
            btchTree = mapFlows[flow_process_id]
            btchTree.dump_flow_constructor(batchDump, flow_process_id)
        batchDump.document_end()
        sys.stdout.write("Closing flow file:%s\n" % outFile)
        output_stream.close()

        if verbose: sys.stdout.write("\n")

    # Generating a docker file needs some data calculated with the summaries.
    if withDockerfile:
        mapParamsSummary = full_map_params_summary

    _generate_summary(mapParamsSummary, summaryFormat, outputSummaryFile)
    
    if withDockerfile:
        if outFile:
            output_files_prefix, filOutExt = os.path.splitext(outFile)
        elif outputSummaryFile:
            output_files_prefix, filOutExt = os.path.splitext(outputSummaryFile)
        else:
            output_files_prefix = "docker"
        assert output_files_prefix[-1] != '.'
        dockerDirName = output_files_prefix + ".docker"
        if os.path.exists(dockerDirName):
            shutil.rmtree(dockerDirName)
        os.makedirs(dockerDirName)

        dockerFilename = dockerDirName + "/Dockerfile"
        cim_objects_definitions.GenerateDockerFile(dockerFilename)

    return outputSummaryFile


# Function called for unit tests by unittest.py
def test_from_file(
        inputLogFile, tracer, topPid, output_files_prefix, outputFormat, verbose, mapParamsSummary,
        summaryFormat, withWarning, withDockerfile, updateServer, aggregator):
    assert isinstance(topPid, int)
    calls_stream = _create_calls_stream([], topPid, inputLogFile, tracer)
    cim_objects_definitions.G_UpdateServer = updateServer

    # Check if there is a context file, which gives parameters such as the current directory,
    # necessary to reproduce the test in the same conditions.

    output_summary_file = _analyse_functions_calls_stream(
        verbose, withWarning, calls_stream, tracer, outputFormat, output_files_prefix,
        mapParamsSummary, summaryFormat, withDockerfile, aggregator)
    return output_summary_file


def _start_processing(global_parameters):
    calls_stream = _create_calls_stream(
        global_parameters.command_line,
        global_parameters.input_process_id,
        global_parameters.input_log_file,
        global_parameters.tracer)

    if global_parameters.output_files_short_prefix:
        output_files_prefix = "%s.%s.%s" % (
            global_parameters.output_files_short_prefix,
            global_parameters.tracer,
            linux_api_definitions.G_topProcessId)

        # tee: This just needs to reimplement "readline()"
        class TeeStream:
            def __init__(self, log_stream):
                self.m_logStrm = log_stream
                assert output_files_prefix[-1] != '.'
                log_fil_nam = output_files_prefix + ".log"
                self.m_outFd = open( log_fil_nam, "w" )
                print("Creating log file:%s" % log_fil_nam )

            def readline(self):
                # sys.stdout.write("xxx\n" )
                aLin = self.m_logStrm.readline()
                # sys.stdout.write("tee=%s" % aLin)
                self.m_outFd.write(aLin)
                return aLin

        calls_stream = TeeStream(calls_stream)

        # If not replaying, saves all parameters in an ini file.
        if not cim_objects_definitions.G_ReplayMode:
            iniFilNam = output_files_prefix + ".ini"
            iniFd = open(iniFilNam,"w")

            # At this stage, we know what is the top process id,
            # because the command is created, or the process attached.
            iniFd.write('TopProcessId=%s\n' % linux_api_definitions.G_topProcessId )

            iniFd.write('CurrentDirectory=%s\n' % os.getcwd() )
            # Necessary because ltrace and strace do not write the date.
            # Done before testing in case the test stops next day.
            iniFd.write('CurrentDate=%s\n' % cim_objects_definitions.G_Today)
            iniFd.write('CurrentHostname=%s\n' % socket.gethostname())
            iniFd.write('CurrentOSType=%s\n' % sys.platform)
            iniFd.close()
    else:
        output_files_prefix = "dockit_output_" + global_parameters.tracer

    assert output_files_prefix[-1] != '.'

    # In normal usage, the summary output format is the same as the output format for calls.
    _analyse_functions_calls_stream(
        global_parameters.verbose,
        global_parameters.with_warning,
        calls_stream,
        global_parameters.tracer,
        global_parameters.output_format,
        output_files_prefix,
        global_parameters.map_params_summary,
        global_parameters.summary_format,
        global_parameters.with_docker_file,
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

        with_docker_file = None

        input_process_id = -1
        output_format = "TXT" # Default output format of the generated files.
        input_log_file = None
        summary_format = None
        output_files_short_prefix = None
        tracer = None
        aggregator = None

    try:
        command_options, G_parameters.command_line = getopt.getopt(sys.argv[1:],
                "hvws:Dp:f:F:i:l:t:S:a:",
                ["help","verbose","warning","summary=",
                 "dockerfile","pid=","format=","summary-format=","input=",
                 "log=","tracer=","server=","aggregator="])
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
            G_parameters.with_docker_file = True
        elif an_option in ("-p", "--pid"):
            G_parameters.input_process_id = int(a_value)
        elif an_option in ("-f", "--format"):
            G_parameters.output_format = a_value.upper()
        elif an_option in ("-F", "--summary_format"):
            G_parameters.summary_format = a_value.upper()
        elif an_option in ("-i", "--input"):
            G_parameters.input_log_file = a_value
        elif an_option in ("-l", "--log"):
            G_parameters.output_files_short_prefix = a_value
        elif an_option in ("-t", "--tracer"):
            G_parameters.tracer = a_value
        elif an_option in ("-S", "--server"):
            G_parameters.cim_objects_definitions.G_UpdateServer = a_value
        elif an_option in ("-a", "--aggregator"):
            G_parameters.aggregator = a_value
        elif an_option in ("-h", "--help"):
            print_dockit_usage(0)
        else:
            assert False, "Unhandled option"

    G_parameters.tracer = default_tracer(G_parameters.input_log_file, G_parameters.tracer)

    _start_processing(G_parameters)

    # These information in JSON format on the last line
    # are needed to find the name of the generated file.
    print('{"pid": "%d"}' % linux_api_definitions.G_topProcessId)

################################################################################
# The End.
################################################################################
