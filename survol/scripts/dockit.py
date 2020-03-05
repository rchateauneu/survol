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
import datetime
import shutil
import tempfile
import logging

# This defines the CIM objects which are created when monitoring
# a running process.
import cim_objects_definitions

################################################################################

G_traceToTracer = {}

# This contains th definitions of Linux system calls, and other things.
# TODO: Should be done on Linux only.
import linux_api_definitions
G_traceToTracer["strace"] = linux_api_definitions.STraceTracer()
G_traceToTracer["ltrace"] = linux_api_definitions.LTraceTracer()

if sys.platform.startswith("win"):
    # Definitions of Win32 systems calls to monitor.
    import win32_api_definitions
    G_traceToTracer["pydbg"] = win32_api_definitions.Win32Tracer()

################################################################################

def Usage(exitCode = 1, errMsg = None):
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
    print("  -i,--input <file name>          trace command input file.")
    print("  -l,--log <filename prefix>      trace command log output file.\n")
    print("  -t,--tracer strace|ltrace|pydbg command for generating trace log")
    print("  -S,--server <Url>               Survol url for CIM objects updates. Ex: http://127.0.0.1:80/survol/event_put.py")
    print("")

    if sys.platform.startswith("lin"):
        print("strace command: "+" ".join(G_traceToTracer["strace"].BuildCommand(["<command>"],None)))
        print("                "+" ".join(G_traceToTracer["strace"].BuildCommand(None,"<pid>")))
        print("ltrace command: "+" ".join(G_traceToTracer["ltrace"].BuildCommand(["<command>"],None)))
        print("                "+" ".join(G_traceToTracer["ltrace"].BuildCommand(None,"<pid>")))
        print("")
        if G_traceToTracer["strace"].Version() < (4,21):
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
def ParseFilterCIM(rgxObjectPath):
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
def GenerateSummaryTXT(mapParamsSummary, fdSummaryFile):
    for rgxObjectPath in mapParamsSummary:
        ( cimClassName, cimKeyValuePairs ) = ParseFilterCIM(rgxObjectPath)
        #print([k for k in globals() if k.find("Computer") > 0])
        #classObj = globals()[ cimClassName ]
        classObj = getattr(cim_objects_definitions, cimClassName)
        classObj.DisplaySummary(fdSummaryFile,cimKeyValuePairs)

# Thsi stores various data related to the execution.
def GenerateSummaryXML(mapParamsSummary,fdSummaryFile):
    fdSummaryFile.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fdSummaryFile.write('<Dockit>\n')
    if mapParamsSummary:
        for rgxObjectPath in mapParamsSummary:
            ( cimClassName, cimKeyValuePairs ) = ParseFilterCIM(rgxObjectPath)
            #classObj = globals()[ cimClassName ]
            classObj = getattr(cim_objects_definitions, cimClassName)
            classObj.XMLSummary(fdSummaryFile,cimKeyValuePairs)
    fdSummaryFile.write('</Dockit>\n')

def GenerateSummary(mapParamsSummary, summaryFormat, outputSummaryFile):
    if summaryFormat == "TXT":
        summaryGenerator = GenerateSummaryTXT
    elif summaryFormat == "XML":
        # The output format is very different.
        summaryGenerator = GenerateSummaryXML
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
            sys.stdout.write("Cannot open packages cache file:%s.\n" % self.m_cacheFileName)
            self.m_cacheFilesToPackages = dict()
            self.m_dirtyCache = False
            return

        try:
            self.m_cacheFilesToPackages = json.load(fdCache)
            fdCache.close()
            self.m_dirtyCache = False
            sys.stdout.write("Loaded packages cache file:%s\n"%self.m_cacheFileName)
        except:
            sys.stdout.write("Error reading packages cache file:%s. Resetting.\n" % self.m_cacheFileName)
            self.m_cacheFilesToPackages = dict()
            self.m_dirtyCache = True

    # Dump cache to a file. It does not use __del__()
    # because it cannot access some global names in recent versions of Python.
    def DumpToFile(self):
        if self.m_dirtyCache:
            try:
                fdCache = open(self.m_cacheFileName,"w")
                sys.stdout.write("Dumping to packages cache file %s\n"%self.m_cacheFileName)
                json.dump(self.m_cacheFilesToPackages,fdCache)
                fdCache.close()
            except IOError:
                raise Exception("Cannot dump packages cache file to %s"%self.m_cacheFileName)

    @staticmethod
    def OneFileToPackageLinuxNoCache(oneFilNam):
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
    def CannotBePackaged(filNam):
        # Some files cannot be packaged, ever.
        for pfx in FileToPackage.unpackagedPrefixes:
            if filNam.startswith(pfx):
                return True
        return False

    def OneFileToPackageLinux(self,oneFilObj):
        oneFilNam = oneFilObj.Name

        # Very common case of a file which is only local.
        if FileToPackage.CannotBePackaged(oneFilNam):
            return []
        try:
            return self.m_cacheFilesToPackages[oneFilNam]
        except KeyError:
            lstPacks= self.OneFileToPackageLinuxNoCache(oneFilNam)

            if lstPacks:
                self.m_dirtyCache = True

            # TODO: Optimisation: Once we have detected a file of a package,
            # this loads all files from this package because reasonably,
            # there will be other files from it.
            # rpm -qf /usr/lib64/libselinux.so.1
            # rpm -q -l libselinux-2.6-6.fc26.x86_64
            self.m_cacheFilesToPackages[oneFilNam] = lstPacks

            return lstPacks


    def GetPackagesList(self,lstPackagedFiles):

        # This command is very slow:
        # dnf provides /usr/bin/as

        # This is quite fast:
        # rpm -qf /bin/ls

        lstPackages = set()
        unknownFiles = []

        for oneFil in lstPackagedFiles:
            # sys.stdout.write("oneFil=%s tp=%s\n"%(oneFil,str(type(oneFil))))
            lstPacks = self.OneFileToPackageLinux(oneFil)
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

atexit.register( FileToPackage.DumpToFile, cim_objects_definitions.G_FilesToPackagesCache )


################################################################################

# Formatting function specific to TXT mode output file.ExceptionIsExit
def FmtTim(aTim):
    return aTim

class BatchDumperBase:
    def DocumentStart(self):
        return

    def DocumentEnd(self):
        return

    def Header(self, extra_header):
        return

    def Footer(self):
        return

class BatchDumperTXT(BatchDumperBase):
    def __init__(self, strm):
        self.m_strm = strm

    def DumpBatch(self,batchLet):
        self.m_strm.write("Pid=%6d {%4d/%s}%1s'%-20s' %s ==>> %s (%s,%s)\n" %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            linux_api_definitions.BatchStatus.chrDisplayCodes[batchLet.m_core.m_status],
            batchLet.m_core.m_funcNam,
            batchLet.SignificantArgs(),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )

class BatchDumperCSV(BatchDumperBase):
    def __init__(self, strm):
        self.m_strm = strm

    def Header(self, extra_header):
        if extra_header:
            self.m_strm.write("%s\n" % extra_header)
        self.m_strm.write("Pid,Occurrences,Style,Function,Arguments,Return,Start,End\n")

    def DumpBatch(self, batchLet):
        self.m_strm.write("%d,%d,%s,%s,%s,%s,%s,%s,%s\n" % (
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            batchLet.m_core.m_status,
            batchLet.m_core.m_funcNam,
            batchLet.SignificantArgs(),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd)))

# TODO: Must use json package.
class BatchDumperJSON(BatchDumperBase):
    def __init__(self, strm):
        self.m_strm = strm

    def DocumentStart(self):
        self.m_strm.write('[\n')
        self.m_top_delimiter = ""

    def DocumentEnd(self):
        self.m_strm.write(']\n')

    def Header(self, extra_header):
        self.m_strm.write(self.m_top_delimiter + '[\n')
        self.m_delimiter = ""
        self.m_top_delimiter = ","

    def DumpBatch(self, batchLet):
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
            json.dumps([str(arg) for arg in batchLet.SignificantArgs()]),
            json.dumps(batchLet.m_core.m_retValue), # It may contain double-quotes
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd)))
        self.m_delimiter = ","

    def Footer(self):
        self.m_strm.write(']\n')


################################################################################



BatchDumpersDictionary = {
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

def DefaultTracer(inputLogFile,tracer=None):
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
    logging.info("Tracer "+tracer)
    return tracer


def LoadIniFile(iniFilNam):
    mapKV = {}
    try:
        filOp =  open(iniFilNam)
        logging.info("Init "+iniFilNam)
    except IOError:
        return mapKV
    for linKV in filOp.readlines():
        clnKV = linKV.strip()
        if not clnKV: continue
        if clnKV[0] == ';': continue
        idxEq = clnKV.find('=')
        if idxEq < 0: continue
        prmKey = clnKV[:idxEq]
        prmVal = clnKV[idxEq+1:]
        mapKV[prmKey] = prmVal
    filOp.close()
    return mapKV

# This returns a stream with each line written by strace or ltrace.
def CreateEventLog(argsCmd, aPid, inputLogFile, tracer ):
    global G_Hostname
    global G_OSType

    # A command or a pid or an input log file, only one possibility.
    if argsCmd != []:
        if aPid > 0 or inputLogFile:
            Usage(1,"When providing command, must not specify process id or input log file")
    elif aPid> 0 :
        if argsCmd != []:
            Usage(1,"When providing process id, must not specify command or input log file")
    elif inputLogFile:
        if argsCmd != []:
            Usage(1,"When providing input file, must not specify command or process id")
    else:
        Usage(1,"Must provide command, pid or input file")

    dateTodayRun = time.strftime("%Y-%m-%d")
    theHostNam = socket.gethostname()
    thePlatform = sys.platform

    currWrkDir = os.getcwd()
    if inputLogFile:
        logStream = open(inputLogFile)
        logging.info("File "+inputLogFile)
        logging.info("Logfile %s pid=%s" % (inputLogFile,aPid) )

        # There might be a context file with important information to reproduce the test.
        contextLogFile = os.path.splitext(inputLogFile)[0]+"."+"ini"
        mapKV = LoadIniFile(contextLogFile)

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

        (linux_api_definitions.G_topProcessId, logStream)   = G_traceToTracer[tracer].LogFileStream(argsCmd,aPid)
        cim_objects_definitions.G_CurrentDirectory          = currWrkDir
        cim_objects_definitions.G_Today                     = dateTodayRun
        G_Hostname                                          = theHostNam
        G_OSType                                            = thePlatform

        cim_objects_definitions.G_ReplayMode = False

    cim_objects_definitions.G_SameMachine = not cim_objects_definitions.G_ReplayMode or G_Hostname == socket.gethostname()


    # Another possibility is to start a process or a thread which will monitor
    # the target process, and will write output information in a stream.

    return logStream


# Global variables which must be reinitialised before a run.
def InitGlobals( withWarning ):
    linux_api_definitions.InitLinuxGlobals(withWarning)

    cim_objects_definitions.InitGlobalObjects()

# Called after a run.
def ExitGlobals():
    cim_objects_definitions.ExitGlobalObjects()

################################################################################

# The role of an aggregator is to receive each function call and store it or not.
# It can aggregate the calls or process them in anyway, on the fly or at the end.
# There is one such object for each execution flow, which is a process
# or a thread.
def BatchFlowModelFactory(aggregators):
    if not aggregators:
        # This is the required interface for aggregators.
        class BatchFlowVoid(object):
            # For each function call.
            def SendBatch(self, oneBatch):
                return None

            # At the end.
            def FactorizeOneFlow(self, verbose, batchConstructor):
                pass

            # This factory must create such an object.
            @staticmethod
            def Factory():
                return BatchFlowVoid()

            def DumpFlowConstructor(self, batchDump, header_string):
                pass

        return BatchFlowVoid

    # This is temporary.
    if aggregators == ["clusterize"]:
        import dockit_aggregate_clusterize
        return dockit_aggregate_clusterize.BatchFlow

    # If there are several aggregators, import all of them and create a wrapper
    # with the right interface and runs the wrapper methods in a loop.

    raise Exception("Invalid aggregators:", aggregators)

################################################################################


# This receives a stream of lines, each of them is a function call,
# possibily unfinished/resumed/interrupted by a signal.
def CreateMapFlowFromStream(verbose, withWarning, logStream, tracer, batchConstructor, aggregators):
    # Here, we have an event log as a stream, which comes from a file (if testing),
    # the output of strace or anything else.

    InitGlobals(withWarning)

    mapFlows = {}

    batchFlowFactory = BatchFlowModelFactory(aggregators).Factory
    #batchConstructor = BatchDumpersDictionary[outputFormat]

    # This generator creates individual BatchLet objects on-the-fly.
    # At this stage, "resumed" calls are matched with the previously received "unfinished"
    # line for the same call.
    # Some calls, for some reason, might stay "unfinished": Though,
    # they are still needed to rebuild the processes tree.
    mapFlowsGenerator = G_traceToTracer[tracer].CreateFlowsFromLogger(verbose, logStream)

    # Maybe, some system calls are unfinished, i.e. the "resumed" part of the call
    # is never seen. They might be matched later.
    for oneBatch in mapFlowsGenerator:
        aCore = oneBatch.m_core


### NO: We must create immediately the derived objects so we can fill the caches in the right order.
### For example in the case where one file descriptor is created in a thread and used in another.
### In other words:
### - Loop on the incoming lines.
### - For each new pid ... or new burst of activity, create a coroutine:
###   This coroutine "is yielded" with new BatchCore objects.

        aPid = aCore.m_pid
        try:
            btchFlow = mapFlows[ aPid ]
        except KeyError:
            # This is the first system call of this process.
            btchFlow = batchFlowFactory()
            mapFlows[ aPid ] = btchFlow

        btchFlow.SendBatch(oneBatch)

    for aPid in sorted(list(mapFlows.keys()), reverse=True):
        btchTree = mapFlows[aPid]
        if verbose > 0: sys.stdout.write("\n------------------ PID=%d\n" % aPid)
        btchTree.FactorizeOneFlow(verbose, batchConstructor)

    ExitGlobals()
    return mapFlows

################################################################################

# All possible summaries. Data created for the summaries are also needed
# to generate a docker file. So, summaries are calculated if Dockerfile is asked.
fullMapParamsSummary = ["CIM_ComputerSystem","CIM_OperatingSystem","CIM_NetworkAdapter","CIM_Process","CIM_DataFile"]

def FromStreamToFlow(
        verbose, withWarning, logStream, tracer, outputFormat,
        baseOutName, mapParamsSummary, summaryFormat, withDockerfile, aggregators):
    if not baseOutName:
        baseOutName = "results"
    if summaryFormat:
        outputSummaryFile = baseOutName + ".summary." + summaryFormat.lower()
    else:
        outputSummaryFile = None

    try:
        batchConstructor = BatchDumpersDictionary[outputFormat]
    except KeyError:
        batchConstructor = None

    mapFlows = CreateMapFlowFromStream(verbose, withWarning, logStream, tracer, batchConstructor, aggregators)

    linux_api_definitions.G_stackUnfinishedBatches.PrintUnfinished(sys.stdout)

    if baseOutName and outputFormat:
        outFile = baseOutName + "." + outputFormat.lower()
        sys.stdout.write("Creating flow file:%s\n" % outFile)
        outFd = open(outFile, "w")
        batchDump = batchConstructor(outFd)
        batchDump.DocumentStart()

        for aPid in sorted(list(mapFlows.keys()),reverse=True):
            btchTree = mapFlows[aPid]
            btchTree.DumpFlowConstructor(batchDump, "================== PID=%d"%aPid)
        batchDump.DocumentEnd()
        outFd.close()

        if verbose: sys.stdout.write("\n")

    # Generating a docker file needs some data calculated withthe summaries.
    if withDockerfile:
        mapParamsSummary = fullMapParamsSummary

    GenerateSummary(mapParamsSummary, summaryFormat, outputSummaryFile)
    
    if withDockerfile:
        if outFile:
            baseOutName, filOutExt = os.path.splitext(outFile)
        elif outputSummaryFile:
            baseOutName, filOutExt = os.path.splitext(outputSummaryFile)
        else:
            baseOutName = "docker"
        dockerDirName = baseOutName + ".docker"
        if os.path.exists(dockerDirName):
            shutil.rmtree(dockerDirName)
        os.makedirs(dockerDirName)

        dockerFilename = dockerDirName + "/Dockerfile"
        cim_objects_definitions.GenerateDockerFile(dockerFilename)

    return outputSummaryFile

# Function called for unit tests by unittest.py
def UnitTest(
        inputLogFile, tracer, topPid, baseOutName, outputFormat, verbose, mapParamsSummary,
        summaryFormat, withWarning, withDockerfile, updateServer, aggregators):
    assert isinstance(topPid, int)
    logStream = CreateEventLog([], topPid, inputLogFile, tracer )
    cim_objects_definitions.G_UpdateServer = updateServer

    # Check if there is a context file, which gives parameters such as the current directory,
    # necessary to reproduce the test in the same conditions.

    outputSummaryFile = FromStreamToFlow(
        verbose, withWarning, logStream, tracer, outputFormat, baseOutName,
        mapParamsSummary, summaryFormat, withDockerfile, aggregators)
    return outputSummaryFile

if __name__ == '__main__':
    try:
        optsCmd, argsCmd = getopt.getopt(sys.argv[1:],
                "hvws:Dp:f:F:r:i:l:t:S:a:",
                ["help","verbose","warning","summary","summary-format",
                 "docker","pid","format","repetition","input",
                 "log","tracer","server","aggregator"])
    except getopt.GetoptError as err:
        # print help information and exit:
        Usage(2,err) # will print something like "option -a not recognized"

    verbose = 0
    withWarning = 0

    # By default, generates all summaries. The filter syntax is based on CIM object pathes:
    # -s 'Win32_LogicalDisk.DeviceID="C:",Prop="Value",Prop="Regex"'
    # -s "CIM+_DataFile:Category=['Others','Shared libraries']"
    #
    # At the moment, the summary generates only two sorts of objects: CIM_Process and CIM_DataFile.
    # mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"]
    mapParamsSummary = fullMapParamsSummary

    withDockerfile = None

    aPid = -1
    outputFormat = "TXT" # Default output format of the generated files.
    szWindow = 0
    inputLogFile = None
    summaryFormat = None
    outputLogFilePrefix = None
    tracer = None
    aggregators = []

    for anOpt, aVal in optsCmd:
        if anOpt in ("-v", "--verbose"):
            verbose += 1
        elif anOpt in ("-w", "--warning"):
            withWarning += 1
        elif anOpt in ("-s", "--summary"):
            mapParamsSummary = mapParamsSummary + [ aVal ] if aVal else []
        elif anOpt in ("-D", "--dockerfile"):
            withDockerfile = True
        elif anOpt in ("-p", "--pid"):
            aPid = int(aVal)
        elif anOpt in ("-f", "--format"):
            outputFormat = aVal.upper()
        elif anOpt in ("-F", "--summary_format"):
            summaryFormat = aVal.upper()
        elif anOpt in ("-w", "--window"):
            szWindow = int(aVal)
            raise Exception("Sliding window not implemented yet")
        elif anOpt in ("-i", "--input"):
            inputLogFile = aVal
        elif anOpt in ("-l", "--log"):
            outputLogFilePrefix = aVal
        elif anOpt in ("-t", "--tracer"):
            tracer = aVal
        elif anOpt in ("-S", "--server"):
            cim_objects_definitions.G_UpdateServer = aVal
        elif anOpt in ("-a", "--aggregator"):
            aggregators.append(aVal)
        elif anOpt in ("-h", "--help"):
            Usage(0)
        else:
            assert False, "Unhandled option"


    tracer = DefaultTracer( inputLogFile, tracer )
    logStream = CreateEventLog(argsCmd, aPid, inputLogFile, tracer )

    if outputLogFilePrefix:
        fullPrefixNoExt = "%s.%s.%s." % ( outputLogFilePrefix, tracer, linux_api_definitions.G_topProcessId )

        # tee: This just needs to reimplement "readline()"
        class TeeStream:
            def __init__(self,logStrm):
                self.m_logStrm = logStrm
                logFilNam = fullPrefixNoExt + "log"
                self.m_outFd = open( logFilNam, "w" )
                print("Creating log file:%s" % logFilNam )

            def readline(self):
                # sys.stdout.write("xxx\n" )
                aLin = self.m_logStrm.readline()
                # sys.stdout.write("tee=%s" % aLin)
                self.m_outFd.write(aLin)
                return aLin

        logStream = TeeStream(logStream)

        #outFilExt = outputFormat.lower() # "txt", "xml" etc...
        #outFilNam = fullPrefixNoExt + outFilExt

        # If not replaying, saves all parameters in an ini file.
        if not cim_objects_definitions.G_ReplayMode:
            iniFilNam = fullPrefixNoExt + "ini"
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
        fullPrefixNoExt = "dockit_output_" + tracer

    # In normal usage, the summary output format is the same as the output format for calls.
    FromStreamToFlow(
        verbose,
        withWarning,
        logStream,
        tracer,
        outputFormat,
        fullPrefixNoExt,
        mapParamsSummary,
        summaryFormat,
        withDockerfile,
        aggregators)

################################################################################
# The End.
################################################################################
