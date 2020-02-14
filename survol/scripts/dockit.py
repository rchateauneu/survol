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

import cProfile
import re
import sys
import getopt
import os
import subprocess
import time
import signal
import inspect
import socket
import json
import atexit
import datetime
import shutil
import tempfile

import linux_api_definitions
import cim_objects_definitions

def Usage(exitCode = 1, errMsg = None):
    if errMsg:
        print(errMsg)

    progNam = sys.argv[0]
    print("DockIT: %s <executable>"%progNam)
    print("Monitors and factorizes systems calls.")
    print("  -h,--help                     This message.")
    print("  -v,--verbose                  Verbose mode (Cumulative).")
    print("  -w,--warning                  Display warnings (Cumulative).")
    print("  -s,--summary <CIM class>      Prints a summary at the end: Start end end time stamps, executable name,\n"
        + "                                loaded libraries, read/written/created files and timestamps, subprocesses tree.\n"
        + "                                Examples: -s 'Win32_LogicalDisk.DeviceID=\"C:\",Prop1=\"Value1\",Prop2=\"Value2\"'\n"
        + "                                          -s 'CIM_DataFile:Category=[\"Others\",\"Shared libraries\"]'" )
    print("  -D,--dockerfile               Generates a dockerfile.")
    print("  -p,--pid <pid>                Monitors a running process instead of starting an executable.")
    print("  -f,--format TXT|CSV|JSON      Output format. Default is TXT.")
    print("  -F,--summary-format TXT|XML   Summary output format. Default is XML.")
    print("  -i,--input <file name>        trace command input file.")
    print("  -l,--log <filename prefix>    trace command log output file.\n")
    print("  -t,--tracer strace|ltrace|cdb command for generating trace log")
    print("  -S,--server <Url>             Survol url for CIM objects updates. Ex: http://127.0.0.1:80/survol/event_put.py")
    print("")
    print("strace command: "+" ".join(BuildSTraceCommand(["<command>"],None)))
    print("                "+" ".join(BuildSTraceCommand(None,"<pid>")))
    print("ltrace command: "+" ".join(BuildLTraceCommand(["<command>"],None)))
    print("                "+" ".join(BuildLTraceCommand(None,"<pid>")))
    print("")
    if STraceVersion() < (4,21):
        # It needs the option "-y"
        print("strace version deprecated. Consider upgrading")

# Example to create a new unit test:
# ./dockit.py -D -l UnitTests/mineit_firefox  -t  ltrace bash firefox

    sys.exit(exitCode)

################################################################################
# This is set by a signal handler when a control-C is typed.
# It then triggers a clean exit, and creation of output results.
# This allows to monitor a running process, just for a given time
# without stopping it.
G_Interrupt = False

################################################################################

def LogWindowsFileStream(extCommand,aPid):
    raise Exception("Not implemented yet")

def CreateFlowsFromWindowsLogger(verbose,logStream):
    raise Exception("Not implemented yet")

################################################################################

# Max bytes number when strace or ltrace display read() and write() calls.
G_StringSize = "500"


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


# This groups several contiguous BatchLet which form a logical operation.
# For example (If the argument is factorised).:
#   Read(x)
#   Write(x)
#
# ... or ...
#   fseek("dummy.txt")
#   fwrite("dummy.txt")
#
# There can be several way to "reuse" a sequence, depending on other similar
# sequences.
#
class BatchLetSequence(linux_api_definitions.BatchLetBase, object):
    def __init__(self,arrBatch,style):
        batchCore = linux_api_definitions.BatchLetCore()

        # TODO: Instead of a string, this could be a tuple because it is hashable.
        concatSigns = "+".join( [ btch.GetSignature() for btch in arrBatch ] )
        batchCore.m_funcNam = "(" + concatSigns + ")"

        batchCore.m_status = linux_api_definitions.BatchStatus.sequence

        # sys.stdout.write("BatchLetSequence concatSigns=%s\n"%concatSigns)

        # This is returned by the method SignificantArgs()

        # Cannot use a set because lists are not hashable, and objects always different.
        # Because there are very few arguments, it is allright to iterate on each list.
        argsArray = []
        for btch in arrBatch:
            for oneArg in btch.SignificantArgs():
                if not oneArg in argsArray:
                    argsArray.append( oneArg )
        batchCore.m_parsedArgs = argsArray

        # All batchlets should have the same pid.
        batchCore.m_pid = arrBatch[0].m_core.m_pid

        batchCore.m_timeStart = arrBatch[0].m_core.m_timeStart
        batchCore.m_timeEnd = arrBatch[-1].m_core.m_timeEnd
        batchCore.m_execTim = datetime.datetime.strptime(batchCore.m_timeEnd, '%H:%M:%S.%f') - datetime.datetime.strptime(batchCore.m_timeStart, '%H:%M:%S.%f')

        super( BatchLetSequence,self).__init__(batchCore,style)



def SignatureForRepetitions(batchRange):
    return "+".join( [ aBtch.GetSignatureWithArgs() for aBtch in batchRange ] )


BatchDumpersDictionary = {
    "TXT": BatchDumperTXT,
    "CSV": BatchDumperCSV,
    "JSON": BatchDumperJSON
}


# This is an execution flow, associated to a process. And a thread ?
class BatchFlow:
    def __init__(self):

        self.m_listBatchLets = []
        self.m_coroutine = self.AddingCoroutine()
        next(self.m_coroutine)

    # It processes system calls on-the-fly without intermediate storage.
    def SendBatch(self,btchLet):
        self.m_coroutine.send(btchLet)

    def AddingCoroutine(self):
        lstBatch = None
        while True:
            btchLet = yield
            
            if lstBatch and lstBatch.SameCall( btchLet ):
                # This is a compression: Similar and consecutive calls are stored once only.
                lstBatch.m_occurrences += 1
            else:
                self.m_listBatchLets.append( btchLet )
            # Intentionally points to the object actually stored in the container,
            # instead of the possibly transient object returned by yield.
            lstBatch = self.m_listBatchLets[-1]

        

    # This removes matched batches (Formerly unfinished calls which were matched to the resumed part)
    # when the merged batches (The resumed calls) comes immediately after.
    def FilterMatchedBatches(self):
        lenBatch = len(self.m_listBatchLets)

        numSubst = 0
        idxBatch = 1
        while idxBatch < lenBatch:
            # sys.stdout.write("FilterMatchedBatches idxBatch=%d\n"%( idxBatch ) )
            batchSeq = self.m_listBatchLets[idxBatch]
            batchSeqPrev = self.m_listBatchLets[idxBatch-1]

            # Sanity check.
            if batchSeqPrev.m_core.m_status == linux_api_definitions.BatchStatus.matched \
            and batchSeq.m_core.m_status == linux_api_definitions.BatchStatus.merged:
                if batchSeqPrev.m_core.m_funcNam != batchSeq.m_core.m_funcNam :
                    raise Exception("INCONSISTENCY1 %s %s\n"% ( batchSeq.m_core.m_funcNam, batchSeqPrev.m_core.m_funcNam ) )

            if batchSeqPrev.m_core.m_status == linux_api_definitions.BatchStatus.matched \
            and batchSeq.m_core.m_status == linux_api_definitions.BatchStatus.merged:
                if batchSeqPrev.m_core.m_resumedBatch.m_unfinishedBatch != batchSeqPrev.m_core:
                    raise Exception("INCONSISTENCY2 %s\n"% batchSeqPrev.m_core.m_funcNam)

            if batchSeqPrev.m_core.m_status == linux_api_definitions.BatchStatus.matched \
            and batchSeq.m_core.m_status == linux_api_definitions.BatchStatus.merged:
                if batchSeq.m_core.m_unfinishedBatch.m_resumedBatch != batchSeq.m_core:
                    raise Exception("INCONSISTENCY3 %s\n"% batchSeq.m_core.m_funcNam)

            if batchSeqPrev.m_core.m_status == linux_api_definitions.BatchStatus.matched \
            and batchSeq.m_core.m_status == linux_api_definitions.BatchStatus.merged \
            and batchSeqPrev.m_core.m_resumedBatch == batchSeq.m_core \
            and batchSeq.m_core.m_unfinishedBatch == batchSeqPrev.m_core :
                del self.m_listBatchLets[idxBatch-1]
                batchSeq.m_core.m_unfinishedBatch = None
                lenBatch -= 1
                numSubst += 1

            idxBatch += 1
            
        return numSubst

    # This counts the frequency of consecutive pairs of calls.
    # Used to replace these common pairs by an aggregate call.
    # See https://en.wikipedia.org/wiki/N-gram about bigrams.
    # About statistics: https://books.google.com/ngrams/info
    def StatisticsBigrams(self):

        lenBatch = len(self.m_listBatchLets)

        mapOccurences = {}

        idxBatch = 0
        maxIdx = lenBatch - 1
        while idxBatch < maxIdx:
            batchRange = self.m_listBatchLets[ idxBatch : idxBatch + 2 ]

            keyRange = SignatureForRepetitions( batchRange )

            try:
                mapOccurences[ keyRange ] += 1
            except KeyError:
                mapOccurences[ keyRange ] = 1
            idxBatch += 1

        return mapOccurences

    # This examines pairs of consecutive calls with their arguments, and if a pair
    # occurs often enough, it is replaced by a single BatchLetSequence which represents it.
    def ClusterizeBigrams(self):
        lenBatch = len(self.m_listBatchLets)

        mapOccurences = self.StatisticsBigrams()

        numSubst = 0
        idxBatch = 0
        maxIdx = lenBatch - 1
        batchSeqPrev = None
        while idxBatch < maxIdx:

            batchRange = self.m_listBatchLets[ idxBatch : idxBatch + 2 ]
            keyRange = SignatureForRepetitions( batchRange )
            numOccur = mapOccurences.get( keyRange, 0 )

            # sys.stdout.write("ClusterizeBigrams keyRange=%s numOccur=%d\n" % (keyRange, numOccur) )

            # Five occurences for example, as representative of a repetition.
            if numOccur > 5:
                batchSequence = BatchLetSequence( batchRange, "Rept" )

                # Maybe it is the same as the previous element, if this is a periodic pattern.
                if batchSeqPrev and batchSequence.SameCall( batchSeqPrev ):
                    # Simply reuse the previous batch.
                    batchSeqPrev.m_occurrences += 1
                    del self.m_listBatchLets[ idxBatch : idxBatch + 2 ]
                    maxIdx -= 2
                else:
                    self.m_listBatchLets[ idxBatch : idxBatch + 2 ] = [ batchSequence ]
                    maxIdx -= 1
                    batchSeqPrev = batchSequence
                    idxBatch += 1

                numSubst += 1
            else:
                batchSeqPrev = None
                idxBatch += 1
            
        return numSubst

    # Successive calls which have the same arguments are clusterized into logical entities.
    def ClusterizeBatchesByArguments(self):
        lenBatch = len(self.m_listBatchLets)

        numSubst = 0
        idxLast = 0
        idxBatch = 1
        while idxBatch <= lenBatch:
            if idxBatch < lenBatch:
                lastBatch = self.m_listBatchLets[ idxLast ]
                lastArgs = lastBatch.SignificantArgs()
                if not lastArgs:
                    idxLast += 1
                    idxBatch += 1
                    continue

                currentBatch = self.m_listBatchLets[ idxBatch ]

                if currentBatch.SignificantArgs() == lastArgs:
                    idxBatch += 1
                    continue

            if idxBatch > idxLast + 1:

                # Clusters should not be too big
                batchSeq = BatchLetSequence( self.m_listBatchLets[ idxLast : idxBatch ], "Args" )
                self.m_listBatchLets[ idxLast : idxBatch ] = [ batchSeq ]

                lenBatch -= ( idxBatch - idxLast - 1 )
                numSubst += 1

            idxLast += 1
            idxBatch = idxLast + 1
        return numSubst

    def DumpFlowInternal(self, batchDump, extra_header = None):
        batchDump.Header(extra_header)
        for aBtch in self.m_listBatchLets:
            batchDump.DumpBatch(aBtch)
        batchDump.Footer()

    def DumpFlowSimple(self, strm, outputFormat):
        batchConstructor = BatchDumpersDictionary[outputFormat]
        batchDump = batchConstructor(strm)
        self.DumpFlowInternal(batchDump)

    def DumpFlowConstructor(self, batchDump, extra_header = None):
        self.DumpFlowInternal(batchDump)

    def FactorizeOneFlow(self, verbose, outputFormat):

        if verbose > 1: self.DumpFlowSimple(sys.stdout,outputFormat)

        if verbose > 0:
            sys.stdout.write("\n")
            sys.stdout.write("FilterMatchedBatches lenBatch=%d\n"%(len(self.m_listBatchLets)) )
        numSubst = self.FilterMatchedBatches()
        if verbose > 0:
            sys.stdout.write("FilterMatchedBatches numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )

        idxLoops = 0
        while True:
            if verbose > 1:
                self.DumpFlowSimple(sys.stdout,outputFormat)

            if verbose > 0:
                sys.stdout.write("\n")
                sys.stdout.write("ClusterizeBigrams lenBatch=%d\n"%(len(self.m_listBatchLets)) )
            numSubst = self.ClusterizeBigrams()
            if verbose > 0:
                sys.stdout.write("ClusterizeBigrams numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )
            if numSubst == 0:
                break
            idxLoops += 1

        if verbose > 1: self.DumpFlowSimple(sys.stdout,outputFormat)

        if verbose > 0:
            sys.stdout.write("\n")
            sys.stdout.write("ClusterizeBatchesByArguments lenBatch=%d\n"%(len(self.m_listBatchLets)) )
        numSubst = self.ClusterizeBatchesByArguments()
        if verbose > 0:
            sys.stdout.write("ClusterizeBatchesByArguments numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )

        if verbose > 1: self.DumpFlowSimple(sys.stdout,outputFormat)


# Logging execution information.
def LogSource(msgSource):
    sys.stdout.write("Parameter:%s\n"%msgSource)

################################################################################

# This executes a Linux command and returns the stderr pipe.
# It is used to get the return content of strace or ltrace,
# so it can be parsed.
def GenerateLinuxStreamFromCommand(raw_command, aPid):
    def quote_argument(elt):
        # Quotes in command-line arguments must be escaped.
        elt = str(elt).replace('"', '\\"').replace("'", "\\'")
        # Quotes the command-line argument if it contains spaces or tabs.
        if " " in elt or "\t" in elt:
            elt = '"%s"' % elt
        return elt

    aCmd = [quote_argument(elt) for elt in raw_command]
    assert isinstance(aPid, int)
    sys.stdout.write("Starting trace command:%s\n" % " ".join(aCmd) )

    # If shell=True, the command must be passed as a single line.
    kwargs = {"bufsize":100000, "shell":False,
        "stdin":sys.stdin, "stdout":subprocess.PIPE, "stderr":subprocess.PIPE}
    if sys.version_info >= (3,):
        kwargs["encoding"] = "utf-8"
    pipPOpen = subprocess.Popen(aCmd, **kwargs)

    # If shell argument is True, this is the process ID of the spawned shell.
    if aPid > 0:
        # The process already exists and strace/ltrace attaches to it.
        thePid = aPid
    else:
        # We want the pid of the process created by strace/ltrace.
        # ltrace always prefixes each line with the pid, so no ambiguity.
        # strace does not always prefixes the top process calls with the pid.
        thePid = int(pipPOpen.pid)

    return ( thePid, pipPOpen.stderr )

# This applies to strace and ltrace.
# It isolates single lines describing an individual function or system call.
def CreateFlowsFromGenericLinuxLog(verbose,logStream,tracer):

    # "[pid 18196] 08:26:47.199313 close(255</tmp/shell.sh> <unfinished ...>"
    # "08:26:47.197164 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 18194 <0.011216>"
    # This test is not reliable because we cannot really control what a spurious output can be:
    def IsLogEnding(aLin):
        if aLin.endswith(">\n"):
            ixLT = aLin.rfind("<")
            if ixLT >= 0:
                strBrack = aLin[ixLT+1:-2]
                try:
                    flt = float(strBrack)
                    return True
                except:
                    pass

                if strBrack == "unfinished ...":
                    return True

                # This value occurs exclusively with ltrace. Examples:
                # exit_group@SYS(0 <no return ...>
                # execve@SYS("/usr/bin/as", 0xd1a138, 0xd1a2b0 <no return ...>
                if strBrack == "no return ...":
                    return True
        else:
            # "[pid 18194] 08:26:47.197005 exit_group(0) = ?"
            # Not reliable because this could be a plain string ending like this.
            if aLin.startswith("[pid ") and aLin.endswith(" = ?\n"):
                return True

            # "08:26:47.197304 --- SIGCHLD {si_signo=SIGCHLD, si_status=0, si_utime=0, si_stime=0} ---"
            # Not reliable because this could be a plain string ending like this.
            if aLin.endswith(" ---\n"):
                return True

        return False


    # This is parsed from each line corresponding to a syztem call.
    batchCore = None

    lastTimeStamp = 0

    numLine = 0
    oneLine = ""
    while True:
        prevLine = oneLine
        oneLine = ""

        # There are several cases of line ending with strace.
        # If a function has a string parameter which contain a carriage-return,
        # this is not filtered and this string is split on multiple lines.
        # We cannot reliably count the double-quotes.
        # FIXME: Problem if several processes.
        while not G_Interrupt:
            # sys.stdout.write("000:\n")
            tmpLine = logStream.readline()
            # sys.stdout.write("AAA:%s"%tmpLine)
            numLine += 1
            # sys.stdout.write("tmpLine after read=%s"%tmpLine)
            if not tmpLine:
                break

            # "[pid 18196] 08:26:47.199313 close(255</tmp/shell.sh> <unfinished ...>"
            # "08:26:47.197164 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 18194 <0.011216>"
            # This test is not reliable because we cannot really control what a spurious output can be:
            if IsLogEnding( tmpLine ):
                # TODO: The most common case is that the call is on one line only.
                oneLine += tmpLine
                break

            # If the call is split on several lines, maybe because a write() contains a "\n".
            oneLine += tmpLine[:-1]

        if not oneLine:
            # If this is the last line and therefore the last call.
            sys.stdout.write("Last line=%s\n"%prevLine)

            # This is the terminate date of the last process still running.
            if lastTimeStamp:
                cim_objects_definitions.CIM_Process.GlobalTerminationDate(lastTimeStamp)

            break

        # This parses the line into the basic parameters of a function call.
        try:
            batchCore = linux_api_definitions.CreateBatchCore(oneLine,tracer)
        except Exception as exc:
            if numLine == 2:
                # If the command does not exist:
                # "strace: Can't stat 'qklsjhdflksd': No such file or directory"
                # "Can't open qklsjhdflksd: No such file or directory"
                if oneLine.find("No such file or directory") >= 0:
                    raise Exception("Invalid command: %s: %s" % (oneLine, exc))

                # If the pid is invalid, the scond contains "No such process"
                # "strace: attach: ptrace(PTRACE_SEIZE, 11111): No such process"
                # "Cannot attach to pid 11111: No such process"
                if oneLine.find("No such process") >= 0:
                    raise Exception("Invalid process id: %s" % (oneLine, exc))

            sys.stderr.write("Caught invalid line %d:%s: %s\n"%(numLine, oneLine, exc) )
            # raise

        # Maybe the line cannot be parsed.
        if batchCore:

            lastTimeStamp = batchCore.m_timeEnd

            # This creates a derived class deduced from the system call.
            #aBatch = linux_api_definitions.BatchLetFactory(batchCore)
            try:
                aBatch = linux_api_definitions.BatchLetFactory(batchCore)
            except Exception as exc:
                sys.stderr.write("Line:%d Error parsing:%s. %s\n" % (numLine, oneLine, exc))

            # Some functions calls should simply be forgotten because there are
            # no side effects, so simply forget them.
            if aBatch:
                yield aBatch

################################################################################

# The command options generate a specific output file format,
# and therefore parsing it is specific to these options.
def BuildLTraceCommand(extCommand,aPid):

    # This selects:
    # libpython2.7.so.1.0->getenv, cx_Oracle.so->getenv, libclntsh.so.11.1->getenv, libresolv.so.2->getenv etc...
    strMandatoryLibc = "-*+getenv+*@SYS"

    # -f  Trace  child  processes as a result of the fork, vfork and clone.
    # This needs long strings because path names are truncated like normal strings.
    aCmd = ["ltrace",
        "-tt", "-T", "-f", "-S", "-s", G_StringSize,
        "-e", strMandatoryLibc
        ]

    # Example of log: This can be filtered with: "-e -realpath"
    # gcc->realpath(0x2abfbe0, 0x7ffd739d8310, 0x2ac0930, 0 <unfinished ...>
    # lstat@SYS("/usr", 0x7ffd739d8240)                    = 0 <0.000167>
    # lstat@SYS("/usr/local", 0x7ffd739d8240)              = 0 <0.000118>
    # lstat@SYS("/usr/local/include", 0x7ffd739d8240)      = 0 <0.000162>
    # lstat@SYS("/usr/local/include/bits", 0x7ffd739d8240) = -2 <0.000177>
    # <... realpath resumed> )                             = 0 <0.001261>

    if extCommand:
        aCmd += extCommand
    else:
        aCmd += [ "-p", aPid ]

    return aCmd

def LogLTraceFileStream(extCommand,aPid):
    aCmd = BuildLTraceCommand( extCommand, aPid )
    if extCommand:
        LogSource("Command "+" ".join(extCommand) )
    else:
        LogSource("Process %s\n"%aPid)
    return GenerateLinuxStreamFromCommand(aCmd, aPid)


# The output log format of ltrace is very similar to strace's, except that:
# - The system calls are suffixed with "@SYS" or prefixed with "SYS_"
# - Entering and leaving a shared library is surrounded by the lines:
# ...  Py_Main(...  <unfinished ...>
# ...  <... Py_Main resumed> ) 
# - It does not print the path of file descriptors.

# [pid 28696] 08:50:25.573022 rt_sigaction@SYS(33, 0x7ffcbdb8f840, 0, 8) = 0 <0.000032>
# [pid 28696] 08:50:25.573070 rt_sigprocmask@SYS(1, 0x7ffcbdb8f9b8, 0, 8) = 0 <0.000033>
# [pid 28696] 08:50:25.573127 getrlimit@SYS(3, 0x7ffcbdb8f9a0) = 0 <0.000028>
# [pid 28696] 08:50:25.576494 __libc_start_main([ "python", "TestProgs/mineit_mysql_select.py"... ] <unfinished ...>
# [pid 28696] 08:50:25.577718 Py_Main(2, 0x7ffcbdb8faf8, 0x7ffcbdb8fb10, 0 <unfinished ...>
# [pid 28696] 08:50:25.578559 ioctl@SYS(0, 0x5401, 0x7ffcbdb8f860, 653) = 0 <0.000037>
# [pid 28696] 08:50:25.578649 brk@SYS(nil)         = 0x21aa000 <0.000019>
# [pid 28696] 08:50:25.578682 brk@SYS(0x21cb000)   = 0x21cb000 <0.000021>
# ...
# [pid 28735] 08:51:40.608641 rt_sigaction@SYS(2, 0x7ffeaa2e6870, 0x7ffeaa2e6910, 8)                                = 0 <0.000109>
# [pid 28735] 08:51:40.611613 sendto@SYS(3, 0x19a7fd8, 5, 0)                                                        = 5 <0.000445>
# [pid 28735] 08:51:40.612230 shutdown@SYS(3, 2, 0, 0)                                                              = 0 <0.000119>
# [pid 28735] 08:51:40.612451 close@SYS(3)                                                                          = 0 <0.000156>
# [pid 28735] 08:51:40.615726 close@SYS(7)                                                                          = 0 <0.000305>
# [pid 28735] 08:51:40.616610 <... Py_Main resumed> )                                                               = 0 <1.092079>
# [pid 28735] 08:51:40.616913 exit_group@SYS(0 <no return ...>



def CreateFlowsFromLtraceLog(verbose,logStream):
    # The output format of the command ltrace seems very similar to strace
    # so for the moment, no reason not to use it.
    return CreateFlowsFromGenericLinuxLog(verbose,logStream,"ltrace")

################################################################################
def STraceVersion():
    strace_version_str = subprocess.check_output('strace -V', shell=True).split()[3]
    return tuple(map(int, strace_version_str.split(b'.')))

def LTraceVersion():
    ltrace_version_str = subprocess.check_output('strace -V', shell=True).split()[2]
    return tuple(map(int, ltrace_version_str.split(b'.')))

# The command options generate a specific output file format,
# and therefore parsing it is specific to these options.
def BuildSTraceCommand(extCommand,aPid):
    # -f  Trace  child  processes as a result of the fork, vfork and clone.
    aCmd = ["strace", "-q", "-qq", "-f", "-tt", "-T", "-s", G_StringSize]

    if STraceVersion() < (4,21):
        aCmd += [ "-e", "trace=desc,ipc,process,network"]
    else:
        aCmd += [ "-y", "-yy", "-e", "trace=desc,ipc,process,network,memory"]

    if extCommand:
        # Run tracer process as a detached grandchild, not as parent of the tracee. This reduces the visible
        # effect of strace by keeping the tracee a direct child of the calling process.
        aCmd += [ "-D" ]
        aCmd += extCommand
    else:
        aCmd += [ "-p", aPid ]
    return aCmd

#
# 22:41:05.094710 rt_sigaction(SIGRTMIN, {0x7f18d70feb20, [], SA_RESTORER|SA_SIGINFO, 0x7f18d7109430}, NULL, 8) = 0 <0.000008>
# 22:41:05.094841 rt_sigaction(SIGRT_1, {0x7f18d70febb0, [], SA_RESTORER|SA_RESTART|SA_SIGINFO, 0x7f18d7109430}, NULL, 8) = 0 <0.000018>
# 22:41:05.094965 rt_sigprocmask(SIG_UNBLOCK, [RTMIN RT_1], NULL, 8) = 0 <0.000007>
# 22:41:05.095113 getrlimit(RLIMIT_STACK, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0 <0.000008>
# 22:41:05.095350 statfs("/sys/fs/selinux", 0x7ffd5a97f9e0) = -1 ENOENT (No such file or directory) <0.000019>
#
# The command parameters and the parsing are specific to strace.
# It returns a data structure which is generic.

def LogSTraceFileStream(extCommand,aPid):
    aCmd = BuildSTraceCommand( extCommand, aPid )
    if extCommand:
        LogSource("Command "+" ".join(extCommand) )
    else:
        LogSource("Process %s\n"%aPid)
    return GenerateLinuxStreamFromCommand(aCmd, aPid)

def CreateFlowsFromLinuxSTraceLog(verbose,logStream):
    return CreateFlowsFromGenericLinuxLog(verbose,logStream,"strace")


################################################################################

# This is const
G_traceToTracer = {
    "cdb"    : ( LogWindowsFileStream, CreateFlowsFromWindowsLogger ),
    "strace" : ( LogSTraceFileStream , CreateFlowsFromLinuxSTraceLog ),
    "ltrace" : ( LogLTraceFileStream, CreateFlowsFromLtraceLog )
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
                tracer = "cdb"
            elif sys.platform.startswith("linux"):
                # This could also be "ltrace", but "strace" is more usual.
                tracer = "strace"
            else:
                raise Exception("Unknown platform")
    LogSource("Tracer "+tracer)
    return tracer


def LoadIniFile(iniFilNam):
    mapKV = {}
    try:
        filOp =  open(iniFilNam)
        LogSource("Init "+iniFilNam)
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
        LogSource("File "+inputLogFile)
        LogSource("Logfile %s pid=%s" % (inputLogFile,aPid) )

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
        try:
            funcTrace = G_traceToTracer[ tracer ][0]
        except KeyError:
            raise Exception("Unknown tracer:%s"%tracer)

        (linux_api_definitions.G_topProcessId, logStream)  = funcTrace(argsCmd,aPid)
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

# This receives a stream of lines, each of them is a function call,
# possibily unfinished/resumed/interrupted by a signal.
def CreateMapFlowFromStream( verbose, withWarning, logStream, tracer,outputFormat):
    # Here, we have an event log as a stream, which comes from a file (if testing),
    # the output of strace or anything else.

    InitGlobals(withWarning)

    mapFlows = {}

    # This step transforms the input log into a map of BatchFlow,
    # which have the same format whatever the platform is.
    try:
        funcCreator = G_traceToTracer[ tracer ][1]
    except KeyError:
        raise Exception("Unknown tracer:%s"%tracer)

    # This generator creates individual BatchLet objects on-the-fly.
    # At this stage, "resumed" calls are matched with the previously received "unfinished"
    # line for the same call.
    # Some calls, for some reason, might stay "unfinished": Though,
    # they are still needed to rebuild the processes tree.
    mapFlowsGenerator = funcCreator(verbose,logStream)

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
            btchFlow = BatchFlow()
            mapFlows[ aPid ] = btchFlow

        btchFlow.SendBatch(oneBatch)

    for aPid in sorted(list(mapFlows.keys()), reverse=True):
        btchTree = mapFlows[aPid]
        if verbose > 0: sys.stdout.write("\n------------------ PID=%d\n" % aPid)
        btchTree.FactorizeOneFlow(verbose, outputFormat)

    ExitGlobals()
    return mapFlows

################################################################################

# All possible summaries. Data created for the summaries are also needed
# to generate a docker file. So, summaries are calculated if Dockerfile is asked.
fullMapParamsSummary = ["CIM_ComputerSystem","CIM_OperatingSystem","CIM_NetworkAdapter","CIM_Process","CIM_DataFile"]

def FromStreamToFlow(
        verbose, withWarning, logStream, tracer, outputFormat,
        baseOutName, mapParamsSummary, summaryFormat, withDockerfile):
    if not baseOutName:
        baseOutName = "results"
    if summaryFormat:
        outputSummaryFile = baseOutName + ".summary." + summaryFormat.lower()
    else:
        outputSummaryFile = None

    mapFlows = CreateMapFlowFromStream( verbose, withWarning, logStream, tracer, outputFormat)

    linux_api_definitions.G_stackUnfinishedBatches.PrintUnfinished(sys.stdout)

    if baseOutName and outputFormat:
        outFile = baseOutName + "." + outputFormat.lower()
        sys.stdout.write("Creating flow file:%s\n" % outFile)
        outFd = open(outFile, "w")
        batchConstructor = BatchDumpersDictionary[outputFormat]
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
        summaryFormat, withWarning, withDockerfile, updateServer):
    assert isinstance(topPid, int)
    logStream = CreateEventLog([], topPid, inputLogFile, tracer )
    cim_objects_definitions.G_UpdateServer = updateServer

    # Check if there is a context file, which gives parameters such as the current directory,
    # necessary to reproduce the test in the same conditions.

    outputSummaryFile = FromStreamToFlow(
        verbose, withWarning, logStream, tracer, outputFormat, baseOutName,
        mapParamsSummary, summaryFormat, withDockerfile)
    return outputSummaryFile

if __name__ == '__main__':
    try:
        optsCmd, argsCmd = getopt.getopt(sys.argv[1:],
                "hvws:Dp:f:F:r:i:l:t:S:",
                ["help","verbose","warning","summary","summary-format",
                 "docker","pid","format","repetition","input",
                 "log","tracer","server"])
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
            aPid = aVal
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

    def signal_handler(signal, frame):
        print('You pressed Ctrl+C!')
        global G_Interrupt
        G_Interrupt = True

    # Generates output files if interrupt with control-C.
    signal.signal(signal.SIGINT, signal_handler)
    print('Press Ctrl+C to exit cleanly')

    # In normal usage, the summary output format is the same as the output format for calls.
    FromStreamToFlow(verbose, withWarning, logStream, tracer,outputFormat, fullPrefixNoExt, mapParamsSummary, summaryFormat, withDockerfile )

################################################################################
# The End.
################################################################################
