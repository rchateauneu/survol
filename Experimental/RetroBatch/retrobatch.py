#!/usr/bin/python


import re
import sys
import getopt
import os
import subprocess
import time
import signal
import inspect

try:
    # To add more information to processes etc...
    # If not there, this is not a problem.
    import psutil
except ImportError:
    pass

def Usage(exitCode = 1, errMsg = None):
    if errMsg:
        print(errMsg)

    progNam = sys.argv[0]
    print("Retrobatch: %s <executable>"%progNam)
    print("Monitors and factorizes systems calls.")
    print("  -h,--help                     This message.")
    print("  -v,--verbose                  Verbose mode (Cumulative).")
    print("  -w,--warning                  Display warnings (Cumulative).")
    print("  -s,--summary <CIM class>      Prints a summary at the end: Start end end time stamps, executable name,\n"
        + "                                loaded libraries, read/written/created files and timestamps, subprocesses tree.")
    print("  -p,--pid <pid>                Monitors a running process instead of starting an executable.")
    print("  -f,--format TXT|CSV|JSON|XML  Output format. Default is TXT.")
    print("  -i,--input <file name>        trace command input file.")
    print("  -o,--output <file name>       summary output file.")
    print("  -l,--log <filename prefix>    trace command log output file.")
    print("  -t,--tracer strace|ltrace|cdb command for generating trace log")
    print("")

    sys.exit(exitCode)

################################################################################
# This is set by a signal handler when a control-C is typed.
# It then triggers a clean exit, and ceration of output results.
# This allows to monitor a running process, just for a given time
# without stopping it.
G_Interrupt = False

################################################################################

def LogWindowsFileStream(extCommand,aPid):
    raise Exception("Not implemented yet")

def CreateFlowsFromWindowsLogger(verbose,logStream):
    raise Exception("Not implemented yet")

################################################################################

# strace creates data structures similar to Python or Json.
# fstat(3</usr/lib64/gconv/gconv-modules.cache>, {st_mode=S_IFREG|0644, st_size=26254, ...})
# execve("/usr/bin/grep", ["grep", "toto", "../TestMySql.py"], [/* 34 vars */]) = 0 <0.000175>
# ['[{fd=5<UNIX:[73470->73473]>, events=POLLIN}]', '1', '25000'] ==>> 1 ([{fd=5, revents=POLLIN}])

# The result might be an array or an object.
# The input argument might be a single value or a key-value pair separated
# by a "=" equal sign.
def AppendArgToResultThrow( theResult, currStr, isArray ):
    # sys.stdout.write("AppendArgToResult %s\n"%currStr)
    argClean = currStr.strip()

    if isArray:
        keyArg = None
        valArg = argClean
    else:
        # sys.stdout.write("argClean=%s\n"%argClean)

        # Special case of an unfinished struct. See strace option:
        # -v    Print unabbreviated versions of environment, stat, termios,  etc. calls.
        #       These structures are very common in calls and so the default behavior
        #       displays a reasonable subset of structure members. Use this option to get all of the gory details.
        if argClean.endswith("..."):
            return

        # TODO: Check if the key is valid ...
        # Some unexplainable case such as: "[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]"
        idxEqual = argClean.find("=")
        if idxEqual > 0:
            keyArg = argClean[:idxEqual].strip()
            valArg = argClean[idxEqual+1:].strip()
        else:
            keyArg = ""
            valArg = argClean
    
    if valArg == "":   
        objToAdd = argClean
    elif valArg[0] == '[':
        if valArg[-1] != ']':
            raise Exception("Invalid array:%s"%valArg)
        objToAdd = ParseSTraceObject( valArg[1:-1], True )
    elif valArg[0] == '{':
        if valArg[-1] != '}':
            raise Exception("Invalid struct:%s"%valArg)
        objToAdd = ParseSTraceObject( valArg[1:-1], False )
    else:
        objToAdd = valArg

    if isArray:
        theResult.append( objToAdd )
    else:
        theResult[keyArg] = objToAdd

# The input string might be broken.
def AppendArgToResult( theResult, currStr, isArray ):
    try:
        AppendArgToResultThrow( theResult, currStr, isArray )
    except:
        if isArray:
            theResult.append( "error" )
        else:
            theResult["error"] = "error"
    

# This transforms a structure as returned by strace, into a Python object.
# The input is a string containing the arguments printed by strace.
# The output is an array of strings with these arguments correctly split.
# The arguments delimiter is a comma, if not between double quotes or brackets.
# It is stripped of the surrounding curly braces or square brackets.
# Beware that the input string might be incomplete: "{st_mode=S_IFREG|0644, st_size=121043, ...}"
def ParseSTraceObject(aStr,isArray):
    # sys.stdout.write("ParseSTraceObject %s\n"%aStr)

    if isArray:
        theResult = []
    else:
        theResult = {}

    inQuotes = False
    levelBrackets = 0
    isEscaped = False
    currStr = ""
    for aChr in aStr:
        if isEscaped:
            currStr += aChr
            isEscaped = False
            continue
        if aChr == '\\':
            isEscaped = True
            continue

        if aChr == '"':
            inQuotes = not inQuotes
            continue

        if not inQuotes:
            # This assumes that [] and {} are correctly paired by strace and therefore,
            # it is not needed to check their parity.
            if aChr in ['{','[','(']:
                levelBrackets += 1
            elif aChr in ['}',']',')']:
                levelBrackets -= 1
            elif aChr == ',':
                if levelBrackets == 0:
                    AppendArgToResult( theResult, currStr, isArray )
                    currStr = ""
                    continue

        currStr += aChr
        continue

    # If there is something in the string.
    if aStr:
        AppendArgToResult( theResult, currStr, isArray )

    return theResult

# Returns the index of the closing parenthesis, not between quotes or escaped.
def FindNonEnclosedPar(aStr,idxStart):
    # sys.stdout.write("FindNonEnclosedPar idxStart=%d aStr=%s\n" % (idxStart, aStr ) )
    lenStr = len(aStr)
    inQuotes = False
    isEscaped = False
    levelParenthesis = 0
    while idxStart < lenStr:
        aChr = aStr[idxStart]
        idxStart += 1
        if isEscaped:
            isEscaped = False
            continue
        if aChr == '\\':
            isEscaped = True
            continue
        if aChr == '"':
            inQuotes = not inQuotes
            continue

        if not inQuotes:
            if aChr == '(':
                levelParenthesis += 1
            elif aChr == ')':
                if levelParenthesis == 0:
                    return idxStart - 1
                levelParenthesis -= 1

    return -1

class ExceptionIsExit(Exception):
    pass

class ExceptionIsSignal(Exception):
    pass


################################################################################

# dated but exec, datedebut et fin exec, binaire utilise , librairies utilisees, 
# fichiers cres, lus, ecrits (avec date+taille premiere action et date+taille derniere)  
# + arborescence des fils lances avec les memes informations 

def TimeStampToStr(timStamp):
    aTm = time.gmtime( timStamp )
    return time.strftime("%Y/%m/%d %H:%M:%S", aTm )

def IsTimeStamp(attr,attrVal):
    return attr.find("Date") > 0 or attr.find("Time") > 0

def IsCIM(attr,attrVal):
    return not callable(attrVal) and not attr.startswith("__") and not attr.startswith("m_")

################################################################################

#class CIM_Process : CIM_LogicalElement
#{
#  string   Caption;
#  string   CreationClassName;
#  datetime CreationDate;
#  string   CSCreationClassName;
#  string   CSName;
#  string   Description;
#  uint16   ExecutionState;
#  string   Handle;
#  datetime InstallDate;
#  uint64   KernelModeTime;
#  string   Name;
#  string   OSCreationClassName;
#  string   OSName;
#  uint32   Priority;
#  string   Status;
#  datetime TerminationDate;
#  uint64   UserModeTime;
#  uint64   WorkingSetSize;
#};
class CIM_Process:
    def __init__(self,procId):
        # BY CONVENTION, SOME MEMBERS MUST BE DISPLAYED AND FOLLOW CIM CONVENTION.
        self.Handle = procId
        self.m_parentProcess = None
        self.CreationDate = None
        self.TerminationDate = None

        if not G_ReplayMode and psutil:
            try:
                # FIXME: If rerunning a simulation, this does not make sense.
                # Same for CIM_DataFile when this is not the target machine.
                procObj = psutil.Process(procId)
            except:
                # Maybe this is replaying a former session and in this case,
                # the process is not there anymore.
                procObj = None
        else:
            procObj = None

        if procObj:
            self.Name = procObj.name()
            self.Executable = procObj.exe()
            self.Username = procObj.username()
            self.CurrentDirectory = procObj.cwd()
            self.Priority = procObj.nice()
        else:
            self.Name = str(procId)
            # TODO: This could be deduced with calls to setuid().
            self.Username = None
            # TODO: This can be partly deduced with calls to chdir() etc...
            # so it would not be necessary to install psutil.
            self.CurrentDirectory = G_CurrentDirectory
            self.Priority = 0

        # If this process appears for the first time and there is only
        # one other process, then it is its parent.
        # It helps if the first vfork() is never finished,
        # and if we did not get the main process id.
        try:
            mapProcs = G_mapCacheObjects["CIM_Process"]
            keysProcs = mapProcs.keys()
            if len(keysProcs) == 1:
                # We are about to create the second process.
                firstProcObj = mapProcs[ keysProcs[0] ]
                self.m_parentProcess = firstProcObj
        except KeyError:
            # This is the first process.
            pass


    def __repr__(self):
        return "'%s'" % self.CreateMoniker(self.Handle)

    @staticmethod
    def CreateMoniker(procId):
        return 'CIM_Process.Handle="%s"' % procId

    @staticmethod
    def DisplaySummary(fdSummaryFile,mapFlows,cimKeyValuePairs):
        fdSummaryFile.write("Processes:\n")
        for objPath,objInstance in sorted( G_mapCacheObjects[CIM_Process.__name__].items() ):
            # sys.stdout.write("Path=%s\n"%objPath)
            objInstance.Summarize(fdSummaryFile)
        fdSummaryFile.write("\n")

    def XMLOneLevelSummary(self,strm,margin="    "):
        self.m_isVisited = True
        strm.write("%s<CIM_Process Handle='%s'>\n" % ( margin, self.Handle) )
        
        subMargin = margin + "    "

        for attr in dir(self):
            attrVal = getattr(self,attr)
            if IsCIM(attr,attrVal):
                # FIXME: Not very reliable.
                if IsTimeStamp(attr,attrVal):
                    attrVal = TimeStampToStr(attrVal)
                strm.write("%s<%s>%s</%s>\n" % ( subMargin, attr, attrVal, attr ) )

        for objInstance in self.m_subProcesses:
            objInstance.XMLOneLevelSummary(strm,subMargin)
        strm.write("%s</CIM_Process>\n" % ( margin ) )

    @staticmethod
    def CalcSubprocess(mapFlows,cimKeyValuePairs):
        """This rebuilds the tree of subprocesses seen from the top. """
        for objPath,objInstance in G_mapCacheObjects[CIM_Process.__name__].items():
            objInstance.m_subProcesses = []

        for objPath,objInstance in G_mapCacheObjects[CIM_Process.__name__].items():
            if objInstance.m_parentProcess:
                objInstance.m_parentProcess.m_subProcesses.append(objInstance)

    @staticmethod
    def TopProcessFromProc(objInstance):
        """This returns the top-level parent of a process."""
        while True:
            parentProc = objInstance.m_parentProcess
            if not parentProc: return objInstance
            objInstance = parentProc

    @staticmethod
    def XMLSummary(fdSummaryFile,mapFlows,cimKeyValuePairs):
        CIM_Process.CalcSubprocess(mapFlows,cimKeyValuePairs)

        # Find unvisited processes. It does not start from G_top_ProcessId
        # because maybe it contains several trees, or subtrees were missed etc...
        for objPath,objInstance in sorted( G_mapCacheObjects[CIM_Process.__name__].items() ):
            try:
                objInstance.m_isVisited
                continue
            except AttributeError:
                pass

            topObjProc = CIM_Process.TopProcessFromProc(objInstance)

            topObjProc.XMLOneLevelSummary(fdSummaryFile)

    # In text mode, with no special formatting.
    def Summarize(self,strm):
        strm.write("Process id:%s\n" % self.Handle )
        try:
            if self.Executable:
                strm.write("    Executable:%s\n" % self.Executable )
        except AttributeError:
            pass
        if self.CreationDate:
            strStart = TimeStampToStr( self.CreationDate )
            strm.write("    Start time:%s\n" % strStart )
        if self.TerminationDate:
            strEnd = TimeStampToStr( self.TerminationDate )
            strm.write("    End time:%s\n" % strEnd )
        if self.m_parentProcess:
            strm.write("    Parent:%s\n" % self.m_parentProcess.Handle )

    def AddParentProcess(self, timeStamp, objCIM_Process):
        self.m_parentProcess = objCIM_Process
        self.CreationDate = timeStamp

    def WaitProcessEnd(self, timeStamp, objCIM_Process):
        # sys.stdout.write("WaitProcessEnd: %s linking to %s\n" % (self.Handle,objCIM_Process.Handle))
        self.TerminationDate = timeStamp
        if not self.m_parentProcess:
            self.m_parentProcess = objCIM_Process
            # sys.stdout.write("WaitProcessEnd: %s not linked to %s\n" % (self.Handle,objCIM_Process.Handle))
        elif self.m_parentProcess != objCIM_Process:
            # sys.stdout.write("WaitProcessEnd: %s not %s\n" % (self.m_parentProcess.Handle,objCIM_Process.Handle))
            pass
        else:
            # sys.stdout.write("WaitProcessEnd: %s already linked to %s\n" % (self.m_parentProcess.Handle,objCIM_Process.Handle))
            pass

    def SetExecutable(self,objCIM_DataFile) :
        self.Executable = objCIM_DataFile.FileName

    def SetThread(self):
        self.IsThread = True

    # Some system calls are relative to the current directory.
    # Therefore, this traces current dir changes due to system calls.
    def SetProcessCurrentDir(self,currDirObject):
        self.CurrentDirectory = currDirObject.FileName

    def GetProcessCurrentDir(self):
        return self.CurrentDirectory

# class CIM_DataFile : CIM_LogicalFile
# {
  # string   Caption;
  # string   Description;
  # datetime InstallDate;
  # string   Status;
  # uint32   AccessMask;
  # boolean  Archive;
  # boolean  Compressed;
  # string   CompressionMethod;
  # string   CreationClassName;
  # datetime CreationDate;
  # string   CSCreationClassName;
  # string   CSName;
  # string   Drive;
  # string   EightDotThreeFileName;
  # boolean  Encrypted;
  # string   EncryptionMethod;
  # string   Name;
  # string   Extension;
  # string   FileName;
  # uint64   FileSize;
  # string   FileType;
  # string   FSCreationClassName;
  # string   FSName;
  # boolean  Hidden;
  # uint64   InUseCount;
  # datetime LastAccessed;
  # datetime LastModified;
  # string   Path;
  # boolean  Readable;
  # boolean  System;
  # boolean  Writeable;
  # string   Manufacturer;
  # string   Version;
# };
class CIM_DataFile:
    def __init__(self,pathName):
        self.FileName = pathName
        self.FileOpenTime = None
        self.FileCloseTime = None
        self.FileCategory = PathCategory(pathName)
        # It will take a proper value if it is "connect()" or "bind()"

        try:
            objStat = os.stat(pathName)
        except:
            objStat = None

        # Some information are not meaningfull because they will vary
        # during the process execution.
        if objStat:
            self.FileSize = objStat.st_size

            self.FileMode = objStat.st_mode
            self.Inode = objStat.st_ino
            self.DeviceId = objStat.st_dev
            self.HardLinksNumber = objStat.st_nlink
            self.OwnerUserId = objStat.st_uid
            self.OwnerGroupId = objStat.st_gid
            self.AccessTime = objStat.st_atime
            self.ModifyTime = objStat.st_mtime
            self.CreationTime = objStat.st_ctime
            try:
                # This does not exist on Windows.
                self.DeviceType = objStat.st_rdev
            except AttributeError:
                pass

            # This is on Windows only.
            # self.UserDefinedFlags = objStat.st_flags
            # self.FileCreator = objStat.st_creator
            # self.FileType = objStat.st_type

    def __repr__(self):
        return "'%s'" % self.CreateMoniker(self.FileName)

    @staticmethod
    def CreateMoniker(pathName):
        return 'CIM_DataFile.Name="%s"' % pathName

        
    @staticmethod
    def SplitFilesByCategory():
        try:
            mapFiles = G_mapCacheObjects[CIM_DataFile.__name__].items()
        except KeyError:
            sys.stdout.write("\n")
            return {}

        # TODO: Find a way to define the presentation as a parameter.
        # Maybe we can use the list of keys: Just mentioning a property
        # means that a sub-level must be displayed.
        mapOfFilesMap = { rgxTuple[0] : {} for rgxTuple in G_lstFilters }

        # objPath = 'CIM_DataFile.Name="/usr/lib64/libcap.so.2.24"'
        for objPath,objInstance in mapFiles:
            mapOfFilesMap[ objInstance.FileCategory ][ objPath ] = objInstance
        return mapOfFilesMap
        
    @staticmethod
    def DisplaySummary(fdSummaryFile,mapFlows,cimKeyValuePairs):
        fdSummaryFile.write("Files:\n")
        mapOfFilesMap = CIM_DataFile.SplitFilesByCategory()

        try:
            filterCats = cimKeyValuePairs["Category"]
        except KeyError:
            filterCats = None

        for categoryFiles, mapFilesSub in sorted( mapOfFilesMap.items() ):
            fdSummaryFile.write("\n** %s\n"%categoryFiles)
            if filterCats and ( not categoryFiles in filterCats ): continue
            for objPath,objInstance in sorted( mapFilesSub.items() ):
                # sys.stdout.write("Path=%s\n"%objPath)
                objInstance.Summarize(fdSummaryFile)
        fdSummaryFile.write("\n")

    def XMLDisplay(self,strm):
        margin = "        "
        strm.write("%s<CIM_DataFile Name='%s'>\n" % ( margin, self.FileName) )
        
        subMargin = margin + "    "

        for attr in dir(self):
            attrVal = getattr(self,attr)
            if IsCIM(attr,attrVal):
                if IsTimeStamp(attr,attrVal):
                    attrVal = TimeStampToStr(attrVal)
                strm.write("%s<%s>%s</%s>\n" % ( subMargin, attr, attrVal, attr ) )

        strm.write("%s</CIM_DataFile>\n" % ( margin ) )

    @staticmethod
    def XMLCategorySummary(fdSummaryFile,mapFilesSub):
        for objPath,objInstance in sorted( mapFilesSub.items() ):
            # sys.stdout.write("Path=%s\n"%objPath)
            objInstance.XMLDisplay(fdSummaryFile)

    @staticmethod
    def XMLSummary(fdSummaryFile,mapFlows,cimKeyValuePairs):
        """Top-level informations are categories of CIM_DataFile which are not technical
        but the regex-based filtering."""
        mapOfFilesMap = CIM_DataFile.SplitFilesByCategory()

        try:
            filterCats = cimKeyValuePairs["Category"]
        except KeyError:
            filterCats = None

        for categoryFiles, mapFilesSub in sorted( mapOfFilesMap.items() ):
            fdSummaryFile.write("    <FilesCategory category='%s'>\n"%categoryFiles)
            if filterCats and ( not categoryFiles in filterCats ): continue
            CIM_DataFile.XMLCategorySummary(fdSummaryFile,mapFilesSub)
            fdSummaryFile.write("    </FilesCategory>\n")
        
    def Summarize(self,strm):
        try:
            # By default, this attribute is not set.
            if self.IsExecuted:
                return
        except AttributeError:
            pass
        strm.write("Path:%s\n" % self.FileName )
        if self.FileOpenTime:
            strOpen = TimeStampToStr( self.FileOpenTime )
            strm.write("  Open:%s\n" % strOpen )

            try:
                strm.write("  Open times:%d\n" % self.NumOpen )
            except AttributeError:
                pass

        if self.FileCloseTime:
            strClose = TimeStampToStr( self.FileCloseTime )
            strm.write("  Close:%s\n" % strClose )

        # Only if this is a socket.
        try:
            for saKey in self.SocketAddress:
                saVal = self.SocketAddress[saKey]
                strm.write("    %s:%s\n" % (saKey,saVal) )
        except AttributeError:
            pass

    def SetOpenTime(self, timeStamp, objCIM_Process):
        try:
            self.NumOpen += 1
        except AttributeError:
            self.NumOpen = 1
        if not self.FileOpenTime or ( timeStamp < self.FileOpenTime ):
            self.FileOpenTime = timeStamp

    def SetCloseTime(self, timeStamp, objCIM_Process):
        if not self.FileCloseTime or ( timeStamp < self.FileCloseTime ):
            self.FileCloseTime = timeStamp

    def SetIsExecuted(self) :
        self.IsExecuted = True

# This contains the CIM objects: CIM_Process, CIM_DataFile and
# is used to generate the summary.
G_mapCacheObjects = None

def CreateObjectPath(classModel, *ctorArgs):
    try:
        mapObjs = G_mapCacheObjects[classModel.__name__]
    except KeyError:
        mapObjs = {}
        G_mapCacheObjects[classModel.__name__] = mapObjs

    objPath = classModel.CreateMoniker(*ctorArgs)
    try:
        theObj = mapObjs[objPath]
    except KeyError:
        theObj = classModel(*ctorArgs)
        mapObjs[objPath] = theObj
    return theObj


def ToObjectPath_CIM_Process(aPid):
    return CreateObjectPath(CIM_Process,aPid)

# TODO: It might be a Linux socket or an IP socket.
def ToObjectPath_CIM_DataFile(pathName):
    return CreateObjectPath(CIM_DataFile,pathName)

def CIM_SharedLibrary(CIM_DataFile):
    pass

# This is not a map, it is not sorted.
# It contains regular expression for classifying file names in categories:
# Shared libraries, source files, scripts, Linux pipes etc...
G_lstFilters = [
    ( "Shared libraries" , [
        "^/usr/lib[^/]*/.*\.so",
        "^/usr/lib[^/]*/.*\.so\..*",
    ] ),
    ( "Other libraries" , [
        "^/usr/lib[^/]*/",
        "^/usr/share/",
    ] ),
    ( "Proc file system" , [
        "^/proc",
    ] ),
    ( "/etc conf files" , [
        "^/etc/",
    ] ),
    ( "/tmp temporary files" , [
        "^/tmp/",
    ] ),
    ( "Pipes and terminals" , [
        "^/sys",
        "^/dev",
        "^pipe:",
        "^UNIX:",
    ] ),
    ( "TCP/IP sockets" , [
        "^TCP:",
        "^UDP:",
    ] ),
    ( "Others" , [] ),
]


def PathCategory(pathName):
    """This match the path name againt the set of regular expressions
    defining broad categories of files: Sockets, libraries, temporary files...
    These categories are not technical but based on application best practices,
    rules of thumbs etc..."""
    for rgxTuple in G_lstFilters:
        for oneRgx in rgxTuple[1]:
            # If the file matches a regular expression,
            # then it is sorted in this category.
            mtchRgx = re.match( oneRgx, pathName )
            if mtchRgx:
                return rgxTuple[0]
    return "Others"


# This receives an array of WMI/WBEM/CIM object paths:
# 'Win32_LogicalDisk.DeviceID="C:"'
# The values can be regular expressions.
# key-value pairs in the expressions are matched one-to-one with objects.

# rgxObjectPath = 'Win32_LogicalDisk.DeviceID="C:",Prop="Value",Prop="Regex"'
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
    tmpInsp = inspect.getargspec( locals()["aTempFunc"] )
    arrArgs = tmpInsp.args
    arrVals = tmpInsp.defaults
    mapKeyValues = dict( zip(arrArgs, arrVals) )

    return ( objClassName, mapKeyValues )

def GenerateSummaryTXT(mapFlows,mapParamsSummary,fdSummaryFile):
    for rgxObjectPath in mapParamsSummary:
        ( cimClassName, cimKeyValuePairs ) = ParseFilterCIM(rgxObjectPath)
        classObj = globals()[ cimClassName ]
        classObj.DisplaySummary(fdSummaryFile,mapFlows,cimKeyValuePairs)

# dated but exec, datedebut et fin exec, binaire utilise , librairies utilisees,
# fichiers cres, lus, ecrits (avec date+taille premiere action et date+taille derniere)  
# + arborescence des fils lances avec les memes informations 
def GenerateSummaryXML(mapFlows,mapParamsSummary,fdSummaryFile):
    if mapParamsSummary:
        fdSummaryFile.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        fdSummaryFile.write('<retrobatch>\n')
        for rgxObjectPath in mapParamsSummary:
            ( cimClassName, cimKeyValuePairs ) = ParseFilterCIM(rgxObjectPath)
            classObj = globals()[ cimClassName ]
            classObj.XMLSummary(fdSummaryFile,mapFlows,cimKeyValuePairs)
        fdSummaryFile.write('</retrobatch>\n')


def GenerateSummary(mapFlows,mapParamsSummary,outputFormat, outputSummaryFile):

    if outputSummaryFile:
        fdSummaryFile = open(outputSummaryFile, "w")
    else:
        fdSummaryFile = sys.stdout

    if outputFormat == "TXT":
        GenerateSummaryTXT(mapFlows,mapParamsSummary,fdSummaryFile)
    elif outputFormat.upper() == "XML":
        # The output format is very different.
        GenerateSummaryXML(mapFlows,mapParamsSummary,fdSummaryFile)
    else:
        raise Exception("Unsupported summary output format:%s"%outputFormat)

    if outputSummaryFile:
        fdSummaryFile.close()

################################################################################

# This associates file descriptors to path names when strace and the option "-y"
# cannot be used. There are predefined values.
G_mapFilDesToPathName = None

# strace associates file descriptors to the original file or socket which created it.
# Option "-y          Print paths associated with file descriptor arguments."
# read ['3</usr/lib64/libc-2.21.so>']
# This returns a WMI object path, which is self-descriptive.
def STraceStreamToPathname(strmStr):
    idxLT = strmStr.find("<")
    if idxLT >= 0:
        pathName = strmStr[ idxLT + 1 : -1 ]
    else:
        # If the option "-y" is not available, with ltrace or truss.
        # Theoretically the path name should be in the map.
        try:
            pathName = G_mapFilDesToPathName[ strmStr ]
        except KeyError:
            if strmStr == "-1": # Normal return value.
                pathName = strmStr
            else:
                pathName = "UnknownFileDescr:%s" % strmStr

    return pathName

def STraceStreamToFile(strmStr):
    return ToObjectPath_CIM_DataFile( STraceStreamToPathname(strmStr) )

################################################################################

# ltrace logs
# [pid 6414] 23:58:46.424055 __libc_start_main([ "gcc", "TestProgs/HelloWorld.c" ] <unfinished ...>
# [pid 6415] 23:58:47.905826 __libc_start_main([ "/usr/libexec/gcc/x86_64-redhat-linux/5.3.1/cc1", "-quiet", "TestProgs/HelloWorld.c", "-quiet"... ] <unfinished ...>


# Typical strings displayed by strace:
# [pid  7492] 07:54:54.205073 wait4(18381, [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 18381 <0.000894>
# [pid  7492] 07:54:54.206000 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=18381, si_uid=1000, si_status=1, si_utime=0, si_stime=0 } ---
# [pid  7492] 07:54:54.206031 newfstatat(7</home/rchateau/rdfmon-code/primhill>, "Survol", {st_mode=S_IFDIR|0775, st_size=4096, ...}, AT_SYMLIN K_NOFOLLOW) = 0 <0.000012>
# [pid  7492] 07:54:54.206113 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fb0d303fad0) = 18382 <0.000065>
# [pid  7492] 07:54:54.206217 wait4(18382, grep: ../../primhill/Survol: Is a directory
# [pid  7492] [{WIFEXITED(s) && WEXITSTATUS(s) == 2}], 0, NULL) = 18382 <0.000904>
# 07:54:54.207500 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=18382, si_uid=1000, si_status=2, si_utime=0, si_stime=0 } ---

class BatchStatus:
    unknown    = 0
    plain      = 1
    unfinished = 2
    resumed    = 3
    matched    = 4 # After the unfinished has found its resumed half.
    merged     = 5 # After the resumed has found its unfinished half.
    sequence   = 6
    chrDisplayCodes = "? URmM "


class BatchLetCore:
    # The input line is read from "strace" command.
    # [pid  7639] 09:35:56.198010 wait4(7777,  <unfinished ...>
    # 09:35:56.202030 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 7777 <0.004010>
    # [pid  7639] 09:35:56.202303 wait4(7778,  <unfinished ...>
    #
    # It works with ltrace, in a certain extent.
    # [pid 3916] 13:20:17.215298 open@SYS("/usr/lib64/python2.7/site-packages/_mysql.so", 0, 0666)                      = 4 <0.000249>
    # [pid 3916] 13:20:17.215576 fstat@SYS(4, 0x7ffd2f04fd50)                                                           = 0 <0.000038>
    # [pid 3916] 13:20:17.215671 open@SYS("/usr/lib64/python2.7/site-packages/_mysql.so", 0x80000, 01674553140)         = 5 <0.000256>
    # [pid 3916] 13:20:17.216004 read@SYS(5, "\177ELF\002\001\001", 832)                                                = 832 <0.000042>

    def __init__(self):
        self.m_retValue = "N/A"
        self.m_status = BatchStatus.unknown

        # Both cannot be set at the same time.
        self.m_unfinishedBatch = None # If this is an merged batch.
        self.m_resumedBatch = None # If this is an matched batch.

        # sys.stdout.write("self=%d\n" % id(self) )
        return

    # tracer = "strace|ltrace"
    def ParseLine( self, oneLine, tracer ):
        # sys.stdout.write("%s oneLine1=%s" % (id(self),oneLine ) )
        self.m_tracer = tracer

        if oneLine[0:4] == "[pid":
            idxAfterPid = oneLine.find("]")

            pidParsed = int( oneLine[ 4:idxAfterPid ] )

            # This is a sub-process.
            self.m_pid = pidParsed

            self.InitAfterPid(oneLine[ idxAfterPid + 2 : ] )
        else:
            # This is the main process, but at this stage we do not have its pid.
            self.m_pid = G_topProcessId
            self.InitAfterPid(oneLine)
        self.m_objectProcess = ToObjectPath_CIM_Process(self.m_pid)

    def SetFunction(self, funcFull):
        # With ltrace, systems calls are suffix with the string "@SYS".
        if self.m_tracer == "strace":
            # strace can only intercept system calls.
            self.m_funcNam = funcFull + "@SYS"
        elif self.m_tracer == "ltrace":
            # ltrace does not add "@SYS" when the function is resumed:
            #[pid 18316] 09:00:22.600426 rt_sigprocmask@SYS(0, 0x7ffea10cd370, 0x7ffea10cd3f0, 8 <unfinished ...>
            #[pid 18316] 09:00:22.600494 <... rt_sigprocmask resumed> ) = 0 <0.000068>
            if self.m_status == BatchStatus.resumed:
                self.m_funcNam = funcFull + "@SYS"
            else:
                self.m_funcNam = funcFull

            # It does not work with this:
            #[pid 4784] 16:42:10.781324 Py_Main(2, 0x7ffed52a8038, 0x7ffed52a8050, 0 <unfinished ...>
            #[pid 4784] 16:42:12.166187 <... Py_Main resumed> ) = 0 <1.384547>
            #
            # The only thing we can do is register the funaton names which have been seen as unfinished,
            # store their prefix and use this to correctly suffix them or not.

        else:
            raise Exception("SetFunction tracer %s unsupported"%self.m_trace)

    # This parsing is specific to strace.
    def InitAfterPid(self,oneLine):

        # sys.stdout.write("oneLine=%s" % oneLine )

        # This could be done without intermediary string.
        # "07:54:54.206113"
        try:
            # This date is conventional, but necessary, otherwise set to 1900/01/01..
            timStruct = time.strptime("2000/01/01 " + oneLine[:15],"%Y/%m/%d %H:%M:%S.%f")
            aTimeStamp = time.mktime( timStruct ) + 3600
        except ValueError:
            sys.stdout.write("Invalid time format:%s\n"%oneLine[0:15])
            aTimeStamp = 0
        except OverflowError:
            sys.stderr.write("Overflow time format:%s\n"%oneLine[0:15])
            aTimeStamp = 0

        self.m_timeStart = aTimeStamp
        self.m_timeEnd = aTimeStamp
        theCall = oneLine[16:]

        # "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=19332, si_uid=1000, si_status=1, si_utime=0, si_stime=0} ---"
        if theCall[0:4] == "--- ":
            raise ExceptionIsExit()

        # "+++ exited with 1 +++ ['+++ exited with 1 +++']"
        if theCall[0:4] == "+++ ":
            raise ExceptionIsSignal()


        # Specific logic of interrupted calls.
        # [pid 12666] 14:50:45.609523 wait4@SYS(-1, 0x7ffd59a919e0, 0, 0 <unfinished ...>
        # [pid 12666] 14:50:45.666995 <... wait4 resumed> ) = 0x317b <0.057470>

        # ... with functions which do not implying signals or processes:
        # [pid 12693] 14:55:38.882089 fwrite(" ?", 2, 1, 0x7f93548c5620 <unfinished ...>
        # [pid 12693] 14:55:38.882412 <... fwrite resumed> ) = 1 <0.000319>

        # Sometimes on two recursive levels:
        # [pid 12753] 14:56:54.288041 sigaction(SIGCHLD, { nil, <>, 0, nil } <unfinished ...>
        # [pid 12753] 14:56:54.288231 rt_sigaction@SYS(17, 0x7ffe7c383380, 0x7ffe7c383420, 8 <unfinished ...>
        # [pid 12753] 14:56:54.288299 <... rt_sigaction resumed> ) = 0 <0.000069>
        # [pid 12753] 14:56:54.288404 <... sigaction resumed> , { 0x5612836832c0, <>, 0, nil }) = 0 <0.000361>

        # "[pid 18534] 19:58:38.406747 wait4(18666,  <unfinished ...>"
        # "19:58:38.410766 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 18666 <0.004009>"

        idxGT = theCall.rfind(">")
        # sys.stdout.write("idxGT=%d\n" % idxGT )
        idxLT = theCall.rfind("<",0,idxGT)
        # sys.stdout.write("idxLT=%d\n" % idxLT )
        self.m_status = BatchStatus.plain
        if idxLT >= 0 :
            exeTm = theCall[idxLT+1:idxGT]
            if exeTm == "unfinished ...":
                self.m_execTim = ""
                self.m_status = BatchStatus.unfinished
            else:
                self.m_execTim = theCall[idxLT+1:idxGT]
        else:
            self.m_execTim = ""

        # Another scenario:
        # [pid 11761] 10:56:39.125823 close@SYS(4 <unfinished ...>
        # [pid 11762] 10:56:39.125896 mmap@SYS(nil, 4096, 3, 34, -1, 0 <unfinished ...>
        # [pid 11761] 10:56:39.125939 <... close resumed> ) = 0 <0.000116>
        # [pid 11762] 10:56:39.125955 <... mmap resumed> ) = 0x7f75198d5000 <0.000063>
        matchResume = re.match( "<\.\.\. ([^ ]*) resumed> (.*)", theCall )
        if matchResume:
            self.m_status = BatchStatus.resumed
            # TODO: Should check if this is the correct function name.
            funcNameResumed = matchResume.group(1)
            self.SetFunction( funcNameResumed )

            # ") = 0 <0.000069>"
            # ", { 0x5612836832c0, <>, 0, nil }) = 0 <0.000361>"

            # Offset of the second match.
            # A 'resumed' function call does not have an opening parenthesis.
            idxPar = matchResume.start(2) - 1

        else:
            idxPar = theCall.find("(")

            if idxPar <= 0 :
                raise Exception("No function in:%s"%oneLine)

            self.SetFunction( theCall[:idxPar] )

        if self.m_status == BatchStatus.unfinished:
            idxLastPar = idxLT - 1
        else:
            idxLastPar = FindNonEnclosedPar(theCall,idxPar+1)

        allArgs = theCall[idxPar+1:idxLastPar]
        # sys.stdout.write("allArgs=%s\n"%allArgs)
        self.m_parsedArgs = ParseSTraceObject( allArgs, True )

        if self.m_status == BatchStatus.unfinished:
            # 18:46:10.920748 execve("/usr/bin/ps", ["ps", "-ef"], [/* 33 vars */] <unfinished ...>
            # sys.stdout.write("self.m_unfinished: %s\n"%oneLine)
            self.m_retValue = None
        else:
            # The parameters list might be broken, with strings containing an embedded double-quote.
            if idxLastPar < 0:
                # The parameters list might be broken, with strings containing an embedded double-quote.
                # So the closing parenthesis could not be found.
                idxEq = theCall.rfind( "=", 0, idxLT )
            else:
                # Normal case where the '=' equal sign comes after the clolsing parenthese of the args list.
                idxEq = theCall.find( "=", idxLastPar )
            self.m_retValue = theCall[ idxEq + 1 : idxLT ].strip()
            # sys.stdout.write("idxEq=%d idxLastPar=%d idxLT=%d retValue=%s\n"%(idxEq,idxLastPar,idxLT,self.m_retValue))

    def AsStr(self):
        return "%s %s s=%s" % (
            str(self.m_parsedArgs),
            self.m_retValue,
            BatchStatus.chrDisplayCodes[ self.m_status ] )

def CreateBatchCore(oneLine,tracer):

    try:
        batchCore = BatchLetCore()
        batchCore.ParseLine( oneLine, tracer )
        return batchCore
    except ExceptionIsExit:
        return None
    except ExceptionIsSignal:
        return None

################################################################################

G_ignoredSyscalls = [
    "mprotect",
    "brk",
    "lseek",
    "arch_prctl",
    "rt_sigaction",
    "set_tid_address",
    "set_robust_list",
    "rt_sigprocmask",
    "rt_sigaction",
    "rt_sigreturn",
    "geteuid",
    "getuid",
    "getgid",
    "getegid",
    "setpgid",
    "getpgid",
    "setpgrp",
    "getpgrp",
    "getpid",
    "getppid",
    "getrlimit",
    "futex",
    "brk",
]


# Each class is indexed with the name of the corresponding system call name.
# If the class is None, it means that this function is explicitly neglected.
# If it is not defined after metaclass registration, then it is processed by BatchLetBase.
# Derived classes of BatchLetBase self-register thanks to the metaclass.
# At init time, this map contains the systems calls which should be ignored.

G_batchModels = { sysCll + "@SYS" : None for sysCll in G_ignoredSyscalls }

# sys.stdout.write("G_batchModels=%s\n"%str(G_batchModels) )

# This metaclass allows derived class of BatchLetBase to self-register their function name.
# So, the name of a system call is used to lookup the class which represents it.
class BatchMeta(type):
    #def __new__(meta, name, bases, dct):
    #    return super(BatchMeta, meta).__new__(meta, name, bases, dct)

    # This registers function names using the name of the derived class which is properly truncated.
    # TODO: It would be cleaner to add members in the class cls, instead of using the class name
    # to characterize the function.
    def __init__(cls, name, bases, dct):
        global G_batchModels

        # This is for Linux system calls.
        btchSysPrefix = "BatchLetSys_"

        # This is for plain libraries functions: "__libc_start_main", "Py_Main" and more to come
        btchLibPrefix = "BatchLetLib_"

        if name.startswith(btchSysPrefix):
            syscallName = name[len(btchSysPrefix):] + "@SYS"
            # sys.stdout.write("Registering sys function:%s\n"%syscallName)
            G_batchModels[ syscallName ] = cls
        elif name.startswith(btchLibPrefix):
            syscallName = name[len(btchLibPrefix):]
            # sys.stdout.write("Registering lib function:%s\n"%syscallName)
            G_batchModels[ syscallName ] = cls
        elif name not in ["NewBase","BatchLetBase","BatchLetSequence"]:
            # Enumerate the list of legal base classes, for safety only.
            raise Exception("Invalid class name:%s"%name)

        super(BatchMeta, cls).__init__(name, bases, dct)

# This is portable on Python 2 and Python 3.
# No need to import the modules six or future.utils
def my_with_metaclass(meta, *bases):
    return meta("NewBase", bases, {})

class BatchLetBase(my_with_metaclass(BatchMeta) ):

    # The style tells if this is a native call or an aggregate of function
    # calls, made with some style: Factorization etc...
    def __init__(self,batchCore,style="Orig"):
        self.m_core = batchCore
        self.m_occurrences = 1
        self.m_style = style
        # sys.stdout.write("NAME=%s\n"%self.__class__.__name__)

        # Maybe we could get rid of the parsed args as they are not needed anymore.
        self.m_significantArgs = self.m_core.m_parsedArgs

    def __str__(self):
        return self.m_core.m_funcNam

    def SignificantArgs(self):
        return self.m_significantArgs

    def SignificantArgsAsStr(self):
        # arrStr = [ str(arg) for arg in self.m_significantArgs ]
        return self.m_significantArgs
        # return arrStr

    # This is used to detect repetitions.
    def GetSignature(self):
        return self.m_core.m_funcNam

    def GetSignatureWithArgs(self):
        return self.GetSignature() + ":" + "&".join( [ str(oneArg) for oneArg in self.SignificantArgs() ] )

    # This is very often used.
    def StreamName(self,idx=0):
        # sys.stdout.write( "StreamName func%s\n"%self.m_core.m_funcNam )
        # sys.stdout.write( "StreamName=%s\n"%self.m_core.m_parsedArgs[idx] )
        return [ STraceStreamToFile( self.m_core.m_parsedArgs[idx] ) ]

    def SameCall(self,anotherBatch):
        if self.m_core.m_funcNam != anotherBatch.m_core.m_funcNam:
            return False

        return self.SameArguments(anotherBatch)

    # This assumes that the function calls are the same.
    # It compares the arguments one by one.
    def SameArguments(self,anotherBatch):
        args1 = self.SignificantArgs()
        args2 = anotherBatch.SignificantArgs()

        # sys.stdout.write("%s args1=%s\n" % ( self.m_core.m_funcNam, str(args1)) )
        # sys.stdout.write("%s args2=%s\n" % ( anotherBatch.m_core.m_funcNam, str(args2)) )

        # At least they should have the same number of arguments.
        if len(args1) != len(args2):
            return False

        for idx,val1 in enumerate(args1):
            val2 = args2[idx]

            if val1 != val2:
                return False
            idx += 1

        return True

################################################################################

def FmtTim(aTim):
    return time.strftime("%H:%M:%S", time.gmtime(aTim))

class BatchDumperBase:
    def Header(self):
        return

    def Footer(self):
        return

class BatchDumperTXT(BatchDumperBase):
    def __init__(self,strm):
        self.m_strm = strm

    def DumpBatch(self,batchLet):
        self.m_strm.write("Pid=%6d {%4d/%s}%1s'%-20s' %s ==>> %s (%s,%s)\n" %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            BatchStatus.chrDisplayCodes[ batchLet.m_core.m_status ],
            batchLet.m_core.m_funcNam,
            batchLet.SignificantArgsAsStr(),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )

class BatchDumperCSV(BatchDumperBase):
    def __init__(self,strm):
        self.m_strm = strm

    def Header(self):
        self.m_strm.write("Pid,Occurrences,Style,Function,Arguments,Return,Start,End\n")

    def DumpBatch(self,batchLet):
        self.m_strm.write("%d,%d,%s,%s,%s,%s,%s,%s,%s\n" %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            batchLet.m_core.m_status,
            batchLet.m_core.m_funcNam,
            batchLet.SignificantArgsAsStr(),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )

class BatchDumperJSON(BatchDumperBase):
    def __init__(self,strm):
        self.m_strm = strm

    def Header(self):
        self.m_strm.write( '[\n' )

    def DumpBatch(self,batchLet):
        self.m_strm.write(
            '{\n'
            '   "pid" : %d\n'
            '   "occurrences" : %d\n'
            '   "style" : %s\n'
            '   "status" : %d\n'
            '   "function" : "%s"\n'
            '   "arguments" : %s\n'
            '   "return_value" : "%s"\n'
            '   "time_start" : "%s"\n'
            '   "time_end" : "%s"\n'
            '},\n' %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            batchLet.m_core.m_status,
            batchLet.m_core.m_funcNam,
            batchLet.SignificantArgsAsStr(),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )

    def Footer(self):
        self.m_strm.write( ']\n' )


def BatchDumperFactory(strm, outputFormat):
    BatchDumpersDictionary = {
        "TXT"  : BatchDumperTXT,
        "XML"  : BatchDumperTXT,
        "CSV"  : BatchDumperCSV,
        "JSON" : BatchDumperJSON
    }

    return BatchDumpersDictionary[ outputFormat ](strm)

################################################################################

# Some Linux functions return a file descriptor which can be invalid:
# This is not shown the same way depending on the tracer: strace or ltrace.
# On Linux, ENOENT = 2.
def InvalidReturnedFileDescriptor(fileDes,tracer):
    if tracer == "strace":
        # 09:18:26.452764 open("/usr/lib/python2.7/numbersmodule.so", O_RDONLY|O_LARGEFILE) = -1 ENOENT (No such file or directory) <0.000012>
        if fileDes.find("ENOENT") >= 0 :
            return True
    elif tracer == "ltrace":
        # [pid 4784] 16:42:12.033450 open@SYS("/usr/lib64/python2.7/numbersmodule.so", 0, 0666) = -2 <0.000195>
        if fileDes.find("-2") >= 0 :
            return True
    else:
        raise Exception("Tracer %s not supported yet"%tracer)
    return False

################################################################################

# os.path.abspath removes things like . and .. from the path
# giving a full path from the root of the directory tree to the named file (or symlink)
def ToAbsPath( dirPath, filNam ):
    if filNam[0] == "/":
        fullPath = filNam
    else:
        fullPath = dirPath + "/" + filNam

    # FIXME: Broken if Linux test run on Windows machine and vice-versa.
    # Therefore, the file manipulation is done.
    # This assumes that original tests are done on Linux, for the moment.
    splitSlash = fullPath.split("/")
    lenSplt = len(splitSlash)
    ix = 1
    while ix < lenSplt:
        if splitSlash[ix] == '..':
            del splitSlash[ix-1:ix+1]
            ix -= 1
            lenSplt -= 2
        elif splitSlash[ix] in ['.','']:
            del splitSlash[ix:ix+1]
            lenSplt -= 1
        else:
            ix += 1


    absPth = "/".join(splitSlash)

    # absPthWin = os.path.abspath( fullPath )
    # sys.stdout.write(" fullPath=%s\n   absPth=%s\nabsPthWin=%s\n"%(fullPath,absPth,absPthWin))
    return absPth

################################################################################

##### File descriptor system calls.

# Must be a new-style class.
class BatchLetSys_open(BatchLetBase,object):
    def __init__(self,batchCore):
        global G_mapFilDesToPathName

        # TODO: If the open is not successful, maybe it should be rejected.
        if InvalidReturnedFileDescriptor(batchCore.m_retValue,batchCore.m_tracer):
            return
        super( BatchLetSys_open,self).__init__(batchCore)

        if batchCore.m_tracer == "strace":
            # strace has the "-y" option which writes the complete path each time,
            # the file descriptor is used as an input argument.

            # If the open succeeds, the file actually opened might be different,
            # than the input argument. Example:
            # open("/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib64/libc-2.25.so>
            # Therefore the returned file should be SignificantArgs(),
            # not the input file.
            self.m_significantArgs = [ STraceStreamToFile( self.m_core.m_retValue ) ]
        elif batchCore.m_tracer == "ltrace":
            # The option "-y" which writes the complete path after the file descriptor,
            # is not available for ltrace.
            # Therefore this mapping must be done here, by reading the result of open()
            # and other system calls which create a file descriptor.

            # This logic also should work with strace if the option "-y" is not there.
            pathName = self.m_core.m_parsedArgs[0]
            filDes = self.m_core.m_retValue

            # TODO: Should be cleaned up when closing ?
            G_mapFilDesToPathName[ filDes ] = pathName
            self.m_significantArgs = [ ToObjectPath_CIM_DataFile( pathName ) ]
        else:
            raise Exception("Tracer %s not supported yet"%batchCore.m_tracer)
        self.m_significantArgs[0].SetOpenTime(self.m_core.m_timeStart,self.m_core.m_objectProcess)

# The important file descriptor is the returned value.
# openat(AT_FDCWD, "../list_machines_in_domain.py", O_RDONLY|O_NOCTTY) = 3</home/rchateau/survol/Experimental/list_machines_in_domain.py> <0.000019>
class BatchLetSys_openat(BatchLetBase,object):
    def __init__(self,batchCore):
        global G_mapFilDesToPathName

        super( BatchLetSys_openat,self).__init__(batchCore)

        # Same logic as for open().
        if batchCore.m_tracer == "strace":
            self.m_significantArgs = [ STraceStreamToFile( self.m_core.m_retValue ) ]
        elif batchCore.m_tracer == "ltrace":
            dirNam = self.m_core.m_parsedArgs[0]
        
            if dirNam == "AT_FDCWD":
                # A relative pathname is interpreted relative to the directory
                # referred to by the file descriptor passed as first parameter.
                dirPath = self.m_core.m_objectProcess.GetProcessCurrentDir()
            else:
                dirPath = STraceStreamToFile( dirNam )
        
            filNam = self.m_core.m_parsedArgs[1]

            pathName = ToAbsPath( dirPath, filNam )

            filDes = self.m_core.m_retValue

            # TODO: Should be cleaned up when closing ?
            G_mapFilDesToPathName[ filDes ] = pathName
            self.m_significantArgs = [ ToObjectPath_CIM_DataFile( pathName ) ]
        else:
            raise Exception("Tracer %s not supported yet"%batchCore.m_tracer)
        self.m_significantArgs[0].SetOpenTime(self.m_core.m_timeStart,self.m_core.m_objectProcess)
        

class BatchLetSys_close(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_close,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()
        self.m_significantArgs[0].SetCloseTime(self.m_core.m_timeEnd,self.m_core.m_objectProcess)

class BatchLetSys_read(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_read,self).__init__(batchCore)

        bytesRead = int(self.m_core.m_retValue)

        self.m_significantArgs = self.StreamName()

        try:
            self.m_significantArgs[0].NumRead += 1
        except AttributeError:
            self.m_significantArgs[0].NumRead = 1
        try:
            self.m_significantArgs[0].BytesRead += bytesRead
        except AttributeError:
            self.m_significantArgs[0].BytesRead = bytesRead

# The process id is the return value but does not have the same format
# with ltrace (hexadecimal) and strace (decimal).
# Example: pread@SYS(256, 0x255a200, 0x4000, 0) = 0x4000
def ConvertBatchCoreRetValue(batchCore):
    if batchCore.m_tracer == "ltrace":
        return int(batchCore.m_retValue,16)
    elif batchCore.m_tracer == "strace":
        return int(batchCore.m_retValue)
    else:
        raise Exception("Invalid tracer")

# Pread() is like read() but reads from the specified position in the file without modifying the file pointer.
class BatchLetSys_preadx(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_preadx,self).__init__(batchCore)

        bytesRead = ConvertBatchCoreRetValue(batchCore)

        self.m_significantArgs = self.StreamName()

        try:
            self.m_significantArgs[0].NumRead += 1
        except AttributeError:
            self.m_significantArgs[0].NumRead = 1
        try:
            self.m_significantArgs[0].BytesRead += bytesRead
        except AttributeError:
            self.m_significantArgs[0].BytesRead = bytesRead

class BatchLetSys_pread64x(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_pread64x,self).__init__(batchCore)

        bytesRead = ConvertBatchCoreRetValue(batchCore)

        self.m_significantArgs = self.StreamName()

        try:
            self.m_significantArgs[0].NumRead += 1
        except AttributeError:
            self.m_significantArgs[0].NumRead = 1
        try:
            self.m_significantArgs[0].BytesRead += bytesRead
        except AttributeError:
            self.m_significantArgs[0].BytesRead = bytesRead

class BatchLetSys_write(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_write,self).__init__(batchCore)

        bytesWritten = int(self.m_core.m_retValue)

        self.m_significantArgs = self.StreamName()
        try:
            self.m_significantArgs[0].NumWritten += 1
        except AttributeError:
            self.m_significantArgs[0].NumWritten = 1
        try:
            self.m_significantArgs[0].BytesWritten += bytesWritten
        except AttributeError:
            self.m_significantArgs[0].BytesWritten = bytesWritten

class BatchLetSys_ioctl(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_ioctl,self).__init__(batchCore)

        self.m_significantArgs = [ STraceStreamToFile( self.m_core.m_parsedArgs[0] ) ] + self.m_core.m_parsedArgs[1:0]

class BatchLetSys_stat(BatchLetBase,object):
    def __init__(self,batchCore):
        # TODO: If the stat is not successful, maybe it should be rejected.
        if InvalidReturnedFileDescriptor(batchCore.m_retValue,batchCore.m_tracer):
            return
        super( BatchLetSys_stat,self).__init__(batchCore)

        self.m_significantArgs = [ ToObjectPath_CIM_DataFile( self.m_core.m_parsedArgs[0] ) ]

class BatchLetSys_lstat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_lstat,self).__init__(batchCore)

        self.m_significantArgs = [ ToObjectPath_CIM_DataFile( self.m_core.m_parsedArgs[0] ) ]

class BatchLetSys_access(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_access,self).__init__(batchCore)

        self.m_significantArgs = [ ToObjectPath_CIM_DataFile( self.m_core.m_parsedArgs[0] ) ]

class BatchLetSys_dup2(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_dup2,self).__init__(batchCore)

        # TODO: After that, the second file descriptor points to the first one.
        self.m_significantArgs = self.StreamName()

##### Memory system calls.

class BatchLetSys_mmap(BatchLetBase,object):
    def __init__(self,batchCore):
        # Not interested by anonymous map because there is no side effect.
        if batchCore.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return
        super( BatchLetSys_mmap,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName(4)

class BatchLetSys_munmap(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_munmap,self).__init__(batchCore)

        # The parameter is only an address and we cannot do much with it.
        self.m_significantArgs = []

# 'mmap2' ['NULL', '4096', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0'] ==>> 0xf7b21000 (09:18:26,09:18:26)
class BatchLetSys_mmap2(BatchLetBase,object):
    def __init__(self,batchCore):
        # Not interested by anonymous map because there is no side effect.
        if batchCore.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return
        super( BatchLetSys_mmap2,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName(4)



##### File system calls.

class BatchLetSys_fstat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fstat,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fstat64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fstat64,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fstatfs(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fstatfs,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fadvise64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fadvise64,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fchdir(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fchdir,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

        # This also stores the new current directory in the process.
        self.m_core.m_objectProcess.SetProcessCurrentDir(self.m_significantArgs[0])

class BatchLetSys_fcntl(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fcntl,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fcntl64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fcntl64,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fchown(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fchown,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_ftruncate(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_ftruncate,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fsync(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fsync,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_fchmod(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_fchmod,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


##### Process system calls.

# Two usual sets of flags:
# flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID
# flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD
#

# CLONE_CHILD_CLEARTID Erase child thread ID at location ctid in child memory when the child exits, and do a wakeup on the futex at that address.
# CLONE_CHILD_SETTID Store child thread ID at location ctid in child memory.
# CLONE_FILES If CLONE_FILES is set, the calling process and the child process share the same file descriptor table.
# CLONE_FS the caller and the child process share the same file system information.
# CLONE_NEWIPC If CLONE_NEWIPC is set, then create the process in a new IPC namespace.
# CLONE_NEWNET If CLONE_NEWNET is set, then create the process in a new network namespace.
# CLONE_NEWNS Start the child in a new mount namespace.
# CLONE_NEWPID Create the process in a new PID namespace.
# CLONE_NEWUTS create the process in a new UTS namespace.
# CLONE_PARENT the parent of the new child (as returned by getppid(2)) will be the same as that of the calling process.
# CLONE_PARENT_SETTID Store child thread ID at location ptid in parent and child memory.
# CLONE_PID the child process is created with the same process ID as the calling process.
# CLONE_PTRACE If CLONE_PTRACE is specified, and the calling process is being traced, then trace the child also .
# CLONE_SETTLS The newtls argument is the new TLS (Thread Local Storage) descriptor.
# CLONE_SIGHAND If CLONE_SIGHAND is set, the calling process and the child process share the same table of signal handlers.
# CLONE_STOPPED the child is initially stopped (as though it was sent a SIGSTOP signal), and must be resumed by sending it a SIGCONT signal.
# CLONE_SYSVSEM the child and the calling process share a single list of System V semaphore undo values (see semop(2)).
# CLONE_THREAD the child is placed in the same thread group as the calling process.
# CLONE_UNTRACED a tracing process cannot force CLONE_PTRACE on this child process.
# CLONE_VFORK the execution of the calling process is suspended until the child releases its virtual memory resources via a call to execve(2) or _exit(2).
# CLONE_VM the calling process and the child process run in the same memory space.
class BatchLetSys_clone(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_clone,self).__init__(batchCore)

        # The process id is the return value but does not have the same format
        # with ltrace (hexadecimal) and strace (decimal).
        if batchCore.m_tracer == "ltrace":
            aPid = int(self.m_core.m_retValue,16)

            # TODO: How to make the difference between thread and process ?
            isThread = True
        elif batchCore.m_tracer == "strace":
            aPid = int(self.m_core.m_retValue)
            flagsClone = self.m_core.m_parsedArgs[1].strip()
            if flagsClone.find("CLONE_VM") >= 0:
                isThread = True
            else:
                isThread = False
        else:
            raise Exception("Tracer %s not supported yet"%tracer)

        # sys.stdout.write("CLONE %s %s PID=%d\n" % ( batchCore.m_tracer, self.m_core.m_retValue, aPid) )

        # This is the created process.
        objNewProcess = ToObjectPath_CIM_Process( aPid)

        if isThread:
            objNewProcess.SetThread()

        self.m_significantArgs = [ objNewProcess ]

        objNewProcess.AddParentProcess(self.m_core.m_timeStart,self.m_core.m_objectProcess)

    # Process creations are not aggregated, not to lose the new pid.
    def SameCall(self,anotherBatch):
        return False

class BatchLetSys_vfork(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_vfork,self).__init__(batchCore)

        # The process id is the return value but does not have the same format
        # with ltrace (hexadecimal) and strace (decimal).
        if batchCore.m_tracer == "ltrace":
            aPid = int(self.m_core.m_retValue,16)
        elif batchCore.m_tracer == "strace":
            aPid = int(self.m_core.m_retValue)
        else:
            raise Exception("Tracer %s not supported yet"%tracer)

        # sys.stdout.write("VFORK %s %s PID=%d\n" % ( batchCore.m_tracer, self.m_core.m_retValue, aPid) )

        # This is the created process.
        objNewProcess = ToObjectPath_CIM_Process( aPid )
        self.m_significantArgs = [ objNewProcess ]

        objNewProcess.AddParentProcess(self.m_core.m_timeStart,self.m_core.m_objectProcess)
        # self.m_core.m_objectProcess.CreateSubprocess(objNewProcess)

    # Process creations are not aggregated, not to lose the new pid.
    def SameCall(self,anotherBatch):
        return False

# This is detected by strace.
# execve("/usr/bin/grep", ["grep", "toto", "../TestMySql.py"], [/* 34 vars */]) = 0 <0.000175>

# This is detected by ltrace also, with several situation:
# execve@SYS("/usr/local/bin/as", 0xd1a138, 0xd1a2b0) = -2 <0.000243>
# execve@SYS("/usr/bin/as", 0xd1a138, 0xd1a2b0 <no return ...>
# execve@SYS("/usr/bin/wc", 0x55e291ac8950, 0x55e291ac8f00 <unfinished ...>

class BatchLetSys_execve(BatchLetBase,object):
    def __init__(self,batchCore):

        # ['/usr/lib64/qt-3.3/bin/grep', '[grep, toto, ..]'] ==>> -1 ENOENT (No such file or directory)
        # If the executable could not be started, no point creating a batch node.
        if batchCore.m_retValue.find("ENOENT") >= 0 :
            return
        super( BatchLetSys_execve,self).__init__(batchCore)

        # The first argument is the executable file name,
        # while the second is an array of command-line parameters.
        objNewDataFile = ToObjectPath_CIM_DataFile(self.m_core.m_parsedArgs[0] )
        self.m_significantArgs = [
            objNewDataFile,
            self.m_core.m_parsedArgs[1] ]
        self.m_core.m_objectProcess.SetExecutable( objNewDataFile )
        objNewDataFile.SetIsExecuted()

        # TODO: Specifically filter the creation of a new process.

    # Process creations or setup are not aggregated.
    def SameCall(self,anotherBatch):
        return False

# This is detected by ltrace.
# __libc_start_main([ "python", "TestProgs/mineit_mysql_select.py" ] <unfinished ...>
# It does not matter if it is not technically finished: We only need the executable.
# BEWARE: See difference with BatchLetSys_xxx classes.
class BatchLetLib___libc_start_main(BatchLetBase,object):
    UnfinishedIsOk = True

    def __init__(self,batchCore):
        super( BatchLetLib___libc_start_main,self).__init__(batchCore)

        # TODO: Take the path of the executable name.
        execName = self.m_core.m_parsedArgs[0][0]
        objNewDataFile = ToObjectPath_CIM_DataFile(execName)
        self.m_significantArgs = [
            objNewDataFile,
            self.m_core.m_parsedArgs[0] ]
        self.m_core.m_objectProcess.SetExecutable( objNewDataFile )
        objNewDataFile.SetIsExecuted()

    # Process creations or setup are not aggregated.
    def SameCall(self,anotherBatch):
        return False

class BatchLetSys_wait4(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_wait4,self).__init__(batchCore)

        # sys.stdout.write("CLONE %s %s PID=%d\n" % ( batchCore.m_tracer, self.m_core.m_retValue, aPid) )

        # sys.stdout.write("WAIT A=%s\n" % self.m_core.m_retValue )
        # This is the terminated pid.
        if batchCore.m_tracer == "ltrace":
            if self.m_core.m_retValue.find("-10") >= 0:
                # ECHILD = 10
                # wait4@SYS(-1, 0x7ffea10cd110, 1, 0) = -10
                aPid = None
            else:
                # <... wait4 resumed> ) = 0x2df2 
                aPid = int(self.m_core.m_retValue,16)
                # sys.stdout.write("WAITzzz=%d\n" % aPid )
        elif batchCore.m_tracer == "strace":
            if self.m_core.m_retValue.find("ECHILD") >= 0:
                # wait4(-1, 0x7fff9a7a6cd0, WNOHANG, NULL) = -1 ECHILD (No child processes) 
                aPid = None
            else:
                # <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 27037 
                aPid = int(self.m_core.m_retValue.split(" ")[0])
                # sys.stdout.write("WAITxxx=%d\n" % aPid )
        else:
            raise Exception("Tracer %s not supported yet"%tracer)

        if aPid:
            # sys.stdout.write("WAIT=%d\n" % aPid )
            waitedProcess = ToObjectPath_CIM_Process( aPid )
            self.m_significantArgs = [ waitedProcess ]
            waitedProcess.WaitProcessEnd(self.m_core.m_timeStart, self.m_core.m_objectProcess)

class BatchLetSys_exit_group(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_exit_group,self).__init__(batchCore)

        self.m_significantArgs = []

#####

# int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
class BatchLetSys_newfstatat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_newfstatat,self).__init__(batchCore)

        dirNam = self.m_core.m_parsedArgs[0]

        if dirNam == "AT_FDCWD":
            dirPath = self.m_core.m_objectProcess.GetProcessCurrentDir()
        else:
            dirPath = STraceStreamToPathname( dirNam )

        filNam = self.m_core.m_parsedArgs[1]

        pathName = ToAbsPath( dirPath, filNam )

        self.m_significantArgs = [ ToObjectPath_CIM_DataFile(pathName) ]

class BatchLetSys_getdents(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_getdents,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_getdents64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_getdents64,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

##### Sockets system calls.

class BatchLetSys_sendmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_sendmsg,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

# sendmmsg(3<socket:[535040600]>, {{{msg_name(0)=NULL, msg_iov(1)=[{"\270\32\1\0\0\1\0\0
class BatchLetSys_sendmmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_sendmmsg,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_recvmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_recvmsg,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

# recvfrom(3<socket:[535040600]>, "\270\32\201\203\0\1\0\0\0\1\0\0\
class BatchLetSys_recvfrom(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_recvfrom,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

class BatchLetSys_getsockname(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_getsockname,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

# ['[{fd=5<UNIX:[73470->73473]>, events=POLLIN}]', '1', '25000'] ==>> 1 ([{fd=5, revents=POLLIN}])
class BatchLetSys_poll(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_poll,self).__init__(batchCore)

        arrStrms = self.m_core.m_parsedArgs[0]

        if batchCore.m_tracer == "strace":
            retList = []
            for oneStream in arrStrms:
                fdName = oneStream["fd"]
                filOnly = STraceStreamToFile( fdName )
                retList.append( filOnly )
                # sys.stdout.write("XX: %s\n" % filOnly )
            # return "XX="+str(arrStrms)
            self.m_significantArgs = [ retList ]
        else:
            self.m_significantArgs = []

# int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
# select ['1', ['0</dev/pts/2>'], [], ['0</dev/pts/2>'], {'tv_sec': '0', 'tv_usec': '0'}] ==>> 0 (Timeout) (07:43:14,07:43:14)
class BatchLetSys_select(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_select,self).__init__(batchCore)

        def ArrFdNameToArrString(arrStrms):
            if arrStrms == "NULL":
                # If the array of file descriptors is empty.
                return []
            else:
                return [ STraceStreamToFile( fdName ) for fdName in arrStrms ]

        arrArgs = self.m_core.m_parsedArgs
        arrFilRead = ArrFdNameToArrString(arrArgs[1])
        arrFilWrit = ArrFdNameToArrString(arrArgs[2])
        arrFilExcp = ArrFdNameToArrString(arrArgs[3])

        self.m_significantArgs = [ arrFilRead, arrFilWrit, arrFilExcp ]

class BatchLetSys_setsockopt(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_setsockopt,self).__init__(batchCore)

        self.m_significantArgs = [ self.m_core.m_retValue ]

# socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 6<UNIX:[2038057]>
class BatchLetSys_socket(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_socket,self).__init__(batchCore)

        self.m_significantArgs = [ STraceStreamToFile(self.m_core.m_retValue) ]

# Different output depending on the tracer:
# strace: connect(6<UNIX:[2038057]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110)
# ltrace: connect@SYS(3, 0x25779f0, 16, 0x1999999999999999)
class BatchLetSys_connect(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_connect,self).__init__(batchCore)
        objPath = STraceStreamToFile(self.m_core.m_parsedArgs[0])

        if batchCore.m_tracer == "strace":
            # 09:18:26.465799 socket(PF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_IP) = 3 <0.000013>
            # 09:18:26.465839 connect(3<socket:[535040600]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0 <0.000016>

            # TODO: Should link this file descriptor to the IP-addr+port pair.
            # But this is not very important because strace does the job of remapping the file descriptor,
            # so things are consistent as long as we follow the same logic, in the same order:
            #    socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3<TCP:[7275805]>
            #    connect(3<TCP:[7275805]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("204.79.197.212")}, 16) = 0
            #    select(4, NULL, [3<TCP:[192.168.0.17:48318->204.79.197.212:80]>], NULL, {900, 0}) = 1
            objPath.SocketAddress = self.m_core.m_parsedArgs[1]
            
        elif batchCore.m_tracer == "ltrace":
            pass
        else:
            raise Exception("Tracer %s not supported yet"%batchCore.m_tracer)

        self.m_significantArgs = [ objPath ]
class BatchLetSys_bind(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_bind,self).__init__(batchCore)
        objPath = STraceStreamToFile(self.m_core.m_parsedArgs[0])
        if batchCore.m_tracer == "strace":
            # bind(4<NETLINK:[7274795]>, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 0
            objPath.SocketAddress = self.m_core.m_parsedArgs[1]

        elif batchCore.m_tracer == "ltrace":
            pass
        else:
            raise Exception("Tracer %s not supported yet"%batchCore.m_tracer)

        self.m_significantArgs = [ objPath ]

# sendto(7<UNIX:[2038065->2038073]>, "\24\0\0", 16, MSG_NOSIGNAL, NULL, 0) = 16
class BatchLetSys_sendto(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_sendto,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

# TODO: If the return value is not zero, maybe reject.
# pipe([3<pipe:[255278]>, 4<pipe:[255278]>]) = 0
class BatchLetSys_pipe(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_pipe,self).__init__(batchCore)

        arrPipes = self.m_core.m_parsedArgs[0]
        arrFil0 = STraceStreamToFile(arrPipes[0])
        arrFil1 = STraceStreamToFile(arrPipes[1])

        self.m_significantArgs = [ arrFil0, arrFil1 ]


class BatchLetSys_shutdown(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLetSys_shutdown,self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


#F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python', '', '4096'] ==>> 7 (16:42:10,16:42:10)
#F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python2', 'python2', '4096'] ==>> 9 (16:42:10,16:42:10)
#F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python2.7', 'python2.7', '4096'] ==>> -22 (16:42:10,16:42:10)

################################################################################

class UnfinishedBatches:
    def __init__(self,withWarning):
        # This must be specific to processes.
        # Because when a system call is resumed, it is in the same process.
        self.m_mapStacks = {}
        self.m_withWarning = withWarning


    # PROBLEM. A vfork() is started in the main process but "appears" in another one.
    # What we could do is infer the main process number when a pid appreas without having been created before.
    # 08:53:31.301860 vfork( <unfinished ...>
    # [pid 23944] 08:53:31.304901 <... vfork resumed> ) = 23945 <0.003032>



    def PushBatch(self,batchCoreUnfinished):
        # sys.stdout.write("PushBatch pid=%s m_funcNam=%s\n"%(batchCoreUnfinished.m_pid,batchCoreUnfinished.m_funcNam))
        try:
            mapByPids = self.m_mapStacks[ batchCoreUnfinished.m_pid ]
            try:
                mapByPids[ batchCoreUnfinished.m_funcNam ].append( batchCoreUnfinished )
            except KeyError:
                mapByPids[ batchCoreUnfinished.m_funcNam ] = [ batchCoreUnfinished ]
        except KeyError:
            self.m_mapStacks[ batchCoreUnfinished.m_pid ] = { batchCoreUnfinished.m_funcNam : [ batchCoreUnfinished ] }
            
        # sys.stdout.write("PushBatch m_funcNam=%s\n"%batchCoreUnfinished.m_funcNam)

    def MergePopBatch(self,batchCoreResumed):
        # sys.stdout.write("MergePopBatch pid=%s m_funcNam=%s\n"%(batchCoreResumed.m_pid,batchCoreResumed.m_funcNam))
        try:
            stackPerFunc = self.m_mapStacks[ batchCoreResumed.m_pid][ batchCoreResumed.m_funcNam ]
        except KeyError:
            if self.m_withWarning > 1:
                sys.stdout.write("Resuming %s: cannot find unfinished call\n"%batchCoreResumed.m_funcNam)

            # This is strange, we could not find the unfinished call.
            # sys.stdout.write("MergePopBatch NOTFOUND1 m_funcNam=%s\n"%batchCoreResumed.m_funcNam)
            return None

        # They should have the same pid.
        try:
            batchCoreUnfinished = stackPerFunc[-1]
        except IndexError:
            if self.m_withWarning > 1:
                sys.stdout.write("MergePopBatch pid=%d m_funcNam=%s cannot find call\n"
                    % (batchCoreResumed.m_pid,batchCoreResumed.m_funcNam) )
            # Same problem, we could not find the unfinished call.
            # sys.stdout.write("MergePopBatch NOTFOUND2 m_funcNam=%s\n"%batchCoreResumed.m_funcNam)
            return None

        del stackPerFunc[-1]

        # Sanity check
        if batchCoreUnfinished.m_funcNam != batchCoreResumed.m_funcNam:
            raise Exception("Inconsistency batchCoreUnfinished.m_funcNam=%s batchCoreResumed.m_funcNam=%s\n"
                % ( batchCoreUnfinished.m_funcNam, batchCoreResumed.m_funcNam ) )

        # Now, the unfinished and the resumed batches are merged.
        argsMerged = batchCoreUnfinished.m_parsedArgs + batchCoreResumed.m_parsedArgs
        batchCoreResumed.m_parsedArgs = argsMerged

        # Sanity check
        if batchCoreUnfinished.m_status != BatchStatus.unfinished:
            raise Exception("Unfinished status is not plain:%d"%batchCoreUnfinished.m_status)

        batchCoreUnfinished.m_status = BatchStatus.matched
        batchCoreUnfinished.m_resumedBatch = batchCoreResumed

        # Sanity check
        if batchCoreResumed.m_status != BatchStatus.resumed:
            raise Exception("Resumed status is not plain:%d"%batchCoreResumed.m_status)

        batchCoreResumed.m_status = BatchStatus.merged
        batchCoreResumed.m_unfinishedBatch = batchCoreUnfinished

        return batchCoreResumed

    def PrintUnfinished(self,strm):
        if self.m_withWarning == 0:
            return
        for onePid in self.m_mapStacks:
            # strm.write("onePid=%s\n"%onePid)
            mapPid = self.m_mapStacks[ onePid ]

            isPidWritten = False
            
            for funcNam in mapPid:
                arrCores = mapPid[funcNam]
                if not arrCores: break

                if not isPidWritten:
                    isPidWritten = True
                    strm.write("Unfinished calls pid=%s\n"%onePid)

                strm.write("    Call name=%s\n"%funcNam)
                arrCores = mapPid[funcNam]
                for batchCoreUnfinished in arrCores:
                    strm.write("        %s\n" % ( batchCoreUnfinished.AsStr() ) )
                strm.write("\n")
        strm.write("\n")

# This is used to collect system or function calls which are unfinished and cannot be matched
# with the corresponding "resumed" line. In some circumstances, the beginning of a "wait4()" call
# might appear in one process, and the resumed part in another. Therefore this container 
# is global for all processes. The "withWarning" flag allows to hide detection of unmatched calls.
G_stackUnfinishedBatches = None

# There are displayed once only.
G_UnknownFunctions = set()

def BatchLetFactory(batchCore):

    try:
        # TODO: We will have to take the library into account.
        aModel = G_batchModels[ batchCore.m_funcNam ]
    except KeyError:
        # Default generic BatchLet, if the function is not associated to a derived class of BatchLetCore.
        if not batchCore.m_funcNam in G_UnknownFunctions:
            sys.stdout.write("Undefined function %s\n"%batchCore.m_funcNam)

            # Py_Main
            # readlink@SYS
            # getcwd@SYS
            # statfs@SYS
            # Py_Main@SYS
            # _llseek@SYS
            # madvise@SYS
            # _exit@SYS
            # prlimit64@SYS
            # ******->getenv
            # setrlimit@SYS
            # getrusage@SYS
            # unlink@SYS
            # umask@SYS
            # chmod@SYS
            # uname@SYS
            # times@SYS
            # mkdir@SYS
            # clock_gettime@SYS
            # sched_getaffinity@SYS
            # gettid@SYS
            # pipe2@SYS
            # getsockopt@SYS
            # clock_getres@SYS
            # getresuid@SYS
            # getresgid@SYS

            G_UnknownFunctions.add(batchCore.m_funcNam)
        return BatchLetBase( batchCore )

    # Explicitely non-existent.
    if aModel == None:
        return None

    # If this is an unfinished system call, it is not possible to build the correct derived class.
    # Until the pair of unfinished and resumed BatchCore-s are merged, this simply creates a generic base class.
    # [pid 12753] 14:56:54.296251 read(3 <unfinished ...>
    # [pid 12753] 14:56:54.296765 <... read resumed> , "#!/usr/bin/bash\n\n# Different ste"..., 131072) = 533 <0.000513>

    if batchCore.m_status == BatchStatus.unfinished:

        # A function as __libc_start_main() is happy if it is not finished
        # as the input parameters contain enough information for us.
        try:
            aModel.UnfinishedIsOk
            btchLetDrv = aModel( batchCore )
            # ResumedOnly
            # UnfinishedOnly
        except AttributeError:
            # We do not have the return value, and maybe not all the arguments,
            # so we simply store what we have and hope to merge
            # with the "resumed" part, later on.
            btchLetDrv = BatchLetBase( batchCore )

            # To match later with the "resumed" line.
            G_stackUnfinishedBatches.PushBatch( batchCore )
    elif batchCore.m_status == BatchStatus.resumed:
        # We should have the "unfinished" part somewhere.

        batchCoreMerged = G_stackUnfinishedBatches.MergePopBatch( batchCore )
        
        if batchCoreMerged:
            if batchCoreMerged != batchCore:
                raise Exception("Inconsistency 4")
            btchLetDrv = aModel( batchCoreMerged )
        else:
            # Could not find the matching unfinished batch.
            # Still we try the degraded mode if it is available.
            try:
                btchLetDrv = aModel.ResumedOnly( batchCore )
                raise Exception("CANNOT HAPPEN")
            except AttributeError:
                pass

            btchLetDrv = BatchLetBase( batchCore )
    else:
        btchLetDrv = aModel( batchCore )

    # If the parameters makes it unusable anyway.
    try:
        btchLetDrv.m_core
        # sys.stdout.write("batchCore=%s\n"%id(batchCore))
        if btchLetDrv.m_core != batchCore:
            raise Exception("Inconsistency 6")
        return btchLetDrv
    except AttributeError:
        return None

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
class BatchLetSequence(BatchLetBase,object):
    def __init__(self,arrBatch,style):
        batchCore = BatchLetCore()

        # TODO: Instaed of a string, this could be a tuple because it is hashable.
        concatSigns = "+".join( [ btch.GetSignature() for btch in arrBatch ] )
        batchCore.m_funcNam = "(" + concatSigns + ")"

        batchCore.m_status = BatchStatus.sequence

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
        batchCore.m_execTim = batchCore.m_timeEnd - batchCore.m_timeStart

        super( BatchLetSequence,self).__init__(batchCore,style)



def SignatureForRepetitions(batchRange):
    return "+".join( [ aBtch.GetSignatureWithArgs() for aBtch in batchRange ] )

            
# This is an execution flow, associated to a process. And a thread ?
class BatchFlow:
    def __init__(self):

        self.m_listBatchLets = []
        self.m_coroutine = self.AddingCoroutine()
        next(self.m_coroutine)

    def AddBatch(self,btchLet):
        # sys.stdout.write("AddBatch:%s\n"%btchLet.GetSignature())
        numBatches = len(self.m_listBatchLets)

        if numBatches > 0:
            lstBatch = self.m_listBatchLets[-1]

            if lstBatch.SameCall( btchLet ):
                lstBatch.m_occurrences += 1
                return

        self.m_listBatchLets.append( btchLet )

    # Does the same AddBatch() but it is possible to process system calls on-the-fly
    # without intermediate storage.
    def SendBatch(self,btchLet):
        self.m_coroutine.send(btchLet)

    def AddingCoroutine(self):
        lstBatch = None
        while True:
            btchLet = yield
            
            if lstBatch and lstBatch.SameCall( btchLet ):
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

        mapOccurences = self.StatisticsPairs()

        numSubst = 0
        idxBatch = 1
        while idxBatch < lenBatch:
            # sys.stdout.write("FilterMatchedBatches idxBatch=%d\n"%( idxBatch ) )
            batchSeq = self.m_listBatchLets[idxBatch]
            batchSeqPrev = self.m_listBatchLets[idxBatch-1]

            # Sanity check.
            if batchSeqPrev.m_core.m_status == BatchStatus.matched \
            and batchSeq.m_core.m_status == BatchStatus.merged:
                if batchSeqPrev.m_core.m_funcNam != batchSeq.m_core.m_funcNam :
                    raise Exception("INCONSISTENCY1 %s %s\n"% ( batchSeq.m_core.m_funcNam, batchSeqPrev.m_core.m_funcNam ) )

            if batchSeqPrev.m_core.m_status == BatchStatus.matched \
            and batchSeq.m_core.m_status == BatchStatus.merged:
                if batchSeqPrev.m_core.m_resumedBatch.m_unfinishedBatch != batchSeqPrev.m_core:
                    raise Exception("INCONSISTENCY2 %s\n"% batchSeqPrev.m_core.m_funcNam)

            if batchSeqPrev.m_core.m_status == BatchStatus.matched \
            and batchSeq.m_core.m_status == BatchStatus.merged:
                if batchSeq.m_core.m_unfinishedBatch.m_resumedBatch != batchSeq.m_core:
                    raise Exception("INCONSISTENCY3 %s\n"% batchSeq.m_core.m_funcNam)

            if batchSeqPrev.m_core.m_status == BatchStatus.matched \
            and batchSeq.m_core.m_status == BatchStatus.merged \
            and batchSeqPrev.m_core.m_resumedBatch == batchSeq.m_core \
            and batchSeq.m_core.m_unfinishedBatch == batchSeqPrev.m_core :
                del self.m_listBatchLets[idxBatch-1]
                batchSeqPrev = None
                batchSeq.m_core.m_unfinishedBatch = None
                lenBatch -= 1
                numSubst += 1

            idxBatch += 1
            
        return numSubst

    
    # This counts the frequency of consecutive pairs of calls.
    # Used to replace these common pairs by an aggregate call.
    def StatisticsPairs(self):

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
    def ClusterizePairs(self):
        lenBatch = len(self.m_listBatchLets)

        mapOccurences = self.StatisticsPairs()

        numSubst = 0
        idxBatch = 0
        maxIdx = lenBatch - 1
        batchSeqPrev = None
        while idxBatch < maxIdx:

            batchRange = self.m_listBatchLets[ idxBatch : idxBatch + 2 ]
            keyRange = SignatureForRepetitions( batchRange )
            numOccur = mapOccurences.get( keyRange, 0 )

            # sys.stdout.write("ClusterizePairs keyRange=%s numOccur=%d\n" % (keyRange, numOccur) )

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


    def DumpFlow(self,strm,outputFormat):

        batchDump = BatchDumperFactory(strm, outputFormat)

        batchDump.Header()

        for aBtch in self.m_listBatchLets:
            batchDump.DumpBatch(aBtch)

        batchDump.Footer()

    def FactorizeOneFlow(self,verbose,withWarning,outputFormat):

        if verbose > 1: self.DumpFlow(sys.stdout,outputFormat)

        if verbose > 0:
            sys.stdout.write("\n")
            sys.stdout.write("FilterMatchedBatches lenBatch=%d\n"%(len(self.m_listBatchLets)) )
        numSubst = self.FilterMatchedBatches()
        if verbose > 0:
            sys.stdout.write("FilterMatchedBatches numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )

        idxLoops = 0
        while True:
            if verbose > 1:
                self.DumpFlow(sys.stdout,outputFormat)

            if verbose > 0:
                sys.stdout.write("\n")
                sys.stdout.write("ClusterizePairs lenBatch=%d\n"%(len(self.m_listBatchLets)) )
            numSubst = self.ClusterizePairs()
            if verbose > 0:
                sys.stdout.write("ClusterizePairs numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )
            if numSubst == 0:
                break
            idxLoops += 1

        if verbose > 1: self.DumpFlow(sys.stdout,outputFormat)

        if verbose > 0:
            sys.stdout.write("\n")
            sys.stdout.write("ClusterizeBatchesByArguments lenBatch=%d\n"%(len(self.m_listBatchLets)) )
        numSubst = self.ClusterizeBatchesByArguments()
        if verbose > 0:
            sys.stdout.write("ClusterizeBatchesByArguments numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )

        if verbose > 1: self.DumpFlow(sys.stdout,outputFormat)

        
        

def LogSource(msgSource):
    sys.stdout.write("Source:%s\n"%msgSource)

################################################################################

# This executes a Linux command and returns the stderr pipe.
# It is used to get the return content of strace or ltrace,
# so it can be parsed.
def GenerateLinuxStreamFromCommand(aCmd, aPid):

    # If shell=True, the command must be passed as a single line.
    pipPOpen = subprocess.Popen(aCmd, bufsize=100000, shell=False,
        stdin=sys.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # stdin=subprocess.PIPE, stdout=subprocess.PIPE, stdout=subprocess.PIPE)

    # If shell argument is True, this is the process ID of the spawned shell.
    if aPid > 0:
        thePid = int(aPid)
    else:
        thePid = int(pipPOpen.pid)

    return ( thePid, pipPOpen.stderr )

# This applies to strace and ltrace.
# It isolates single lines describing an individual function or system call.
def CreateFlowsFromGenericLinuxLog(verbose,logStream,tracer):

    # "[pid 18196] 08:26:47.199313 close(255</tmp/shell.sh> <unfinished ...>"
    # "08:26:47.197164 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 18194 <0.011216>"
    # This test is not reliable because we cannot really control what a spurious output can be:
    def IsLogEnding(aLin):
        mtchBracket = re.match("^.*<([^>]*)>\n$", aLin)

        if not mtchBracket:
            return False

        strBrack = mtchBracket.group(1)
        ##sys.stdout.write("Brack=%s\n"%strBrack)

        if strBrack == "unfinished ...":
            return True

        # This value occurs exclusively with ltrace. Examples:
        # exit_group@SYS(0 <no return ...>
        # execve@SYS("/usr/bin/as", 0xd1a138, 0xd1a2b0 <no return ...>
        if strBrack == "no return ...":
            sys.stdout.write("NO RETURN\n")
            return True

        try:
            flt = float(strBrack)
            return True
        except:
            return False


    numLine = 0
    while True:
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

            # "[pid 18194] 08:26:47.197005 exit_group(0) = ?"
            # Not reliable because this could be a plain string ending like this.
            if tmpLine.startswith("[pid ") and tmpLine.endswith(" = ?\n"):
                oneLine += tmpLine
                break

            # "08:26:47.197304 --- SIGCHLD {si_signo=SIGCHLD, si_status=0, si_utime=0, si_stime=0} ---"
            # Not reliable because this could be a plain string ending like this.
            if tmpLine.endswith(" ---\n"):
                oneLine += tmpLine
                break

            # "[pid 18196] 08:26:47.199313 close(255</tmp/shell.sh> <unfinished ...>"
            # "08:26:47.197164 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 18194 <0.011216>"
            # This test is not reliable because we cannot really control what a spurious output can be:
            # if tmpLine.endswith(">\n"):
            if IsLogEnding( tmpLine ):
                # TODO: The most common case is that the call is on one line only.
                oneLine += tmpLine
                break

            # If the call is split on several lines, maybe because a write() contains a "\n".
            oneLine += tmpLine[:-1]

        # sys.stdout.write("BBB:%s"%oneLine)
        if not oneLine:
            break
        # sys.stdout.write("CCC:%s"%oneLine)

        # This parses the line into the basic parameters of a function call.
        try:
            batchCore = CreateBatchCore(oneLine,tracer)
        except:
            # raise Exception("Invalid line %d:%s\n"%(numLine,oneLine) )
            raise

        # Maybe the line cannot be parsed.
        if batchCore:

            # Based on the function call, it creates a specific derived class.
            aBatch = BatchLetFactory(batchCore)

            # Some functions calls should simply be forgotten because there are
            # no side effects, so simply forget them.
            if aBatch:
                yield aBatch

################################################################################

# These libc calls can be detected by ltrace but must be filtered
# because they do not bring information we want (And there are loads of them
# These libc calls can be detected by ltrace but must be filtered
# because they do not bring information we want (And there are loads of them))
G_ignoredCallLTrace = [
    "strncmp",
    "strlen",
    "malloc",
    "strcmp",
    "memcmp",
    "memcpy",
    "calloc",
    "malloc",
    "free",
    "memset",
    "strcasecmp",
    "__strdup",
    "strchr",
    "sprintf",
    "__errno_location",
    "bfd*",
    "fopen",
]

# Many libc calls are created by several libraries because they are static.
# For example:
#    gcc->getenv("GNUTARGET") = nil <0.000182>
#    liblto_plugin.so.0->getenv("COLLECT_GCC_OPTIONS") = "'-mtune=generic' '-march=x86-64'" <0.000321>
# Note that the results are visible.
#
# Also, there are many libc calls, and in general, we do not know how to process
# their arguments.
# So we filter them additively.

# mandatoryCallLTrace = [
  #   "getenv",
# ]

#-brk@SYS
#-rt_sigaction@SYS"   gcc TestProgs/HelloWorld.c
#]

# The command options generate a specific output file format,
# and therefore parsing it is specific to these options.
def BuildLTraceCommand(extCommand,aPid):
    # We do not want these libc calls.
    # strIgnoreLibc = "".join( "-" + libcCall for libcCall in G_ignoredCallLTrace )

    # strMandatoryLibc = "".join( "-" + libcCall for libcCall in mandatoryCallLTrace )

    # Remove everything, then add system calls and some libc functions whatever the shared lib

    # Remove everything, then add system calls and some libc functions whatever the shared lib
    # This selects:
    # libpython2.7.so.1.0->getenv, cx_Oracle.so->getenv, libclntsh.so.11.1->getenv, libresolv.so.2->getenv etc...
    strMandatoryLibc = "-*+getenv+*@SYS"

    # -f  Trace  child  processes as a result of the fork, vfork and clone.
    # This needs long strings because path names are truncated just like
    # normal strings.
    aCmd = ["ltrace",
        "-tt", "-T", "-f", "-S", "-s", "200", 
        # "-e", strIgnoreLibc + strIgnoredSysCall
        # "-e", strIgnoreLibc
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
        LogSource("Command "+" ".join(extCommand) )
    else:
        aCmd += [ "-p", aPid ]
        LogSource("Process %s\n"%aPid)

    LogSource("%s\n" % ( " ".join(aCmd) ) )

    return aCmd

def LogLTraceFileStream(extCommand,aPid):
    aCmd = BuildLTraceCommand( extCommand, aPid )
    return GenerateLinuxStreamFromCommand(aCmd, aPid)


# The output log format of ltrace is very similar to strace's, except that:
# - The system calls are suffixed with "@SYS"
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
# The command options generate a specific output file format,
# and therefore parsing it is specific to these options.
def BuildSTraceCommand(extCommand,aPid):
    # -f  Trace  child  processes as a result of the fork, vfork and clone.
    aCmd = ["strace",
        "-q", "-qq", "-f", "-tt", "-T", "-s", "200", "-y", "-yy",
        "-e", "trace=desc,ipc,process,network,memory",
        ]

    if extCommand:
        aCmd += extCommand
        LogSource("Command "+" ".join(extCommand) )
    else:
        aCmd += [ "-p", aPid ]
        LogSource("Process %s\n"%aPid)

    LogSource("%s\n" % ( " ".join(aCmd) ) )

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

# Read from a real process or from the log file name when replaying a session.
G_topProcessId = None

# Read from a real process or from the ini file when replaying a session.
G_CurrentDirectory = None

# When replaying a session, it is not worth getting information about processes
# because they do not exist anymore.
G_ReplayMode = False

################################################################################

def DefaultTracer(inputLogFile,tracer=None):
    if not tracer:
        if inputLogFile:
            # Maybe the pid is embedde in the log file.
            matchTrace = re.match(".*\.([^\.]*)\.[0-9]+\.log", inputLogFile )
            if matchTrace:
                tracer = matchTrace.group(1)
            else:
                # The file format might be "xyzxyz.strace.log", "abcabc.ltrace.log", "123123.cdb.log"
                # depending on the tool which generated the log.
                matchTrace = re.match(".*\.([^\.]*)\.log", inputLogFile )
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
    return mapKV

def CreateEventLog(argsCmd, aPid, inputLogFile, tracer ):
    global G_topProcessId
    global G_CurrentDirectory
    global G_ReplayMode

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

    if inputLogFile:
        logStream = open(inputLogFile)
        LogSource("File "+inputLogFile)
        sys.stdout.write("Logfile=%s pid=%s lenBatch=?\n" % (inputLogFile,aPid) )

        # The main process pid might be embedded in the log file name.
        G_topProcessId = aPid

        # There might be a context file with important information to reproduce the test.
        contextLogFile = os.path.splitext(inputLogFile)[0]+'.ini'
        mapKV = LoadIniFile(contextLogFile)

        G_CurrentDirectory = mapKV.get("CurrentDirectory",".")
        G_ReplayMode = True

    else:
        try:
            funcTrace = G_traceToTracer[ tracer ][0]
        except KeyError:
            raise Exception("Unknown tracer:%s"%tracer)

        ( G_topProcessId, logStream ) = funcTrace(argsCmd,aPid)
        G_CurrentDirectory = "."
        G_ReplayMode = False

    sys.stdout.write("G_CurrentDirectory=%s\n"%G_CurrentDirectory)

    # Another possibility is to start a process or a thread which will monitor
    # the target process, and will write output information in a stream.

    return logStream

# Global variables which must be reinitialised before a run.
def InitGlobals( withWarning ):
    global G_stackUnfinishedBatches
    G_stackUnfinishedBatches = UnfinishedBatches(withWarning)

    global G_mapCacheObjects
    G_mapCacheObjects = {}

    global G_mapFilDesToPathName
    G_mapFilDesToPathName = {
        "0" : "stdin",
        "1" : "stdout",
        "2" : "stderr"}

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

        if False:
            btchFlow.AddBatch( oneBatch )
        else:
            btchFlow.SendBatch( oneBatch )
    for aPid in sorted(list(mapFlows.keys()),reverse=True):
        btchTree = mapFlows[aPid]
        if verbose > 0: sys.stdout.write("\n================== PID=%d\n"%aPid)
        btchTree.FactorizeOneFlow(verbose,withWarning,outputFormat)
        

    return mapFlows

################################################################################

def FromStreamToFlow(verbose, withWarning, logStream, tracer,outputFormat, outFile, mapParamsSummary, summaryFormat, outputSummaryFile):
    mapFlows = CreateMapFlowFromStream( verbose, withWarning, logStream, tracer,outputFormat)

    G_stackUnfinishedBatches.PrintUnfinished(sys.stdout)

    if outFile:
        outFd = open(outFile, "w")

        for aPid in sorted(list(mapFlows.keys()),reverse=True):
            btchTree = mapFlows[aPid]
            outFd.write("\n================== PID=%d\n"%aPid)
            btchTree.DumpFlow(outFd,outputFormat)

        if verbose: sys.stdout.write("\n")

    GenerateSummary(mapFlows,mapParamsSummary,summaryFormat, outputSummaryFile)

# Function called for unit tests by unittest.py
# Function called for unit tests
def UnitTest(inputLogFile,tracer,topPid,outFile,outputFormat, verbose, mapParamsSummary, summaryFormat, withWarning, outputSummaryFile):

    logStream = CreateEventLog([], topPid, inputLogFile, tracer )

    # Check if there is a context file, which gives parameters such as the current directory,
    # necessary to reproduce the test in the same conditions.

    FromStreamToFlow(verbose, withWarning, logStream, tracer,outputFormat, outFile, mapParamsSummary, summaryFormat, outputSummaryFile)


if __name__ == '__main__':
    try:
        optsCmd, argsCmd = getopt.getopt(sys.argv[1:],
                "hvws:p:f:r:i:o:l:t:",
                ["help","verbose","warning","summary","pid","format","repetition","input","output","log","tracer"])
    except getopt.GetoptError as err:
        # print help information and exit:
        Usage(2,err) # will print something like "option -a not recognized"

    verbose = 0
    withWarning = 0
    # mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"]
    mapParamsSummary = ["CIM_Process","CIM_DataFile"]
    aPid = -1
    outputFormat = "TXT" # Default output format of the generated files.
    szWindow = 0
    inputLogFile = None
    outputSummaryFile = None
    outputLogFilePrefix = None
    tracer = None

    for anOpt, aVal in optsCmd:
        if anOpt in ("-v", "--verbose"):
            verbose += 1
        elif anOpt in ("-w", "--warning"):
            withWarning += 1
        elif anOpt in ("-s", "--summary"):
            mapParamsSummary = mapParamsSummary + [ aVal ] if aVal else []
        elif anOpt in ("-p", "--pid"):
            aPid = aVal
        elif anOpt in ("-f", "--format"):
            outputFormat = aVal.upper()
        elif anOpt in ("-w", "--window"):
            szWindow = int(aVal)
            raise Exception("Sliding window not implemented yet")
        elif anOpt in ("-i", "--input"):
            inputLogFile = aVal
        elif anOpt in ("-o", "--output"):
            outputSummaryFile = aVal
        elif anOpt in ("-l", "--log"):
            outputLogFilePrefix = aVal
        elif anOpt in ("-t", "--tracer"):
            tracer = aVal
        elif anOpt in ("-h", "--help"):
            Usage(0)
        else:
            assert False, "Unhandled option"


    tracer = DefaultTracer( inputLogFile, tracer )
    logStream = CreateEventLog(argsCmd, aPid, inputLogFile, tracer )

    if outputLogFilePrefix:
        # tee: This jusy need to reimplement "readline()"
        class TeeStream:
            def __init__(self,logStrm):
                self.m_logStrm = logStrm
                outFilNam = "%s.%s.%s.log" % ( outputLogFilePrefix, tracer, G_topProcessId )
                self.m_outFd = open( outFilNam, "w" )
                print("Creation of log file %s" % outFilNam )

            def readline(self):
                # sys.stdout.write("xxx\n" )
                aLin = self.m_logStrm.readline()
                # sys.stdout.write("tee=%s" % aLin)
                self.m_outFd.write(aLin)
                return aLin

        logStream = TeeStream(logStream)


    def signal_handler(signal, frame):
        print('You pressed Ctrl+C!')
        global G_Interrupt
        G_Interrupt = True

    # When waiting for a process, interrupt with control-C.
    if aPid > 0:
        signal.signal(signal.SIGINT, signal_handler)
        print('Press Ctrl+C to exit cleanly')

    # In normal usage, the summary output format is the same as
    # the output format for calls.
    FromStreamToFlow(verbose, withWarning, logStream, tracer,outputFormat, None, mapParamsSummary, outputFormat, outputSummaryFile )

################################################################################
# Options:
# -p pid
# -u user
# -g group

# https://www.eventtracker.com/newsletters/how-to-use-process-tracking-events-in-the-windows-security-log/
# https://stackoverflow.com/questions/26852228/detect-new-process-creation-instantly-in-linux
# https://stackoverflow.com/questions/6075013/detect-launching-of-programs-on-linux-platform

# An adapter to Linux kernel support for inotify directory-watching.
# https://pypi.python.org/pypi/inotify
# As an aside, Inotify doesn't work. It will not work on /proc/ to detect new processes:

# linux process monitoring (exec, fork, exit, set*uid, set*gid)
# http://bewareofgeek.livejournal.com/2945.html

################################################################################
# Cas de figure:
# findstr "wait4 vfork" UnitTests\mineit_gcc_incomplete.strace.log
#
#             08:53:31.301860 vfork( <unfinished ...>
# [pid 23944] 08:53:31.304901 <... vfork resumed> ) = 23945 <0.003032>
# [pid 23944] 08:53:31.304921 wait4(23945,  <unfinished ...>
#             08:53:31.335463 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 23945 <0.030535>
#             08:53:31.335744 vfork( <unfinished ...>
# [pid 23944] 08:53:31.336179 <... vfork resumed> ) = 23946 <0.000427>
# [pid 23944] 08:53:31.336196 wait4(23946,  <unfinished ...>
#             08:53:31.348242 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 23946 <0.012039>
#             08:53:31.349322 vfork( <unfinished ...>
# [pid 23944] 08:53:31.349554 <... vfork resumed> ) = 23947 <0.000222>
# [pid 23944] 08:53:31.349571 wait4(23947,  <unfinished ...>
# [pid 23947] 08:53:31.353394 vfork( <unfinished ...>
# [pid 23947] 08:53:31.353725 <... vfork resumed> ) = 23948 <0.000323>
# [pid 23947] 08:53:31.353797 wait4(23948,  <unfinished ...>
# [pid 23947] 08:53:31.478920 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 23948 <0.125108>
#             08:53:31.479748 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 23947 <0.130171>
#
#
# findstr "wait4 vfork" UnitTests\mineit_gcc_incomplete.strace.txt
# Pid= 23947 M'vfork@SYS' ['CIM_Process.Handle="23948"'] ==>> 23948
# Pid= 23947 M'wait4@SYS' ['CIM_Process.Handle="23948"'] ==>> 23948
# Pid= 23944 U'wait4@SYS' ['23945', ''] ==>> None
# Pid= 23944 R'vfork@SYS' [] ==>> 23945
# Pid= 23944 R'vfork@SYS' [] ==>> 23946
# Pid= 23944 U'wait4@SYS' ['23946', ''] ==>> None
# Pid= 23944 R'vfork@SYS' [] ==>> 23947
# Pid= 23944 U'wait4@SYS' ['23947', ''] ==>> None
# Pid=    -1 U'vfork@SYS' [] ==>> None (08:53:31,08:53:31)
# Pid=    -1 R'wait4@SYS' [[{'WIFEXITED(s) && WEXITSTATUS(s)': '= 0'}], '0', 'NULL'] ==>> 23945
# Pid=    -1 U'vfork@SYS' [] ==>> None
# Pid=    -1 R'wait4@SYS' [[{'WIFEXITED(s) && WEXITSTATUS(s)': '= 0'}], '0', 'NULL'] ==>> 23946
# Pid=    -1 U'vfork@SYS' [] ==>> None
# Pid=    -1 R'wait4@SYS' [[{'WIFEXITED(s) && WEXITSTATUS(s)': '= 0'}], '0', 'NULL'] ==>> 23947
#
#
