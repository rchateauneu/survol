#!/usr/bin/python


import re
import sys
import getopt
import os
import socket
import subprocess
import time

def Usage(exitCode = 1, errMsg = None):
    if errMsg:
        print(errMsg)

    progNam = sys.argv[0]
    print("Retrobatch: %s <executable>"%progNam)
    print("Monitors and factorizes systems calls.")
    print("  -h,--help                     This message.")
    print("  -v,--verbose                  Verbose mode.")
    print("  -p,--pid <pid>                Monitors a running process instead of starting an executable.")
    print("  -f,--format TXT|CSV|JSON      Output format. Default is TXT.")
    print("  -d,--depth <integer>          Maximum length of detected calls sequence. Default is 5.")
    print("  -w,--window <integer>         Size of sliding window of system calls, used for factorization.")
    print("                                Default is 0, i.e. no window")
    print("  -r,--repetition <integer>     Threshold of repetition number of system calls before being factorized")
    print("  -i,--input <file name>        trace command output file.")
    print("  -t,--tracer strace|ltrace|cdb command for generating trace log")
    print("")

    sys.exit(exitCode)

################################################################################

def LogWindowsFileStream(extCommand,aPid):
    raise Exception("Not implemented yet")

def CreateFlowsFromWindowsLogger(verbose,logStream,maxDepth):
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
    idx = 0

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

    if currStr:
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

# These functions return an object path.

def ToObjectPath_CIM_Process(aPid):
    objectPath = 'CIM_Process.Handle="%s"' % aPid
    return objectPath

# TODO: It might be a Linux socket or an IP socket.
def ToObjectPath_CIM_DataFile(pathName):
    objectPath = 'CIM_DataFile.Name="%s"' % pathName
    return objectPath

################################################################################

# strace associates file descriptors to the original file or socket which created it.
# Option "-y          Print paths associated with file descriptor arguments."
# read ['3</usr/lib64/libc-2.21.so>']
# This returns a WMI object path, which is self-descriptive.
def STraceStreamToFile(strmStr):
    idxLT = strmStr.find("<")
    pathName = strmStr[ idxLT + 1 : -1 ]
    return ToObjectPath_CIM_DataFile( pathName )


# Typical strings displayed by strace:
# [pid  7492] 07:54:54.205073 wait4(18381, [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 18381 <0.000894>
# [pid  7492] 07:54:54.206000 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=18381, si_uid=1000, si_status=1, si_utime=0, si_stime=0 } ---
# [pid  7492] 07:54:54.206031 newfstatat(7</home/rchateau/rdfmon-code/primhill>, "Survol", {st_mode=S_IFDIR|0775, st_size=4096, ...}, AT_SYMLIN K_NOFOLLOW) = 0 <0.000012>
# [pid  7492] 07:54:54.206113 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fb0d303fad0) = 18382 <0.000065>
# [pid  7492] 07:54:54.206217 wait4(18382, grep: ../../primhill/Survol: Is a directory
# [pid  7492] [{WIFEXITED(s) && WEXITSTATUS(s) == 2}], 0, NULL) = 18382 <0.000904>
# 07:54:54.207500 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=18382, si_uid=1000, si_status=2, si_utime=0, si_stime=0 } ---

# This is set to the parent pid as soon as it can be detected.
### rootPid = None

class BatchLetCore:
    # The input line is read from "strace" command.
    # [pid  7639] 09:35:56.198010 wait4(7777,  <unfinished ...>
    # 09:35:56.202030 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 7777 <0.004010>
    # [pid  7639] 09:35:56.202303 wait4(7778,  <unfinished ...>
    def __init__(self,oneLine = None):
        #global rootPid

        if oneLine is None:
            # This constructor is used when building a BatchLetSequence.

            self.m_retValue = "N/A"
            return

        # sys.stdout.write("oneLine1=%s" % oneLine )
        # self.m_debugLine = oneLine

        if oneLine[0:4] == "[pid":
            idxAfterPid = oneLine.find("]")

            pidParsed = int( oneLine[ 4:idxAfterPid ] )

            # This is a sub-process.
            self.m_pid = pidParsed

            self.InitAfterPid(oneLine[ idxAfterPid + 2 : ] )
        else:
            # This is the main process, but at this stage we do not have its pid.
            self.m_pid = -1
            self.InitAfterPid(oneLine)


    def InitAfterPid(self,oneLine):

        # "[{WIFEXITED(s) && WEXITSTATUS(s) == 2}], 0, NULL) = 18382 <0.000904>"
        if oneLine[0] == '[':
            raise ExceptionIsExit()

        # sys.stdout.write("oneLine2=%s" % oneLine )

        # This could be done without intermediary string.
        # "07:54:54.206113"
        try:
            # This date is conventional, but necessary, otherwise set to 1900/01/01..
            timStruct = time.strptime("2000/01/01 " + oneLine[:15],"%Y/%m/%d %H:%M:%S.%f")
            aTimeStamp = time.mktime( timStruct )
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

        idxPar = theCall.find("(")

        if idxPar <= 0 :
            raise Exception("No function in:%s"%oneLine)

        self.m_funcNam = theCall[:idxPar]
        # sys.stdout.write("theCall=%s\n" % theCall )

        idxGT = theCall.rfind(">")
        # sys.stdout.write("idxGT=%d\n" % idxGT )
        idxLT = theCall.rfind("<",0,idxGT)
        # sys.stdout.write("idxLT=%d\n" % idxLT )
        if idxLT >= 0 :
            self.m_execTim = theCall[idxLT+1:idxGT]
        else:
            self.m_execTim = ""

        # Maybe the system call is interrupted by a signal.
        # "[pid 18534] 19:58:38.406747 wait4(18666,  <unfinished ...>"
        # "19:58:38.410766 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 18666 <0.004009>"

        idxLastPar = FindNonEnclosedPar(theCall,idxPar+1)

        allArgs = theCall[idxPar+1:idxLastPar]

        idxEq = theCall.find( "=", idxLastPar )
        self.m_retValue = theCall[ idxEq + 1 : idxLT ].strip()
        # sys.stdout.write("retValue=%s\n"%self.m_retValue)

        # sys.stdout.write("allArgs=%s\n"%allArgs)
        self.m_parsedArgs = ParseSTraceObject( allArgs, True )
        # sys.stdout.write("Parsed arguments=%s\n" % str(self.m_parsedArgs) )

        # sys.stdout.write("Func=%s\n"%self.m_funcNam)


# Each class is indexed with the name of the corresponding system call name.
# If the class is None, it means that this function is explicitly neglected.
# If it is not defined after metaclass registration,
# then it is processed by BatchLetBase.
# Derived classes of BatchLetBase self-register thanks to the metaclass.
batchModels = {
    # "open"      : BatchLet_open,
    # ...
    # "close"     : BatchLet_close,
    "mprotect"  : None,
    "brk"       : None,
    "lseek"     : None,
    "arch_prctl": None,
}

# This metaclass allows derived class of BatchLetBase to self-register their function name.
# So, the name of a system call is used to lookup the class which represents it.
class BatchMeta(type):
    #def __new__(meta, name, bases, dct):
    #    return super(BatchMeta, meta).__new__(meta, name, bases, dct)

    def __init__(cls, name, bases, dct):
        global batchModels

        if name.startswith("BatchLet_"):
            shortClassName = name[9:]
            batchModels[ shortClassName ] = cls
        super(BatchMeta, cls).__init__(name, bases, dct)

# This is portable for Python 2 and Python 3.
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

    def __str__(self):
        return self.m_core.m_funcNam

    def SignificantArgs(self):
        # sys.stdout.write("m_core.m_funcNam=%s\n"%self.m_core.m_funcNam)
        # sys.stdout.write("m_core.m_pid=%s\n"%self.m_core.m_pid)
        # sys.stdout.write("m_core.m_timeStart=%s\n"%self.m_core.m_timeStart)
        # sys.stdout.write("m_core.m_timeEnd=%s\n"%self.m_core.m_timeEnd)

        return self.m_core.m_parsedArgs

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

        for idx,val1 in enumerate(args1):
            val2 = args2[idx]

            if val1 != val2:
                return False
            idx += 1

        return True

################################################################################

def FmtTim(aTim):
    return time.strftime("%H:%M:%S", time.gmtime(aTim))

class BatchDumberBase:
    def Header(self):
        return

    def Footer(self):
        return

class BatchDumperTXT(BatchDumberBase):
    def __init__(self,strm):
        self.m_strm = strm

    def DumpBatch(self,batchLet):
        self.m_strm.write("F=%6d {%4d/%s} '%-20s' %s ==>> %s (%s,%s)\n" %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            batchLet.m_core.m_funcNam,
            str(batchLet.SignificantArgs() ),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )

class BatchDumperCSV(BatchDumberBase):
    def __init__(self,strm):
        self.m_strm = strm

    def Header(self):
        self.m_strm.write("Pid,Occurrences,Style,Function,Arguments,Return,Start,End\n")

    def DumpBatch(self,batchLet):
        self.m_strm.write("%d,%d,%s,%s,%s,%s,%s,%s\n" %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            batchLet.m_core.m_funcNam,
            str(batchLet.SignificantArgs() ),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )

class BatchDumperJSON(BatchDumberBase):
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
            '   "function" : "%s"\n'
            '   "arguments" : %s\n'
            '   "return_value" : "%s"\n'
            '   "time_start" : "%s"\n'
            '   "time_end" : "%s"\n'
            '},\n' %(
            batchLet.m_core.m_pid,
            batchLet.m_occurrences,
            batchLet.m_style,
            batchLet.m_core.m_funcNam,
            str(batchLet.SignificantArgs() ),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )

    def Footer(self):
        self.m_strm.write( ']\n' )


def BatchDumperFactory(strm, outputFormat):
    BatchDumpersDictionary = {
        "TXT"  : BatchDumperTXT,
        "CSV"  : BatchDumperCSV,
        "JSON" : BatchDumperJSON
    }

    return BatchDumpersDictionary[ outputFormat ](strm)

################################################################################


##### File descriptor system calls.

# Must be a new-style class.
class BatchLet_open(BatchLetBase,object):
    def __init__(self,batchCore):
        if batchCore.m_retValue.find("ENOENT") >= 0 :
            # TODO: If the open is not successful, maybe it should be rejected.
            return
        super( BatchLet_open,self).__init__(batchCore)

    # But, if it succeeds, the file actually opened might be different,
    # than the input argument. Example:
    # open("/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib64/libc-2.25.so>
    # Therefore the returned file should be SignificantArgs(),
    # not the input file.
    def SignificantArgs(self):
        return [ STraceStreamToFile( self.m_core.m_retValue ) ]

class BatchLet_openat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_openat,self).__init__(batchCore)

    # A relative pathname is interpreted relative to the directory
    # referred to by the file descriptor passed as first parameter.
    def SignificantArgs(self):
        dirNam = self.m_core.m_parsedArgs[0]

        if dirNam == "AT_FDCWD":
            dirPath = "."
        else:
            dirPath = STraceStreamToFile( dirNam )

        filNam = self.m_core.m_parsedArgs[1]
        pathName = dirPath +"/" + filNam
        return [ ToObjectPath_CIM_DataFile( pathName ) ]

class BatchLet_close(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_close,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_read(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_read,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_write(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_write,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_ioctl(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_ioctl,self).__init__(batchCore)

    def SignificantArgs(self):
        return [ STraceStreamToFile( self.m_core.m_parsedArgs[0] ) ] + self.m_core.m_parsedArgs[1:0]

##### Memory system calls.

class BatchLet_mmap(BatchLetBase,object):
    def __init__(self,batchCore):
        # Not interested by anonymous map because there is no side effect.
        if batchCore.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return
        super( BatchLet_mmap,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName(4)

class BatchLet_munmap(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_munmap,self).__init__(batchCore)

    def SignificantArgs(self):
        # The parameter is only an address and we cannot do much with it.
        return []

# 'mmap2' ['NULL', '4096', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0'] ==>> 0xf7b21000 (09:18:26,09:18:26)
class BatchLet_mmap2(BatchLetBase,object):
    def __init__(self,batchCore):
        # Not interested by anonymous map because there is no side effect.
        if batchCore.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return
        super( BatchLet_mmap2,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName(4)



##### File system calls.

class BatchLet_fstat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fstat,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fstat64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fstat64,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fstatfs(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fstatfs,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fadvise64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fadvise64,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fchdir(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fchdir,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fcntl(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fcntl,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fcntl64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fcntl64,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fchown(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fchown,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_ftruncate(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_ftruncate,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fsync(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fsync,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fchmod(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fchmod,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()


##### Process system calls.

class BatchLet_clone(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_clone,self).__init__(batchCore)

    def SignificantArgs(self):
        # return [ self.m_core.m_parsedArgs[0] ]
        # This is the created pid.
        return [ ToObjectPath_CIM_Process( self.m_core.m_retValue ) ]

    # Process creations are not aggregated, not to lose the new pid.
    def SameCall(self,anotherBatch):
        return False

# execve("/usr/bin/grep", ["grep", "toto", "../TestMySql.py"], [/* 34 vars */]) = 0 <0.000175>
class BatchLet_execve(BatchLetBase,object):
    def __init__(self,batchCore):

        # ['/usr/lib64/qt-3.3/bin/grep', '[grep, toto, ..]'] ==>> -1 ENOENT (No such file or directory)
        # If the executable could not be started, no point creating a batch node.
        if batchCore.m_retValue.find("ENOENT") >= 0 :
            return
        super( BatchLet_execve,self).__init__(batchCore)

    # The first argument is the executable file name, while the second is an array 
    # of command-line parameters.
    def SignificantArgs(self):
        return [
            ToObjectPath_CIM_DataFile(self.m_core.m_parsedArgs[0] ),
            self.m_core.m_parsedArgs[1] ]

    # Process creations are not aggregated.
    def SameCall(self,anotherBatch):
        return False

class BatchLet_wait4(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_wait4,self).__init__(batchCore)

    def SignificantArgs(self):
        # The first argument is the PID.
        return [ ToObjectPath_CIM_Process( self.m_core.m_parsedArgs[0] ) ]

class BatchLet_exit_group(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_exit_group,self).__init__(batchCore)

    def SignificantArgs(self):
        return []

#####

class BatchLet_newfstatat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_newfstatat,self).__init__(batchCore)

    def SignificantArgs(self):
        dirNam = self.m_core.m_parsedArgs[0]

        if dirNam == "AT_FDCWD":
            dirPath = "."
        else:
            dirPath = STraceStreamToFile( dirNam )

        filNam = self.m_core.m_parsedArgs[1]
        pathName = dirPath +"/" + filNam
        return [ pathName ]

class BatchLet_getdents(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_getdents,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_getdents64(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_getdents64,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

##### Sockets system calls.

class BatchLet_sendmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_sendmsg,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

# sendmmsg(3<socket:[535040600]>, {{{msg_name(0)=NULL, msg_iov(1)=[{"\270\32\1\0\0\1\0\0
class BatchLet_sendmmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_sendmmsg,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_recvmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_recvmsg,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

# recvfrom(3<socket:[535040600]>, "\270\32\201\203\0\1\0\0\0\1\0\0\
class BatchLet_recvfrom(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_recvfrom,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_getsockname(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_getsockname,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

# ['[{fd=5<UNIX:[73470->73473]>, events=POLLIN}]', '1', '25000'] ==>> 1 ([{fd=5, revents=POLLIN}])
class BatchLet_poll(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_poll,self).__init__(batchCore)

    def SignificantArgs(self):
        arrStrms = self.m_core.m_parsedArgs[0]

        retList = []
        for oneStream in arrStrms:
            fdName = oneStream["fd"]
            filOnly = STraceStreamToFile( fdName )
            retList.append( filOnly )
            # sys.stdout.write("XX: %s\n" % filOnly )
        # return "XX="+str(arrStrms)
        return [ retList ]

# int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
# select ['1', ['0</dev/pts/2>'], [], ['0</dev/pts/2>'], {'tv_sec': '0', 'tv_usec': '0'}] ==>> 0 (Timeout) (07:43:14,07:43:14)
class BatchLet_select(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_select,self).__init__(batchCore)

    def SignificantArgs(self):
        def ArrFdNameToArrString(arrStrms):
            return [ STraceStreamToFile( fdName ) for fdName in arrStrms ]

        arrArgs = self.m_core.m_parsedArgs
        arrFilRead = ArrFdNameToArrString(arrArgs[1])
        arrFilWrit = ArrFdNameToArrString(arrArgs[2])
        arrFilExcp = ArrFdNameToArrString(arrArgs[3])

        return [ arrFilRead, arrFilWrit, arrFilExcp ]

class BatchLet_setsockopt(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_setsockopt,self).__init__(batchCore)

    def SignificantArgs(self):
        return [ self.m_core.m_retValue ]

# socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 6<UNIX:[2038057]>
class BatchLet_socket(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_socket,self).__init__(batchCore)

    def SignificantArgs(self):
        return [ STraceStreamToFile(self.m_core.m_retValue) ]

# connect(6<UNIX:[2038057]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110)
class BatchLet_connect(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_connect,self).__init__(batchCore)

    def SignificantArgs(self):
        return [ STraceStreamToFile(self.m_core.m_parsedArgs[0]), self.m_core.m_parsedArgs[1] ]

# sendto(7<UNIX:[2038065->2038073]>, "\24\0\0", 16, MSG_NOSIGNAL, NULL, 0) = 16
class BatchLet_sendto(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_sendto,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

# TODO: If the return value is not zero, maybe reject.
# pipe([3<pipe:[255278]>, 4<pipe:[255278]>]) = 0
class BatchLet_pipe(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_pipe,self).__init__(batchCore)

    def SignificantArgs(self):
        arrPipes = self.m_core.m_parsedArgs[0]
        arrFil0 = STraceStreamToFile(arrPipes[0])
        arrFil1 = STraceStreamToFile(arrPipes[1])

        return [ arrFil0, arrFil1 ]


class BatchLet_shutdown(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_shutdown,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()






################################################################################

def BatchFactory(oneLine):

    try:
        batchCore = BatchLetCore( oneLine )
    except ExceptionIsExit:
        return None
    except ExceptionIsSignal:
        return None

    try:
        aModel = batchModels[ batchCore.m_funcNam ]
    except KeyError:
        # Default generic BatchLet
        return BatchLetBase( batchCore )

    # Explicitely non-existent.
    if aModel == None:
        return None

    btchLetDrv = aModel( batchCore )

    # If the parameters makes it unusable anyway.
    try:
        btchLetDrv.m_core
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
        # global countSequence

        batchCore = BatchLetCore()

        concatSigns = "+".join( [ btch.GetSignature() for btch in arrBatch ] )

        # batchCore.m_funcNam = "Sequence_%d" % countSequence
        batchCore.m_funcNam = "(" + concatSigns + ")"

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
    def __init__(self,maxDepth):
        self.m_maxDepth = maxDepth

        self.m_listBatchLets = []

    def AddBatch(self,btchLet):
        # sys.stdout.write("AddBatch:%s\n"%btchLet.GetSignature())
        numBatches = len(self.m_listBatchLets)

        if numBatches > 0:
            lstBatch = self.m_listBatchLets[-1]

            if lstBatch.SameCall( btchLet ):
                lstBatch.m_occurrences += 1
                return

        self.m_listBatchLets.append( btchLet )


    def StatisticsPairs(self):

        lenBatch = len(self.m_listBatchLets)

        mapOccurences = {}

        sys.stdout.write("\n")
        sys.stdout.write("StatisticsPairs lenBatch=%d\n"%(lenBatch) )

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


    def ClusterizePairs(self):
        lenBatch = len(self.m_listBatchLets)
        sys.stdout.write("\n")
        sys.stdout.write("ClusterizePairs lenBatch=%d\n"%(lenBatch) )

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

            # Five occurences for example.
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
            
        sys.stdout.write("ClusterizePairs numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )
        return numSubst

    # Successive calls which have the same arguments are clusterized into logical entities.
    def ClusterizeBatchesByArguments(self):
        lenBatch = len(self.m_listBatchLets)

        sys.stdout.write("\n")
        sys.stdout.write("ClusterizeBatchesByArguments lenBatch=%d\n"%(lenBatch) )

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
        sys.stdout.write("ClusterizeBatchesByArguments numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )



    def DumpFlow(self,strm,outputFormat):

        batchDump = BatchDumperFactory(strm, outputFormat)

        batchDump.Header()

        for aBtch in self.m_listBatchLets:
            batchDump.DumpBatch(aBtch)

        batchDump.Footer()

def LogSource(msgSource):
    sys.stdout.write("Source:%s\n"%msgSource)

################################################################################

# This executes a Linux command and returns the stderr pipe.
# It is used to get the return content of strace or ltrace,
# so it can be parsed.
def GenerateLinuxStreamFromCommand(aCmd):

    # If shell=True, the command must be passed as a single line.
    pipPOpen = subprocess.Popen(aCmd, bufsize=100000, shell=False,
        stdin=sys.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # stdin=subprocess.PIPE, stdout=subprocess.PIPE, stdout=subprocess.PIPE)

    return pipPOpen.stderr

################################################################################
# The command options generate a specific output file format,
# and therefore parsing it is specific to these options.
def BuildLTraceCommand(extCommand,aPid):
    # -f  Trace  child  processes as a result of the fork, vfork and clone.
    aCmd = ["ltrace",
        "-tt", "-T", "-f", "-S", "-s", "20", 
        ]

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
    return GenerateLinuxStreamFromCommand(aCmd)


# The output log format of ltrace is very similar to strace's, except that:
# - The system calls are suffixed with "@SYS"
# - Entering and leaving a shared library is surrounded by the lines:
# ...  Py_Main(...  <unfinished ...>
# ...  <... Py_Main resumed> ) 

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



def CreateFlowsFromLtraceLog(verbose,logStream,maxDepth):
    # The output format of the command ltrace seems very similar to strace
    # so for the moment, no reason not to use it.
    return CreateFlowsFromLinuxSTraceLog(verbose,logStream,maxDepth)

################################################################################
# The command options generate a specific output file format,
# and therefore parsing it is specific to these options.
def BuildSTraceCommand(extCommand,aPid):
    # -f  Trace  child  processes as a result of the fork, vfork and clone.
    aCmd = ["strace",
        "-q", "-qq", "-f", "-tt", "-T", "-s", "20", "-y", "-yy",
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
    return GenerateLinuxStreamFromCommand(aCmd)

def CreateFlowsFromLinuxSTraceLog(verbose,logStream,maxDepth):
    while True:
        oneLine = ""

        # If this line is not properly terminated, then concatenates the next line.
        # FIXME: Problem if several processes.
        while True:
            tmpLine = logStream.readline()
            # sys.stdout.write("tmpLine after read=%s"%tmpLine)
            if not tmpLine:
                break
            if tmpLine.endswith(">\n"):
                # TODO: The most common case is that the call is on one line only.
                oneLine += tmpLine
                break

            # If the call is split on several lines, maybe because a write() contains a "\n".
            oneLine += tmpLine[:-1]

        if not oneLine:
            break

        matchResume = re.match( ".*<\.\.\. ([^ ]*) resumed> (.*)", oneLine )
        if matchResume:
            # TODO: Should check if this is the correct function name.
            funcNameResumed = matchResume.group(1)
            # sys.stdout.write("RESUMING FUNCTION resumed C:%s\n"%funcNameResumed)
            lineRest = matchResume.group(2)
            continue


        # This could be done without intermediary string.
        aBatch = BatchFactory(oneLine)
        if aBatch:
            yield aBatch

################################################################################

def FactorizeMapFlows(mapFlows,verbose,outputFormat,maxDepth,thresholdRepetition):
    for aPid in sorted(list(mapFlows.keys()),reverse=True):
        btchTree = mapFlows[aPid]
        sys.stdout.write("\n================== PID=%d\n"%aPid)
        FactorizeOneFlow(btchTree,verbose,outputFormat,maxDepth,thresholdRepetition)

def FactorizeOneFlow(btchTree,verbose,outputFormat,maxDepth,thresholdRepetition):

    idxLoops = 0
    while True:
        btchTree.DumpFlow(sys.stdout,outputFormat)
        numSubst = btchTree.ClusterizePairs()
        if numSubst == 0:
            break
        idxLoops += 1

    btchTree.DumpFlow(sys.stdout,outputFormat)

    btchTree.ClusterizeBatchesByArguments()

    btchTree.DumpFlow(sys.stdout,outputFormat)
    # treeStats = btchTree.CreateStatisticsTree(maxDepth)


traceToTracer = {
    "cdb"    : ( LogWindowsFileStream, CreateFlowsFromWindowsLogger ),
    "strace" : ( LogSTraceFileStream , CreateFlowsFromLinuxSTraceLog ),
    "ltrace" : ( LogLTraceFileStream, CreateFlowsFromLtraceLog )
    }

def CreateEventLog(argsCmd, aPid, inputLogFile, tracer ):
    # A command or a pid or an input log file, only one possibility.
    if argsCmd != []:
        if aPid or inputLogFile:
            Usage(1,"When providing command, must not specify process id or input log file")
    elif aPid:
        if argsCmd != [] or inputLogFile:
            Usage(1,"When providing process id, must not specify command or input log file")
    elif inputLogFile:
        if argsCmd != [] or aPid:
            Usage(1,"When providing input file, must not specify command or process id")
    else:
        Usage(1,"Must provide command, pid or input file")

    if inputLogFile:
        logStream = open(inputLogFile)
        LogSource("File "+inputLogFile)
        sys.stdout.write("Logfile=%s lenBatch=?\n" % inputLogFile)
    else:
        try:
            funcTrace = traceToTracer[ tracer ][0]
        except KeyError:
            raise Exception("Unknown tracer:%s"%tracer)

        logStream = funcTrace(argsCmd,aPid)


    # Another possibility is to start a process or a thread which will monitor
    # the target process, and will write output information in a stream.

    return logStream

def CreateMapFlowFromStream( verbose, logStream, tracer, maxDepth ):
    # Here, we have an event log as a stream, which comes from a file (if testing),
    # the output of strace or anything else.

    # Consider some flexibility in this input format.
    # This is why there are two implementations.

    mapFlows = {}

    # This step transforms the input log into a map of BatchFlow,
    # which have the same format whatever the platform is.
    try:
        funcCreator = traceToTracer[ tracer ][1]
    except KeyError:
        raise Exception("Unknown tracer:%s"%tracer)

    # mapFlows = funcCreator(verbose,logStream,maxDepth)
    mapFlowsGenerator = funcCreator(verbose,logStream,maxDepth)

    for oneBatch in mapFlowsGenerator:
        aCore = oneBatch.m_core

        aPid = aCore.m_pid
        try:
            btchFlow = mapFlows[ aPid ]
        except KeyError:
            # This is the first system call of this process.
            btchFlow = BatchFlow(maxDepth)
            mapFlows[ aPid ] = btchFlow

        btchFlow.AddBatch( oneBatch )

    # TODO: maxDepth should not be passed as a parameter.
    # It is only there because stats are created.
    return mapFlows

# Function called for unit tests
def UnitTest(inputLogFile,tracer,outFile,outputFormat):
    logStream = CreateEventLog([], None, inputLogFile, tracer )

    maxDepth = 5
    mapFlows = CreateMapFlowFromStream( False, logStream, tracer, maxDepth )

    FactorizeMapFlows(mapFlows,False,outputFormat,maxDepth,0)

    outFd = open(outFile, "w")

    for aPid in sorted(list(mapFlows.keys()),reverse=True):
        btchTree = mapFlows[aPid]
        outFd.write("\n================== PID=%d\n"%aPid)
        btchTree.DumpFlow(outFd,outputFormat)

    outFd.close()
    sys.stdout.write("Test finished")


if __name__ == '__main__':
    try:
        optsCmd, argsCmd = getopt.getopt(sys.argv[1:],
                "hvp:f:d:w:r:i:t:",
                ["help","verbose","pid","format","depth","window","repetition","input","tracer"])
    except getopt.GetoptError as err:
        # print help information and exit:
        Usage(2,err) # will print something like "option -a not recognized"

    verbose = False
    aPid = None
    outputFormat = "TXT" # Default output format of the generated files.
    maxDepth = 5
    szWindow = 0
    thresholdRepetition = 10
    inputLogFile = None

    if sys.platform.startswith("win32"):
        tracer = "cdb"
    elif sys.platform.startswith("linux"):
        tracer = "strace"
    else:
        tracer = "unknown tracer command"

    for anOpt, aVal in optsCmd:
        if anOpt in ("-v", "--verbose"):
            verbose = True
        elif anOpt in ("-p", "--pid"):
            aPid = aVal
        elif anOpt in ("-f", "--format"):
            outputFormat = aVal.upper()
        elif anOpt in ("-d", "--depth"):
            maxDepth = int(aVal)
        elif anOpt in ("-w", "--window"):
            szWindow = int(aVal)
            raise Exception("Sliding window not implemented yet")
        elif anOpt in ("-r", "--repetition"):
            thresholdRepetition = int(aVal)
        elif anOpt in ("-i", "--input"):
            inputLogFile = aVal
        elif anOpt in ("-t", "--tracer"):
            tracer = aVal
        elif anOpt in ("-h", "--help"):
            Usage(0)
        else:
            assert False, "Unhandled option"

    logStream = CreateEventLog(argsCmd, aPid, inputLogFile, tracer )

    mapFlows = CreateMapFlowFromStream( verbose, logStream, tracer, maxDepth )

    FactorizeMapFlows(mapFlows,verbose,outputFormat,maxDepth,thresholdRepetition)

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

    # Une premiere passe sur le log decoupleen traces independantes,
    # selon pid ou tid ou bien selon le time-stamp, s'il y a un delai importnant..
    # Ca genere des maps de BatchFlows. L index peut etre pid, tid, ou un time rgane.
    # Ensuite on injecte des batchflows, independamment, vers des passes de simplification.
