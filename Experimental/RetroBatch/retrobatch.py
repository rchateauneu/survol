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
    print("  -h,--help                 This message.")
    print("  -v,--verbose              Verbose mode.")
    print("  -p,--pid <pid>            Monitors a running process instead of starting an executable.")
    print("  -f,--format TXT|CSV|JSON  Output format. Default is TXT.")
    print("  -d,--depth <integer>      Maximum length of detected calls sequence. Default is 5.")
    print("  -w,--window <integer>     Size of sliding window of system calls, used for factorization.")
    print("                            Default is 0, i.e. no window")
    print("  -r,--repetition <integer> Threshold of repetition number of system calls before being factorized")
    print("  -i,--input <file name>    strace or cdb output file.")
    print("")

    sys.exit(exitCode)

################################################################################

def CreateFlowsFromWindowsLogger(verbose,logStream,maxDepth):
    raise Exception("Not implemented yet")
    return

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

# strace associates file descriptors to the original file or socket which created it.
# Option "-y          Print paths associated with file descriptor arguments."
# read ['3</usr/lib64/libc-2.21.so>']
def STraceStreamToFile(strmStr):
    idxLT = strmStr.find("<")
    return strmStr[ idxLT + 1 : -1 ]


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


class BatchLetBase:
    __metaclass__ = BatchMeta

    def __init__(self,batchCore):
        self.m_core = batchCore
        self.m_occurences = 1
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
        self.m_strm.write("F=%6d {%4d} '%-20s' %s ==>> %s (%s,%s)\n" %(
            batchLet.m_core.m_pid,
            batchLet.m_occurences,
            batchLet.m_core.m_funcNam,
            str(batchLet.SignificantArgs() ),
            batchLet.m_core.m_retValue,
            FmtTim(batchLet.m_core.m_timeStart),
            FmtTim(batchLet.m_core.m_timeEnd) ) )

class BatchDumperCSV(BatchDumberBase):
    def __init__(self,strm):
        self.m_strm = strm

    def Header(self):
        self.m_strm.write("Pid,Occurences,Function,Arguments,Return,Start,End\n")

    def DumpBatch(self,batchLet):
        self.m_strm.write("%d,%d,%s,%s,%s,%s,%s\n" %(
            batchLet.m_core.m_pid,
            batchLet.m_occurences,
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
            '   "occurences" : %d\n'
            '   "function" : "%s"\n'
            '   "arguments" : %s\n'
            '   "return_value" : "%s"\n'
            '   "time_start" : "%s"\n'
            '   "time_end" : "%s"\n'
            '},\n' %(
            batchLet.m_core.m_pid,
            batchLet.m_occurences,
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

# Must be a new-style class.
class BatchLet_open(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_open,self).__init__(batchCore)

    # TODO: If the open is not successful, maybe it should be rejected.
    # TODO: But, if it succeeds, the file actually opened might be different,
    # than the input argument. Example:
    # open("/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib64/libc-2.25.so>
    # Therefore the returned file should be SignificantRgas().
    # But if we also keep the input file, it might hamper the grouping
    # of calls on the same parameters.

    def SignificantArgs(self):
        # return self.StreamName()
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_openat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_openat,self).__init__(batchCore)

    # TODO: A relative pathname is interpreted relative to the directory
    # referred to by the file descriptor passed as first parameter.
    def SignificantArgs(self):
        return self.StreamName(1)

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

class BatchLet_mmap(BatchLetBase,object):
    def __init__(self,batchCore):
        # Not interested by anonymous map because there is no side effect.
        if batchCore.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return
        super( BatchLet_mmap,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName(4)

class BatchLet_ioctl(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_ioctl,self).__init__(batchCore)

    def SignificantArgs(self):
        return [ STraceStreamToFile( self.m_core.m_parsedArgs[0] ) ] + self.m_core.m_parsedArgs[1:0]

class BatchLet_fstat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_fstat,self).__init__(batchCore)

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

class BatchLet_clone(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_clone,self).__init__(batchCore)

    def SignificantArgs(self):
        return [ self.m_core.m_parsedArgs[0] ]

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

    def SignificantArgs(self):
        return self.m_core.m_parsedArgs[0:2]

    # Process creations are not aggregated.
    def SameCall(self,anotherBatch):
        return False

class BatchLet_wait4(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_wait4,self).__init__(batchCore)

    def SignificantArgs(self):
        # The first argument is the PID.
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_newfstatat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_newfstatat,self).__init__(batchCore)

    def SignificantArgs(self):
        dirNam = self.m_core.m_parsedArgs[0]
        filNam = self.m_core.m_parsedArgs[1]
        pathName = dirNam +"/" + filNam
        return [ pathName ]

class BatchLet_getdents(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_getdents,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_openat(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_openat,self).__init__(batchCore)

    def SignificantArgs(self):
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_sendmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_sendmsg,self).__init__(batchCore)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_recvmsg(BatchLetBase,object):
    def __init__(self,batchCore):
        super( BatchLet_recvmsg,self).__init__(batchCore)

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



# Typical repetitions:

# This happens at process startup:
# open ['/lib64/libselinux.so.']
# read ['/usr/lib64/libselinux.so.1']
# fstat ['/usr/lib64/libselinux.so.1']
# mmap ['/usr/lib64/libselinux.so.1']
# mmap ['/usr/lib64/libselinux.so.1']
# close ['/usr/lib64/libselinux.so.1']
# open ['/lib64/libm.so.']
# read ['/usr/lib64/libm-2.21.so']
# fstat ['/usr/lib64/libm-2.21.so']
# mmap ['/usr/lib64/libm-2.21.so']
# mmap ['/usr/lib64/libm-2.21.so']
# close ['/usr/lib64/libm-2.21.so']
# open ['/lib64/libc.so.']
# read ['/usr/lib64/libc-2.21.so']
# fstat ['/usr/lib64/libc-2.21.so']
# mmap ['/usr/lib64/libc-2.21.so']
# mmap ['/usr/lib64/libc-2.21.so']
# close ['/usr/lib64/libc-2.21.so']



# open ['/usr/share/locale/en_GB.UTF-8/LC_MESSAGES/findutils.m']
# open ['/usr/share/locale/en_GB.utf8/LC_MESSAGES/findutils.m']
# ...
# open ['/usr/share/locale/en.utf8/LC_MESSAGES/findutils.m']
# open ['/usr/share/locale/en/LC_MESSAGES/findutils.m']

# write ['pipe:[82244]']
# write ['pipe:[82244]']
# ...
# write ['pipe:[82244]']


#def GetBatchesSignature(arrBatches):
#    arrSigs = [ aBatch.GetSignature() for aBatch in arrBatches ]
#    sigBatch = ",".join( arrSigs )
#    return sigBatch

# This is just a helper for counting generated sequences.
# countSequence = 0

# VIRE LES BATCHLETS QUI N ONT PAS A D ARGUMENT INTERESSANT, STYLE FICHIER OU SOCKET.
# SELON LA DLL CA SE FERA DIFFEREMMENT.

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
    def __init__(self,arrBatch):
        # global countSequence

        batchCore = BatchLetCore()

        concatSigns = "+".join( [ btch.GetSignature() for btch in arrBatch ] )

        # batchCore.m_funcNam = "Sequence_%d" % countSequence
        batchCore.m_funcNam = "(" + concatSigns + ")"

        sys.stdout.write("BatchLetSequence concatSigns=%s\n"%concatSigns)

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

        super( BatchLetSequence,self).__init__(batchCore)


# On essaye de former une sequence en aveugle.
# le constructor 

#     def SignificantArgs(self):
#         ON repere les arguments.
# on essaye de s en abstraire.
# Exemple de critere de fusion:
#     Meme signature de fonctions (Signature "legere")
#     Juste un seul argument (Eventuellement different). Alors on considere que c est la meme operation "en gros".
# 
# Ou:
#     Meme signature concatenee (signature "lourde")
#         return self.m_core.m_parsedArgs[0]
# 
# Donc une sequence peut apparaitre deux fois ?
# Quel remplacement est le plus avantageux ?
# 
# Il faut pouvoir empiler les BatchLetSequence.
# 
# Faire plusieurs passes dans la liste pour factoriser a plusieurs niveaux.
# Et recalculer les statistiques.
# Si on garde dans la fenetre (Si fil de l eau) des elements,
# et qu'ensuite on les vire, envoyer status=deleted.
# 


class StatisticsNode:
    def __init__(self, signat = None):
        self.m_mapStats = {}
        self.m_signature = signat
        self.m_occurences = 0

    # This adds a complete sequence of batches and updates the intermediary nodes.
    def AddCompleteBatchRange(self,batchRange):
        lenBatch = len(batchRange)
        # sys.stdout.write("AddCompleteBatchRange batchRange=%s\n" % ",".join([ str(btch) for btch in batchRange ] ) )

        if lenBatch == 0:
            raise Exception("Empty range")

        idx = 0
        currNode = self
        while idx < lenBatch:
            currSignature = batchRange[idx].GetSignature()
            try:
                subNode = currNode.m_mapStats[ currSignature ]
            except KeyError:
                subNode = StatisticsNode( currSignature )
                subNode.m_occurences = 0
                currNode.m_mapStats[ currSignature ] = subNode

            subNode.m_occurences += 1
            currNode = subNode
            idx += 1

    # TODO: Renvoyer plutot l'occurence la plus elevee et sa longueur.
    def GetOccurences( self, batchRange ):
        lenBatch = len(batchRange)

        sys.stdout.write("GetOccurences:%s\n" % "=".join( [ btch.GetSignature() for btch in batchRange ] ) )
        idx = 0
        currNode = self
        while idx < lenBatch:
            currSignature = batchRange[idx].GetSignature()
            try:
                subNode = currNode.m_mapStats[ currSignature ]
                sys.stdout.write("    SubNode: %d %s \n"%(subNode.m_occurences,currSignature))
            except KeyError:
                raise Exception("Tree should be deeper:idx=%d lenBatch=%d currSignature=%s"%(idx,lenBatch,currSignature) )
            currNode = subNode
            idx += 1

        sys.stdout.write("Occurences:%d\n" % currNode.m_occurences)
        return subNode.m_occurences

    # Another approach is to look for a plateau.

    # This takes the longest possible range prefix, whose occurence is greater or equal to the threahold.
    def GetOccurencesMinimal( self, batchRange, currThreshold ):
        lenBatch = len(batchRange)

        sys.stdout.write(
                "GetOccurencesMinimal currThreshold=%d lenBatch=%d batchRange=%s\n"
                %(currThreshold,lenBatch,"-".join([btch.GetSignature() for btch in batchRange])))
        idx = 0
        currNode = self
        while idx < lenBatch:
            currSignature = batchRange[idx].GetSignature()
            try:
                currNode = currNode.m_mapStats[ currSignature ]
                sys.stdout.write("    CurrNode: %d %s \n"%(currNode.m_occurences,currSignature))
            except KeyError:
                raise Exception("Tree should be deeper. idx=%d currSignature=%s\n"%(idx,currSignature))

            if currNode.m_occurences < currThreshold:
                break

            idx += 1

        sys.stdout.write("GetOccurencesMinimal idx=%d Occurences:%d currThreshold=%d\n" % (idx, currNode.m_occurences, currThreshold ) )
        return idx


    def DumpStats(self, strm, newMargin = "" ):
        strm.write( "%s%-20s {%4d}\n" % ( newMargin, self.m_signature, self.m_occurences ) )
        for aSig in sorted( list( self.m_mapStats.keys() ) ):
            aSub = self.m_mapStats[ aSig ]
            aSub.DumpStats( strm, newMargin + "....")
            
            
def SignatureForRepetitions(batchRange):
    return "+".join( [ aBtch.GetSignatureWithArgs() for aBtch in batchRange ] )

            
# This is an execution flow, associated to a process. And a thread ?
class BatchFlow:
    def __init__(self,maxDepth):
        self.m_maxDepth = maxDepth
        # self.m_treeStats = StatisticsNode()

        self.m_listBatchLets = []

        # This contain combinations of system calls, of length 2, 3 etc...
        # Problem: If we increase the depth, the calculation step becomes quadratic.
        #
        # Notes about how to factorize consecutive system calls:
        # - If a signature does not appear too often, remove it.
        # - If a signature is repetitive, remove it.
        # - Signatures are cyclic: If several signatures are identical except a rotation,
        #   only one should be kept. By convention, alphabetical order ?
        #   Or, before inserting, check for the existence of a rotated signature ?
        # - When replacing a sequence, possibly rotate the signature ?
        #
        #
        # Un BatchLet a deux signatures: 
        # - Avec ou sans les arguments. Actuellement, on a uniquement le nom de la fonction.
        # 
        # On peut grouper des batchlets de plusieurs facons:
        # - On garde les arguments
        # - On ne garde que le nom de la fonction.
        # - On factorise le seul argument interessant: pid ou stream:
        # On aggrege des batch contigus qui ont le meme argument et on en fait un super-batch.
        # Ex: fseek(fil)+fread(file)
        #
        # On peut aussi grouper les batchlets par ressource (fichier ou socket).
        # BatchLet ayant la meme ressource en argument.
        # 
        #

    def CreateStatisticsTree(self,maxDepth):
        treeStats = StatisticsNode(maxDepth)

        lenBtch = len( self.m_listBatchLets )

        idxBtch = 0
        maxBtch = lenBtch - maxDepth
        while idxBtch < maxBtch:
            treeStats.AddCompleteBatchRange( self.m_listBatchLets[ idxBtch : idxBtch + maxDepth ] )
            idxBtch += 1

        return treeStats


    def AddBatch(self,btchLet):
        # sys.stdout.write("AddBatch:%s\n"%btchLet.GetSignature())
        numBatches = len(self.m_listBatchLets)

        if numBatches > 0:
            lstBatch = self.m_listBatchLets[-1]

            if lstBatch.SameCall( btchLet ):
                lstBatch.m_occurences += 1
                return

        self.m_listBatchLets.append( btchLet )

    # This rewrites a window at the beginning 
    # of the queue and can write it to a file.
    # It returns the number of factorizations.
    # If it is small or zero, it should be stopped.
    def Factorize(self,treeStats,maxDepth,currThreshold):
        lenBatch = len(self.m_listBatchLets)
        if lenBatch < maxDepth:
            raise Exception("Not enough batches vs maximum depth")

        idxBatch = 0
        lastValidIdx = lenBatch - maxDepth

        sys.stdout.write("\n")
        sys.stdout.write("Factorize currThreshold=%d lenBatch=%d lastValidIdx=%d\n"%(currThreshold,lenBatch,lastValidIdx) )

        numSubsts = 0

        while idxBatch < lastValidIdx:
            batchRange = self.m_listBatchLets[ idxBatch : idxBatch + maxDepth ]

            lenRepetition = treeStats.GetOccurencesMinimal( batchRange, currThreshold )
            sys.stdout.write("lenRepetition=%d batchRange=%s\n"%( lenRepetition, "*".join( [ btch.GetSignature() for btch in batchRange ]) ) )

            if lenRepetition > 1:
                # Only a prefix of this range is repeated enough.
                subBatchRange = batchRange[ : lenRepetition ]
                batchSeq = BatchLetSequence( subBatchRange )

                # Maybe this new batch is similar to the previous one.
                if idxBatch > 0:
                    batchPrevious = self.m_listBatchLets[ idxBatch - 1 ]
                    sys.stdout.write("Factorise compare %s == %s\n"%( batchSeq.GetSignature(), batchPrevious.GetSignature() ) )
                else:
                    batchPrevious = None

                if batchPrevious and ( batchSeq.GetSignature() == batchPrevious.GetSignature() ):
                    sys.stdout.write("Factorize delete idxBatch=%d\n"%idxBatch )
                    batchPrevious.m_occurences += 1

                    del self.m_listBatchLets[ idxBatch : idxBatch + lenRepetition ]
                    lastValidIdx -= lenRepetition

                else:

                    self.m_listBatchLets[ idxBatch : idxBatch + lenRepetition ] = [ batchSeq ]
                    lastValidIdx -= ( lenRepetition - 1 )


                # The number of occurences of this sequence is not decremented because
                # the frequency is still valid and must apply to further substitutions.

                # However, several new sequences are added and might appear elsewhere.
                idxBackward = max(0,idxBatch - lenRepetition)
                idxSubSeq = idxBackward
                
                sys.stdout.write("Factorize idxSubSeq=%d idxBatch=%d lastValidIdx=%d\n"%(idxSubSeq,idxBatch,lastValidIdx) )
                while idxSubSeq <= idxBatch:
                    treeStats.AddCompleteBatchRange( self.m_listBatchLets[ idxSubSeq : idxSubSeq + lenRepetition ] )
                    idxSubSeq += 1

                # Restart from backward position because the list has changed.
                idxBatch = idxBackward

                numSubsts += 1
            else:
                # No change in the list of system calls.
                idxBatch += 1
        return numSubsts

# Detecting short repetitions with same arguments.

#On voit d'abord si le range qui arrive est dans le dictionnaire des repetitions frequentes.
#En commencant par les plus longues.

#Puis on veut detecter de nouvelles repetitions.
#On voit si
#(0,1) == (2,3) == (4,5) == (6,7)
#Si oui, on cree un BatchSequence pour [0,1] avec 4 occurences
#(qui remplacent le reste)
#on le met dans le dictionnaire des repetiions frequentes.

#Sinon on cherche (0,1,2) == (3,4,5) == (6,7,8)
#... puis (0,1,2,3,4) == (5,6,7,8,9)
#... puis (0,1,2,3,4,5,6) == (7,8,9,10,11,12,13)

#Petit tableau longueurs+repetitions, pas la peine d aller trop loin.
#Aucun probleme si deja multiple occurences.
    

# In a second stage, much later, we can detect if repetitions are identical wrt respect to argument changes: Factorization.

    def StatisticsRepetitions(self,maxLenRepeat):

        # https://stackoverflow.com/questions/29481088/how-can-i-tell-if-a-string-repeats-itself-in-python
        def PrincipalPeriod(aStr):
            # ix = ( aStr + aStr ).find( aStr, 1, -1 )
            # return ix
            lenStr = len(aStr)
            lenStr2 = lenStr - 1

            ixStr = 1
            while ixStr <= lenStr2:
                ixSubStr = 0
                while ixSubStr < lenStr:
                    ixTotal = ixStr + ixSubStr
                    if ixTotal >= lenStr:
                        ixTotal -= lenStr

                    if aStr[ ixSubStr ] != aStr[ ixTotal ]:
                        break
                    ixSubStr += 1

                if ixSubStr == lenStr:
                    return ixStr
                ixStr += 1
            return -1



        lenBatch = len(self.m_listBatchLets)

        mapOccurences = {}

        sys.stdout.write("\n")
        sys.stdout.write("StatisticsRepetitions lenBatch=%d\n"%(lenBatch) )

        # First pass to build a map of occurrences.
        idxBatch = 0
        maxIdx = lenBatch - maxLenRepeat
        while idxBatch < maxIdx:
            subLen = 2
            while subLen < maxLenRepeat:
                batchRange = self.m_listBatchLets[ idxBatch : idxBatch + subLen ]
                if PrincipalPeriod( batchRange ) < 0:

                    keyRange = SignatureForRepetitions( batchRange )

                    try:
                        mapOccurences[ keyRange ] += 1
                    except KeyError:
                        mapOccurences[ keyRange ] = 1
                subLen += 1
            idxBatch += 1

        return mapOccurences



    # Think about generators, with a special "buffer" taking a generator returning another one,
    # with an internal buffer, as a window..
    def ClusterizeShortRepeat(self,maxLenRepeat):
        lenBatch = len(self.m_listBatchLets)
        sys.stdout.write("\n")
        sys.stdout.write("ClusterizeShortRepeat lenBatch=%d\n"%(lenBatch) )

        mapOccurences = self.StatisticsRepetitions(maxLenRepeat)
        #sys.stdout.write("ClusterizeShortRepeat mapOccurencess\n" )
        #for keyOccur in mapOccurences:
        #    valOccur = mapOccurences[ keyOccur ]
        #    sys.stdout.write("ClusterizeShortRepeat keyOccur=%s valOccurs=%s\n" % ( keyOccur, valOccur ) )

        sys.stdout.write("\n")
        sys.stdout.write("ClusterizeShortRepeat Starting\n" )

        numSubst = 0
        idxBatch = 0
        maxIdx = lenBatch - maxLenRepeat
        while idxBatch < maxIdx:
            subLen = maxLenRepeat
            while subLen >= 2:
                batchRange = self.m_listBatchLets[ idxBatch : idxBatch + subLen ]
                keyRange = SignatureForRepetitions( batchRange )

                try:
                    numOccur = mapOccurences[ keyRange ]
                except KeyError:
                    numOccur = 0

                # Five occurences for example.
                if numOccur > 5:
                    batchSequence = BatchLetSequence( batchRange )
                    self.m_listBatchLets[ idxBatch : idxBatch + subLen ] = [ batchSequence ]

                    maxIdx -= ( subLen - 1 )
                    numSubst += 1
                    break
                subLen -= 1
            idxBatch += 1
            

        sys.stdout.write("ClusterizeShortRepeat numSubst=%d lenBatch=%d\n"%(numSubst, len(self.m_listBatchLets) ) )

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

                if currentBatch.SignificantArgs() == lastBatch.SignificantArgs():
                    idxBatch += 1
                    continue

            if idxBatch > idxLast + 1:

                # Clusters should not be too big
                batchSeq = BatchLetSequence( self.m_listBatchLets[ idxLast : idxBatch ] )
                self.m_listBatchLets[ idxLast : idxBatch ] = [ batchSeq ]

                lenBatch -= ( idxBatch - idxLast )
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

# The command options generate a specific output file format,
# and therefore parsing it is specific to these options.
def BuildLinuxCommand(extCommand,aPid):
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
# The command and the parsing are specific to Linux.
# It returns a data structure which is generic.

def LogLinuxFileStream(extCommand,aPid):
    aCmd = BuildLinuxCommand( extCommand, aPid )

    # If shell=True, the command must be passed as a single line.
    pipPOpen = subprocess.Popen(aCmd, bufsize=100000, shell=False,
        stdin=sys.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # stdin=subprocess.PIPE, stdout=subprocess.PIPE, stdout=subprocess.PIPE)

    return pipPOpen.stderr


def CreateFlowsFromLinuxSystraceLog(verbose,logStream,maxDepth):
    # This is indexed by the pid.
    mapFlows = { -1 : BatchFlow(maxDepth) }

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

            # Is it defined ?
            # This throws of the core object could not be created
            # if the current line cannot reasonably transformed
            # into a usable call.
            # sys.stdout.write("oneLine before add=%s"%oneLine)
            aCore = aBatch.m_core

            aPid = aCore.m_pid

            try:
                btchTree = mapFlows[ aPid ]
            except KeyError:
                # This is the first system call of this process.
                btchTree = BatchFlow(maxDepth)
                mapFlows[ aPid ] = btchTree

            btchTree.AddBatch( aBatch )

    return mapFlows

def FactorizeMapFlows(mapFlows,verbose,outputFormat,maxDepth,thresholdRepetition):
    for aPid in sorted(list(mapFlows.keys()),reverse=True):
        btchTree = mapFlows[aPid]
        sys.stdout.write("\n================== PID=%d\n"%aPid)
        FactorizeOneFlow(btchTree,verbose,outputFormat,maxDepth,thresholdRepetition)

def FactorizeOneFlow(btchTree,verbose,outputFormat,maxDepth,thresholdRepetition):

    idxLoops = 0

    currThreshold = thresholdRepetition

    btchTree.DumpFlow(sys.stdout,outputFormat)

    btchTree.ClusterizeShortRepeat(10)

    btchTree.DumpFlow(sys.stdout,outputFormat)

    btchTree.ClusterizeBatchesByArguments()

    treeStats = btchTree.CreateStatisticsTree(maxDepth)

    while True:
        btchTree.DumpFlow(sys.stdout,outputFormat)

        if verbose:
            treeStats.DumpStats(sys.stdout)

        idxLoops += 1

        if currThreshold < 5:
            sys.stdout.write("End of factorization (Low repetition threshold)\n")
            break

        sys.stdout.write("Factorization idx=%d Threshold=%d\n"%(idxLoops,currThreshold) )
        numSubsts = btchTree.Factorize(treeStats,maxDepth,currThreshold)

        if verbose:
            treeStats.DumpStats(sys.stdout)

        sys.stdout.write("After factorization %d: Number of substitutions:%d\n"%(idxLoops,numSubsts))

        currThreshold = currThreshold / 2

def CreateEventLog(argsCmd, aPid, inputLogFile ):
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
    else:
        if sys.platform.startswith("win32"):
            logStream = LogWindowsFileStream(argsCmd,aPid)
        elif sys.platform.startswith("linux"):
            logStream = LogLinuxFileStream(argsCmd,aPid)
        else:
            raise Exception("Unknown platform:%s"%sys.platform)


    # Another possibility is to start a process or a thread which will monitor
    # the target process, and will write output information in a stream.

    return logStream

def CreateMapFlowFromStream( verbose, logStream, maxDepth ):
    # Here, we have an event log as a stream, which comes from a file (if testing),
    # the output of strace or anything else.

    # Consider some flexibility in this input format.
    # This is why there are two implementations.

    # This step transforms the input log into a map of BatchFlow,
    # which have the same format whatever the platform is.
    if sys.platform.startswith("win32"):
        mapFlows = CreateFlowsFromWindowsLogger(verbose,logStream,maxDepth)
    elif sys.platform.startswith("linux"):
        mapFlows = CreateFlowsFromLinuxSystraceLog(verbose,logStream,maxDepth)
    else:
        raise Exception("Unknown platform:%s"%sys.platform)

    # TODO: maxDepth should not be passed as a parameter.
    # It is only there because stats are created.
    return mapFlows

if __name__ == '__main__':
    try:
        optsCmd, argsCmd = getopt.getopt(sys.argv[1:], "hvp:f:d:w:r:i:", ["help","verbose","pid","format","depth","window","repetition","input"])
    except getopt.GetoptError as err:
        # print help information and exit:
        Usage(2,err) # will print something like "option -a not recognized"

    verbose = False
    aPid = None
    outputFormat = "TXT"
    maxDepth = 5
    szWindow = 0
    thresholdRepetition = 10
    inputLogFile = None

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
        elif anOpt in ("-h", "--help"):
            Usage(0)
        else:
            assert False, "Unhandled option"

    logStream = CreateEventLog(argsCmd, aPid, inputLogFile )

    mapFlows = CreateMapFlowFromStream( verbose, logStream, maxDepth )

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
