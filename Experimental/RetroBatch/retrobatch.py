import re
import sys
import getopt
import os
import socket
import subprocess
import time

def Usage():
    progNam = sys.argv[0]
    print("Retrobatch: %s <executable>"%progNam)
    print("Monitors and factorizes systems calls.")
    print("  -h,--help                 This message.")
    print("  -v,--verbose              Verbose mode.")
    print("  -p,--pid <pid>            Monitors a running process instead of starting an executable.")
    print("  -f,--format TXT|CSV|JSON  Output format. Default is TXT.")
    print("  -l,--loops <integer>      Number of compression loops. Default is zero.")
    print("  -d,--depth <integer>      Maximum length of detected calls sequence. Default is 5.")
    print("  -w,--window <integer>     Size of sliding window of system calls, used for factorization. Default is 0, i.e. no window")
    print("")

################################################################################

def StartSystrace_Windows(verbose,extCommand,aPid,maxDepth):
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
        # sys.stderr.write("argClean=%s\n"%argClean)

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
    # sys.stderr.write("FindNonEnclosedPar idxStart=%d aStr=%s\n" % (idxStart, aStr ) )
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

        # sys.stderr.write("oneLine1=%s" % oneLine )
        # self.m_debugLine = oneLine

        if oneLine[0:4] == "[pid":
            idxAfterPid = oneLine.find("]")

            pidParsed = int( oneLine[ 4:idxAfterPid ] )

            # The first line with "[pid " is the pid of the [arent process,
            # when it creates its sub-processes.
            #if not rootPid:
            #    rootPid = pidParsed
            #    self.m_pid = -1
            #elif rootPid == pidParsed:
            #    # This sticks to the convention that the root process is set to -1.
            #    # This is because it is detected too late, after the first system calls.
            #    self.m_pid = -1
            #else:
            #    # This is a sub-process.
            #    self.m_pid = pidParsed

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

        # sys.stderr.write("oneLine2=%s" % oneLine )

        # This could be done without intermediary string.
        # "07:54:54.206113"
        try:
            aTimeStamp = time.mktime( time.strptime(oneLine[:15],"%H:%M:%S.%f") )
        except ValueError:
            sys.stderr.write("Invalid time format:%s\n"%oneLine[0:15])
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
        # sys.stderr.write("theCall=%s\n" % theCall )

        idxGT = theCall.rfind(">")
        # sys.stderr.write("idxGT=%d\n" % idxGT )
        idxLT = theCall.rfind("<",0,idxGT)
        # sys.stderr.write("idxLT=%d\n" % idxLT )
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
        # sys.stderr.write("retValue=%s\n"%self.m_retValue)

        # sys.stderr.write("allArgs=%s\n"%allArgs)
        self.m_parsedArgs = ParseSTraceObject( allArgs, True )
        # sys.stderr.write("Parsed arguments=%s\n" % str(self.m_parsedArgs) )

        # sys.stderr.write("Func=%s\n"%self.m_funcNam)


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
        # sys.stderr.write("NAME=%s\n"%self.__class__.__name__)

    def SignificantArgs(self):
        return self.m_core.m_parsedArgs

    # This is used to detect repetitions.
    def GetSignature(self):
        return self.m_core.m_funcNam

    # This is very often used.
    def StreamName(self,idx=0):
        # sys.stderr.write( "StreamName func%s\n"%self.m_core.m_funcNam )
        # sys.stderr.write( "StreamName=%s\n"%self.m_core.m_parsedArgs[idx] )
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
            # sys.stderr.write("XX: %s\n" % filOnly )
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


def GetBatchesSignature(arrBatches):
    arrSigs = [ aBatch.GetSignature() for aBatch in arrBatches ]
    sigBatch = ",".join( arrSigs )
    return sigBatch

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
        batchCore = BatchLetCore()

        # All batchlets should have the same pid.
        batchCore.m_pid = arrBatch[0].m_core.m_pid

        batchCore.m_timeStart = arrBatch[0].m_core.m_timeStart
        batchCore.m_timeEnd = arrBatch[-1].m_core.m_timeEnd
        batchCore.m_execTim = batchCore.m_timeEnd - batchCore.m_timeStart

        # TODO ????????????
        self.m_parsedArgs = None

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
# Faire plusieurs passes dans la liste pour compresser a plusieurs niveaux.
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
                currNode.m_mapStats[ currSignature ] = subNode

            subNode.m_occurences += 1
            currNode = subNode
            idx += 1


    def GetOccurences( self, batchRange ):
        lenBatch = len(batchRange)

        idx = 0
        currNode = self
        while idx < lenBatch:
            currSignature = batchRange[idx].GetSignature()
            try:
                subNode = currNode.m_mapStats[ currSignature ]
            except KeyError:
                raise Exception("Tree should be deeper")
            idx += 1

        return subNode.m_occurences


    def DumpStats(self, strm, newMargin = "" ):
        strm.write( "%s%-20s {%4d}\n" % ( newMargin, self.m_signature, self.m_occurences ) )
        # newMargin += "    "
        for aSig in sorted( list( self.m_mapStats.keys() ) ):
            aSub = self.m_mapStats[ aSig ]
            aSub.DumpStats( strm, newMargin + "....")
            
            
            
# This is an execution flow, associated to a process. And a thread ?
class BatchFlow:
    def __init__(self,maxDepth):
        self.m_maxDepth = maxDepth
        self.m_treeStats = StatisticsNode()

        self.m_listBatchLets = []

        # This contain combinations of system calls, of length 2, 3 etc...
        # Problem: If we increase the depth, the calculation step becomes quadratic.
        #
        # Notes about how to compress consecutive system calls:
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
        self.m_mapPatterns = {}

    def GetMaxDepth(self):
        # Maximum length of repetition.
        actualDepth = min(self.m_maxDepth,len(self.m_listBatchLets) )
        return actualDepth


    # Updates probabilities with the latest insertion in mind.
    def UpdateStatistics(self):

        actualDepth = self.GetMaxDepth()

        # Repetition of the same call is already taken into account.
        idx = 2
        while idx <= actualDepth:
            signatureBatches = GetBatchesSignature( self.m_listBatchLets[ -idx : ] )

            try:
                sigsByDepth = self.m_mapPatterns[ idx ]
                try:
                    sigsByDepth[ signatureBatches ] += 1
                except KeyError:
                    sigsByDepth[ signatureBatches ] = 1
            except KeyError:
                self.m_mapPatterns[ idx ] = { signatureBatches : 1 }
            idx += 1

    def UpdateStatsTree(self):
        actualDepth = self.GetMaxDepth()

        # TODO: Would be faster to pass the array and the indices instead of creating a subarray.
        self.m_treeStats.AddCompleteBatchRange( self.m_listBatchLets[ -actualDepth : ] )

    def EffectiveAppendBatch(self,btchLet):
        self.m_listBatchLets.append( btchLet )
        self.UpdateStatistics()
        self.UpdateStatsTree()

    def AddBatch(self,btchLet):
        # sys.stderr.write("AddBatch:%s\n"%btchLet.GetSignature())
        numBatches = len(self.m_listBatchLets)

        if numBatches > 0:
            lstBatch = self.m_listBatchLets[-1]

            if lstBatch.SameCall( btchLet ):
                lstBatch.m_occurences += 1
            else:
                self.EffectiveAppendBatch( btchLet )
        else:
            self.EffectiveAppendBatch( btchLet )

    # Problem: This is to add to the statistics, a new type of node.
    # BUT IN FACT WE SHOULD RESCAN EVERYTHING FIRST !!
    def UpdateStatistics(self):
        return

    # This rewrites a window at the beginning 
    # of the queue and can write it to a file.
    # It returns the number of factorizations.
    # If it is small or zero, it should be stopped.
    def Factorize(self):
        lenBatch = len(self.m_listBatchLets)
        idxBatch = 0
        actualDepth = self.GetMaxDepth()
        lastValidIdx = lenBatch - actualDepth

        numSubsts = 0

        while idxBatch < lastValidIdx:
            batchRange = self.m_listBatchLets[ idxBatch : idxBatch + actualDepth ]

            numOcc = self.m_treeStats.GetOccurences( batchRange )

            # 3 occurences of the same pattern is arbitrary.
            if numOcc > 3:
                batchSeq = BatchLetSequence( batchRange )
                self.m_listBatchLets[ idxBatch : idxBatch + actualDepth ] = [ batchSeq ]

                # The number of occurences is not decremented because
                # the frequency is still valid and must apply to further substitutions.

                # However, several new sequences are added and might appear elsewhere.
                idxBackward = idxBatch - actualDepth
                idxSubSeq = idxBackward
                while idxSubSeq <= idxBatch:
                    self.m_treeStats.AddCompleteBatchRange( self.m_listBatchLets[ idxSubSeq : idxSubSeq + actualDepth ] )

                lastValidIdx -= ( actualDepth - 1 )

                # Restart from backward position because the list has changed.
                idxBatch = idxBackward

                numSubsts += 1
            else:
                idxBatch += 1
        return numSubsts

    def DumpFlow(self,strm,outputFormat):

        batchDump = BatchDumperFactory(strm, outputFormat)

        batchDump.Header()

        for aBtch in self.m_listBatchLets:
            batchDump.DumpBatch(aBtch)

        batchDump.Footer()

    def CleanupStatistics(self):
        for keyIdx in self.m_mapPatterns:
            sigsToDel = []
            for aSignature in self.m_mapPatterns[ keyIdx ]:
                numOccurs = self.m_mapPatterns[ keyIdx ][ aSignature ]
                if numOccurs <= 3:
                    sigsToDel.append( aSignature )

            for aSignature in sigsToDel:
                del self.m_mapPatterns[ keyIdx ][ aSignature ]


    def DumpStatistics(self,strm):
        strm.write("DUMPING STATISTICS MAP (DEPRECATED)\n")
        for keyIdx in self.m_mapPatterns:
            strm.write("Repetition length:%d\n" % keyIdx )
            for aSignature in sorted( list( self.m_mapPatterns[ keyIdx ].keys() ) ):
                numOccurs = self.m_mapPatterns[ keyIdx ][ aSignature ]
                strm.write("    %-20s : %d\n" % ( aSignature, numOccurs ) )

        strm.write("DUMPING STATISTICS TREE\n")
        self.m_treeStats.DumpStats(strm)

# The command is tightly coupled to the way its result is parsed.
def BuildLinuxCommand(extCommand,aPid):
    # -f  Trace  child  processes as a result of the fork, vfork and clone.
    aCmd = ["strace",
        "-q", "-qq", "-f", "-tt", "-T", "-s", "20", "-y", "-yy",
        "-e", "trace=desc,ipc,process,network,memory",
        ]

    if extCommand:
        aCmd += extCommand
    else:
        aCmd += [ "-p", aPid ]

    sys.stderr.write("aCmd=%s\n" % ( " ".join(aCmd) ) )

    return aCmd


#
# 22:41:05.094710 rt_sigaction(SIGRTMIN, {0x7f18d70feb20, [], SA_RESTORER|SA_SIGINFO, 0x7f18d7109430}, NULL, 8) = 0 <0.000008>
# 22:41:05.094841 rt_sigaction(SIGRT_1, {0x7f18d70febb0, [], SA_RESTORER|SA_RESTART|SA_SIGINFO, 0x7f18d7109430}, NULL, 8) = 0 <0.000018>
# 22:41:05.094965 rt_sigprocmask(SIG_UNBLOCK, [RTMIN RT_1], NULL, 8) = 0 <0.000007>
# 22:41:05.095113 getrlimit(RLIMIT_STACK, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0 <0.000008>
# 22:41:05.095350 statfs("/sys/fs/selinux", 0x7ffd5a97f9e0) = -1 ENOENT (No such file or directory) <0.000019>
#
# lags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9c27230ad0) = 7256 <0.000075> ['lags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD', 'child_tidptr=0x7f9c27230ad0']

# The command and the parsing are specific to Linux.
# It returns a data strcture which is generic.
def StartSystrace_Linux(verbose,extCommand,aPid,maxDepth):
    aCmd = BuildLinuxCommand( extCommand, aPid )

    # If shell=True, the command must be passed as a single line.
    pipPOpen = subprocess.Popen(aCmd, bufsize=100000, shell=False,
        stdin=sys.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # This is indexed by the pid.
    mapFlows = { -1 : BatchFlow(maxDepth) }

    lineSignal = ""

    # for oneLine in pipErr:
    while True:
        oneLine = ""

        # If this line is not properly terminated, then concatenates the next line.
        # FIXME: Problem if several processes.
        while True:
            tmpLine = pipPOpen.stderr.readline()
            # sys.stderr.write("tmpLine after read=%s"%tmpLine)
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

        # sys.stderr.write("oneLine after read=%s"%oneLine)


#        matchAttached = re.match("strace: Process (\d+) attached", oneLine)
#        if matchAttached:
#            # This should be before the first system call of this process, but not always.
#            pidAttached = int(matchAttached.group(1))
#            continue

        # Big difficulty if two different processes in the same system call
        # are interrupted by a signal ?? How can we match the two pieces ?
        # Luckily: "If a system call is being executed and meanwhile another one is being called
        # from a different thread/process then strace will try to preserve the
        # order of those events and mark the ongoing call as being unfinished.
        # When the call returns it will be marked as resumed.

        # strace: Process 24848 attached
        # [pid 24711] 23:41:39.833567 wait4(24848,  <unfinished ...>
        # [pid 24848] 23:41:39.833682 fchdir(3</home/rchateau/rdfmon-code/Experimental/RetroBatch>) = 0 <0.000115>
        # [pid 24848] 23:41:39.837619 +++ exited with 1 +++
        # 23:41:39.837639 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 24848 <0.004063>
#        strUnfinished = "<unfinished ...>\n"
#        if oneLine.endswith( strUnfinished ):
#            if lineSignal != "":
#                sys.stderr.write("Two simultaneous signals\n")
#                sys.stderr.write("  lineSignal=%s.\n"%lineSignal)
#                sys.stderr.write("  oneLine=%s.\n"%oneLine)
#                # raise Exception("Cannot handle two simultaneous signals")
#                sys.stderr.write("Cannot handle two simultaneous signals\n")
#                lineSignal = ""
#                # TODO: FIXME.
#                continue
#            lineSignal = oneLine[ : -len(strUnfinished) ]
#            sys.stderr.write("Set lineSignal to:%s.\n"%lineSignal)
#            sys.stderr.write("  oneLine=%s.\n"%oneLine)
#            continue

        # TODO: When a function is resumed, do not do anything yet.

        # sys.stderr.write("Trying resumed:%s\n"%oneLine)
        # 23:41:39.837639 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 24848 <0.004063>
        # matchResume = re.match( ".... ([^ ]*) resumed. (.*)", oneLine )
        matchResume = re.match( ".*<\.\.\. ([^ ]*) resumed> (.*)", oneLine )
        if matchResume:
            # TODO: Should check if this is the correct function name.
            funcNameResumed = matchResume.group(1)
            sys.stderr.write("RESUMING FUNCTION resumed C:%s\n"%funcNameResumed)
            lineRest = matchResume.group(2)
            # oneLine = lineSignal + lineRest
            # lineSignal = ""
            continue


        # This could be done without intermediary string.
        aBatch = BatchFactory(oneLine)
        if aBatch:

            # Is it defined ?
            # This throws of the core object could not be created
            # if the current line cannot reasonably transformed
            # into a usable call.
            # sys.stderr.write("oneLine before add=%s"%oneLine)
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

def StartSystrace(verbose,extCommand,aPid,outputFormat,numLoops,maxDepth,szWindow):

    if szWindow != 0:
        raise Exception("Sliding window not implemented yet")

    if sys.platform.startswith("win32"):
        mapFlows = StartSystrace_Windows(verbose,extCommand,aPid,maxDepth)
    elif sys.platform.startswith("linux"):
        mapFlows = StartSystrace_Linux(verbose,extCommand,aPid,maxDepth)
    else:
        raise Exception("Unknown platform:%s"%sys.platform)


    for aPid in sorted(list(mapFlows.keys()),reverse=True):
        btchTree = mapFlows[aPid]
        sys.stdout.write("\n================== PID=%d\n"%aPid)

        idxLoops = 0

        while True:
            btchTree.DumpFlow(sys.stdout,outputFormat)

            if verbose:
                btchTree.DumpStatistics(sys.stdout)

            if idxLoops >= numLoops:
                break
            idxLoops += 1

            numSubsts = btchTree.Factorize()

            if verbose:
                btchTree.DumpStatistics(sys.stdout)

            sys.stdout.write("Number of substitutions:%d\n"%numSubsts)
            if numSubsts == 0:
                sys.stdout.write("End of compression\n")
                break

            btchTree.CleanupStatistics()


if __name__ == '__main__':
    try:
        optsCmd, argsCmd = getopt.getopt(sys.argv[1:], "hvp:f:l:d:w:", ["help","verbose","pid","format","loops","depth","window"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        Usage()
        sys.exit(2)

    verbose = False
    aPid = None
    outputFormat = "TXT"
    numLoops = 0
    maxDepth = 5
    szWindow = 0

    for anOpt, aVal in optsCmd:
        if anOpt in ("-v", "--verbose"):
            verbose = True
        elif anOpt in ("-p", "--pid"):
            aPid = aVal
        elif anOpt in ("-f", "--format"):
            outputFormat = aVal.upper()
        elif anOpt in ("-l", "--loops"):
            numLoops = int(aVal)
        elif anOpt in ("-d", "--depth"):
            maxDepth = int(aVal)
        elif anOpt in ("-w", "--window"):
            szWindow = int(aVal)
        elif anOpt in ("-h", "--help"):
            Usage()
            sys.exit()
        else:
            assert False, "Unhandled option"

    # A command or a pid, not both.
    if not ( ( argsCmd  == [] ) ^ ( aPid is None ) ):
        print("Must provide command or process id")
        sys.exit()
    StartSystrace(verbose,argsCmd,aPid,outputFormat,numLoops,maxDepth,szWindow)

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

