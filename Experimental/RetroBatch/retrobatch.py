import re
import sys
import getopt
import os
import socket
import subprocess

def Usage():
    progNam = sys.argv[0]
    print("Retrobatch: %s <executable>"%progNam)
    print("    -v,--verbose              Verbose mode")
    print("")

def StartSystrace_Windows(verbose,extCommand):
    return

# strace -h
# Usage: strace.exe [OPTIONS] <command-line>
# Usage: strace.exe [OPTIONS] -p <pid>
#
# Trace system calls and signals
#
#   -b, --buffer-size=SIZE       set size of output file buffer
#   -d, --no-delta               don't display the delta-t microsecond timestamp
#   -f, --trace-children         trace child processes (toggle - default true)
#   -h, --help                   output usage information and exit
#   -m, --mask=MASK              set message filter mask
#   -n, --crack-error-numbers    output descriptive text instead of error
#                             numbers for Windows errors
#   -o, --output=FILENAME        set output file to FILENAME
#   -p, --pid=n                  attach to executing program with cygwin pid n
#   -q, --quiet                  suppress messages about attaching, detaching, etc.
#   -S, --flush-period=PERIOD    flush buffered strace output every PERIOD secs
#   -t, --timestamp              use an absolute hh:mm:ss timestamp insted of
#                             the default microsecond timestamp.  Implies -d
#   -T, --toggle                 toggle tracing in a process already being
#                             traced. Requires -p <pid>
#   -u, --usecs                  toggle printing of microseconds timestamp
#   -V, --version                output version information and exit
#   -w, --new-window             spawn program under test in a new window
#
#
# With a Cygwin executable
#   820 1235721 [main] dir 8916 fhandler_base::close_with_arch: line 1142:  /dev/cons0<0x612E6C88> usecount + -1 = 1
#   699 1236420 [main] dir 8916 fhandler_base::close_with_arch: not closing archetype
#   765 1237185 [main] dir 8916 init_cygheap::close_ctty: closing cygheap->ctty 0x612E6C88
#   820 1238005 [main] dir 8916 fhandler_base::close_with_arch: closing passed in archetype 0x0, usecount 0
#   875 1238880 [main] dir 8916 fhandler_console::free_console: freed console, res 1
#
# With notepad
# C:\Users\rchateau>C:\Users\rchateau\Documents\MobaXterm\slash\bin\strace notepad.exe
# --- Process 7432, exception 000006ba at 7686C54F
# --- Process 7432, exception 000006ba at 7686C54F
def StartSystrace_Cygwin(verbose,extCommand):
    pathCygwin = "C:\\Users\\rchateau\\Documents\\MobaXterm\\slash\\bin\\strace"

    return

# strace creates data structures similar to Python or Json.
# fstat(3</usr/lib64/gconv/gconv-modules.cache>, {st_mode=S_IFREG|0644, st_size=26254, ...})
# execve("/usr/bin/grep", ["grep", "toto", "../TestMySql.py"], [/* 34 vars */]) = 0 <0.000175>

# The input is a string containing the arguments printed by strace.
# The output is an array of strings wtith these arguments correctly split.
def ParsePar(aStr):
    idx = 0
    theArr = []
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
            if aChr in ['{','[']:
                levelBrackets += 1
            elif aChr in ['}',']']:
                levelBrackets -= 1
            elif aChr == ',':
                if levelBrackets == 0:
                    theArr.append( currStr.strip() )
                    currStr = ""
                    continue

        currStr += aChr
        continue

    if currStr:
        theArr.append( currStr.strip() )

    return theArr

def FindNonEnclosedPar(aStr,idxStart):
    lenStr = len(aStr)
    inQuotes = False
    isEscaped = False
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
            if aChr == ')':
                return idxStart - 1

    return -1

class ExceptionIsExit(Exception):
    pass

class ExceptionIsSignal(Exception):
    pass

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

# Thi sis set to the parent pid as soon as it can be detected.
rootPid = None

class BatchLetCore:
    # [pid  7639] 09:35:56.198010 wait4(7777,  <unfinished ...>
    # 09:35:56.202030 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 7777 <0.004010>
    # [pid  7639] 09:35:56.202303 wait4(7778,  <unfinished ...>
    def __init__(self,oneLine):
        global rootPid

        # sys.stderr.write("oneLine1=%s" % oneLine )
        # self.m_debugLine = oneLine

        if oneLine[0:4] == "[pid":
            idxAfterPid = oneLine.find("]")

            pidParsed = int( oneLine[ 4:idxAfterPid ] )

            # The first line with "[pid " is the pid of the [arent process,
            # when it creates its sub-processes.
            if not rootPid:
                rootPid = pidParsed
                self.m_pid = -1
            elif rootPid == pidParsed:
                # This sticks to the convention that the root process is set to -1.
                # This is because it is detected too late, after the first system calls.
                self.m_pid = -1
            else:
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
        self.m_timeStamp = oneLine[:15]
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
        # sys.stderr.write("Line=%s" % theCall )

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


        # if self.m_funcNam == "wait4":
        #     sys.stderr.write("wait4 execTim:%s\n"%self.m_execTim)

        # idxLastPar = theCall.rfind(")",0,idxLT)
        idxLastPar = FindNonEnclosedPar(theCall,idxPar+1)

        allArgs = theCall[idxPar+1:idxLastPar]

        idxEq = theCall.find( "=", idxLastPar )
        self.m_retValue = theCall[ idxEq + 1 : idxLT ].strip()
        # sys.stderr.write("retValue=%s\n"%self.m_retValue)

        # sys.stderr.write("allArgs=%s\n"%allArgs)
        self.m_parsedArgs = ParsePar( allArgs )
        # sys.stderr.write("Parsed arguments=%s\n" % str(self.m_parsedArgs) )


        # sys.stderr.write("Func=%s\n"%self.m_funcNam)

# Each class is indexed with the name of the corresponding system call name.
# If the class is None, it means that this function is explicitly neglected.
# If it is not defined after metaclass registration,
# then it is processed by BatchLetBase.
batchModels = {
    # "open"      : BatchLet_open,
    # "close"     : BatchLet_close,
    # "read"      : BatchLet_read,
    # "write"     : BatchLet_write,
    # "mmap"      : BatchLet_mmap,
    # "ioctl"     : BatchLet_ioctl,
    # "fstat"     : BatchLet_fstat,
    # "fchdir"    : BatchLet_fchdir,
    # "fcntl"     : BatchLet_fcntl,
    # "clone"     : BatchLet_clone,
    # "wait4"     : BatchLet_wait4,
    # "newfstatat": BatchLet_newfstatat,
    # "getdents"  : BatchLet_getdents,
    # "openat"    : BatchLet_openat,
    "mprotect"  : None,
    "brk"       : None,
    "lseek"     : None,
    "arch_prctl": None,
}



class BatchMeta(type):
    #def __new__(meta, name, bases, dct):
    #    print '-----------------------------------'
    #    print "Allocating memory for class", name
    #    print meta
    #    print bases
    #    print dct
    #    return super(BatchMeta, meta).__new__(meta, name, bases, dct)

    def __init__(cls, name, bases, dct):
        global batchModels

        # print '-----------------------------------'
        if name.startswith("BatchLet_"):
            shortClassName = name[9:]
            # print "Initializing class", shortClassName
            batchModels[ shortClassName ] = cls
        # print cls
        # print bases
        # print dct
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
        return [ STraceStreamToFile( self.m_core.m_parsedArgs[idx] ) ]

    def DumpBatch(self,strm):
        # strm.write("X=%s"%self.m_core.m_debugLine)
        strm.write("F=%6d {%4d} '%-20s' %s ==>> %s\n"
            %(self.m_core.m_pid, self.m_occurences, self.m_core.m_funcNam,str(self.SignificantArgs() ), self.m_core.m_retValue ) )

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

# Must be a new-style class.
class BatchLet_open(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_open,self).__init__(batchBase)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_openat(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_openat,self).__init__(batchBase)

    # TODO: A relative pathname is interpreted relative to the directory
    # referred to by the file descriptor passed as first parameter.
    def SignificantArgs(self):
        return self.StreamName(1)

class BatchLet_close(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_close,self).__init__(batchBase)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_read(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_read,self).__init__(batchBase)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_write(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_write,self).__init__(batchBase)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_mmap(BatchLetBase,object):
    def __init__(self,batchBase):
        # Not interested by anonymous map because there is no side effect.
        if batchBase.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return
        super( BatchLet_mmap,self).__init__(batchBase)

    def SignificantArgs(self):
        return self.StreamName(4)

class BatchLet_ioctl(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_ioctl,self).__init__(batchBase)

    def SignificantArgs(self):
        return [ STraceStreamToFile( self.m_core.m_parsedArgs[0] ) ] + self.m_core.m_parsedArgs[1:0]

class BatchLet_fstat(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_fstat,self).__init__(batchBase)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fchdir(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_fchdir,self).__init__(batchBase)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_fcntl(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_fcntl,self).__init__(batchBase)

    def SignificantArgs(self):
        return self.StreamName()

class BatchLet_clone(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_clone,self).__init__(batchBase)

    def SignificantArgs(self):
        return [ self.m_core.m_parsedArgs[0] ]

    # Process creations are not aggregated, not to lose the new pid.
    def SameCall(self,anotherBatch):
        return False

# execve("/usr/bin/grep", ["grep", "toto", "../TestMySql.py"], [/* 34 vars */]) = 0 <0.000175>
class BatchLet_execve(BatchLetBase,object):
    def __init__(self,batchBase):

        # ['/usr/lib64/qt-3.3/bin/grep', '[grep, toto, ..]'] ==>> -1 ENOENT (No such file or directory)
        # If the executable could not be started, no point creating a batch node.
        if batchBase.m_retValue.find("ENOENT") >= 0 :
            return
        super( BatchLet_execve,self).__init__(batchBase)

    def SignificantArgs(self):
        return self.m_core.m_parsedArgs[0:2]

    # Process creations are not aggregated.
    def SameCall(self,anotherBatch):
        return False

class BatchLet_wait4(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_wait4,self).__init__(batchBase)

    def SignificantArgs(self):
        # The first argument is the PID.
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_newfstatat(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_newfstatat,self).__init__(batchBase)

    def SignificantArgs(self):
        dirNam = self.m_core.m_parsedArgs[0]
        filNam = self.m_core.m_parsedArgs[1]
        pathName = dirNam +"/" + filNam
        return [ pathName ]

class BatchLet_getdents(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_getdents,self).__init__(batchBase)

    def SignificantArgs(self):
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_openat(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_openat,self).__init__(batchBase)

    def SignificantArgs(self):
        return [ self.m_core.m_parsedArgs[0] ]

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


maxDepth = 4


def GetBatchesSignature(arrBatches):
    arrSigs = [ aBatch.GetSignature() for aBatch in arrBatches ]
    sigBatch = ",".join( arrSigs )
    return sigBatch

class BatchTree:
# One per process, or per thread ?
    def __init__(self):
        self.m_treeBatches = []

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
        self.m_mapPatterns = {}


    # Updates probabilities with the latest insertion in mind.
    def UpdateStatistics(self):
        actualDepth = min(maxDepth,len(self.m_treeBatches) )

        # Repetition of the same call is already taken into account.
        idx = 2
        while idx <= actualDepth:
            signatureBatches = GetBatchesSignature( self.m_treeBatches[ -idx : ] )

            try:
                sigsByDepth = self.m_mapPatterns[ idx ]
                try:
                    sigsByDepth[ signatureBatches ] += 1
                except KeyError:
                    sigsByDepth[ signatureBatches ] = 1
            except KeyError:
                self.m_mapPatterns[ idx ] = { signatureBatches : 1 }
            idx += 1


    def EffectiveAppendBatch(self,btchLet):
        self.m_treeBatches.append( btchLet )
        self.UpdateStatistics()

    def AddBatch(self,btchLet):
        # sys.stderr.write("AddBatch:%s\n"%btchLet.GetSignature())
        numBatches = len(self.m_treeBatches)

        if numBatches > 0:
            lstBatch = self.m_treeBatches[-1]

            if lstBatch.SameCall( btchLet ):
                lstBatch.m_occurences += 1
            else:
                self.EffectiveAppendBatch( btchLet )
        else:
            self.EffectiveAppendBatch( btchLet )

    # This rewrites a window at the beginning 
    # of the queue and can write it to a file.
    def RewriteWindow(self):
        pass

    def DumpTree(self,strm):
        for aBtch in self.m_treeBatches:
            aBtch.DumpBatch(strm)

    def CleanupStatistics(self):
        for keyIdx in self.m_mapPatterns:
            sigsToDel = []
            for aSignature in self.m_mapPatterns[ keyIdx ]:
                numOccurs = self.m_mapPatterns[ keyIdx ][ aSignature ]
                if numOccurs <= 2:
                    sigsToDel.append( aSignature )

            for aSignature in sigsToDel:
                del self.m_mapPatterns[ keyIdx ][ aSignature ]


    def DumpStatistics(self,strm):
        strm.write("DUMPING STATISTICS\n")
        for keyIdx in self.m_mapPatterns:
            strm.write("Repetition length:%d\n" % keyIdx )
            for aSignature in sorted( list( self.m_mapPatterns[ keyIdx ].keys() ) ):
                numOccurs = self.m_mapPatterns[ keyIdx ][ aSignature ]
                strm.write("    %-20s : %d\n" % ( aSignature, numOccurs ) )


#
# 22:41:05.094710 rt_sigaction(SIGRTMIN, {0x7f18d70feb20, [], SA_RESTORER|SA_SIGINFO, 0x7f18d7109430}, NULL, 8) = 0 <0.000008>
# 22:41:05.094841 rt_sigaction(SIGRT_1, {0x7f18d70febb0, [], SA_RESTORER|SA_RESTART|SA_SIGINFO, 0x7f18d7109430}, NULL, 8) = 0 <0.000018>
# 22:41:05.094965 rt_sigprocmask(SIG_UNBLOCK, [RTMIN RT_1], NULL, 8) = 0 <0.000007>
# 22:41:05.095113 getrlimit(RLIMIT_STACK, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0 <0.000008>
# 22:41:05.095350 statfs("/sys/fs/selinux", 0x7ffd5a97f9e0) = -1 ENOENT (No such file or directory) <0.000019>
#
# lags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f9c27230ad0) = 7256 <0.000075> ['lags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD', 'child_tidptr=0x7f9c27230ad0']

#
def StartSystrace_Linux(verbose,extCommand):

    # -f  Trace  child  processes as a result of the fork, vfork and clone.

    aCmd = ["strace",
        "-q", "-qq", "-f", "-tt", "-T", "-s", "100", "-y", "-yy",
        "-e", "trace=desc,ipc,process,network,memory",
        ]
    aCmd += extCommand

    sys.stderr.write("pid=%s aCmd=%s\n" % (os.getpid(), " ".join(aCmd) ) )

    # If shell=True, the command must be passed as a single line.
    pipPOpen = subprocess.Popen(aCmd, bufsize=100000, shell=False,
        stdin=sys.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # This is indexed by the pid.
    mapTrees = { -1 : BatchTree() }

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
                btchTree = mapTrees[ aPid ]
            except KeyError:
                # This is the first system call of this process.
                btchTree = BatchTree()
                mapTrees[ aPid ] = btchTree

            btchTree.AddBatch( aBatch )

    for aPid in sorted(list(mapTrees.keys()),reverse=True):
        btchTree = mapTrees[aPid]
        sys.stdout.write("\n================== PID=%d\n"%aPid)
        btchTree.DumpTree(sys.stdout)
        btchTree.CleanupStatistics()
        btchTree.DumpStatistics(sys.stdout)

    return

def StartSystrace(verbose,extCommand):
    if sys.platform.startswith("win32"):
        StartSystrace_Windows(verbose,extCommand)
    elif sys.platform.startswith("linux"):
        StartSystrace_Linux(verbose,extCommand)
    else:
        StartSystrace_Cygwin(verbose,extCommand)

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hv", ["help","verbose"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        Usage()
        sys.exit(2)

    verbose = False

    for anOpt, aVal in opts:
        if anOpt in ("-v", "--verbose"):
            verbose = True
        elif anOpt in ("-h", "--help"):
            Usage()
            sys.exit()
        else:
            assert False, "Unhandled option"

    if not args:
        print("Must provide command")
        sys.exit()
    StartSystrace(verbose,args)
