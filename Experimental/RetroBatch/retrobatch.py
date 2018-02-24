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
            if aChr == '{':
                levelBrackets += 1
            elif aChr == '}':
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


# Typical strings displayed by strace:
# [pid  7492] 07:54:54.205073 wait4(18381, [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 18381 <0.000894>
# [pid  7492] 07:54:54.206000 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=18381, si_uid=1000, si_status=1, si_utime=0, si_stime=0 } ---
# [pid  7492] 07:54:54.206031 newfstatat(7</home/rchateau/rdfmon-code/primhill>, "Survol", {st_mode=S_IFDIR|0775, st_size=4096, ...}, AT_SYMLIN K_NOFOLLOW) = 0 <0.000012>
# [pid  7492] 07:54:54.206113 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7fb0d303fad0) = 18382 <0.000065>
# [pid  7492] 07:54:54.206217 wait4(18382, grep: ../../primhill/Survol: Is a directory
# [pid  7492] [{WIFEXITED(s) && WEXITSTATUS(s) == 2}], 0, NULL) = 18382 <0.000904>
# 07:54:54.207500 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=18382, si_uid=1000, si_status=2, si_utime=0, si_stime=0 } ---


class BatchLetCore:
    # [pid  7639] 09:35:56.198010 wait4(7777,  <unfinished ...>
    # 09:35:56.202030 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 1}], 0, NULL) = 7777 <0.004010>
    # [pid  7639] 09:35:56.202303 wait4(7778,  <unfinished ...>
    def __init__(self,oneLine):
        if oneLine[0:4] == "[pid":
            idxAfterPid = oneLine.find("]")
            self.m_pid = int( oneLine[ 4:idxAfterPid ] )
            self.InitAfterPid(oneLine[ idxAfterPid + 2 : ] )
        else:
            # This is the main process.
            self.m_pid = -1
            self.InitAfterPid(oneLine)


    def InitAfterPid(self,oneLine):

        # "[{WIFEXITED(s) && WEXITSTATUS(s) == 2}], 0, NULL) = 18382 <0.000904>"
        if oneLine[0] == '[':
            raise ExceptionIsExit()

        # sys.stderr.write("oneLine=%s\n" % oneLine )

        # This could be done without intermediary string.
        self.m_timeStamp = oneLine[:15]
        theCall = oneLine[16:]

        # "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=19332, si_uid=1000, si_status=1, si_utime=0, si_stime=0} ---"
        if theCall[0:4] == "--- ":
            raise ExceptionIsSignal()

        idxPar = theCall.find("(")

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
        # sys.stderr.write("execTim=%s\n" % execTim )

        # idxLastPar = theCall.rfind(")",0,idxLT)
        idxLastPar = FindNonEnclosedPar(theCall,idxPar+1)

        allArgs = theCall[idxPar+1:idxLastPar]

        self.m_parsedArgs = ParsePar( allArgs )
        # sys.stderr.write("Parsed arguments=%s\n" % str(self.m_parsedArgs) )

        idxEq = theCall.find( "=", idxLastPar )
        self.m_retValue = theCall[ idxEq + 1 : idxLT ].strip()
        # sys.stderr.write("retValue=%s\n"%self.m_retValue)

        sys.stderr.write("Func=%s\n"%self.m_funcNam)

class BatchLetBase:
    def __init__(self,batchCore):
        self.m_core = batchCore

    def SignificantData(self):
        return self.m_core.m_parsedArgs

    def DumpBatch(self,strm):
        
        strm.write("F=%6d %s %s\n"%(self.m_core.m_pid, self.m_core.m_funcNam,str(self.SignificantData() ) ) )


# Must be a new-style class.
class BatchLet_open(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_open,self).__init__(batchBase)

class BatchLet_close(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_close,self).__init__(batchBase)

    def SignificantData(self):
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_read(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_read,self).__init__(batchBase)

    def SignificantData(self):
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_write(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_write,self).__init__(batchBase)

    def SignificantData(self):
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_mmap(BatchLetBase,object):
    def __init__(self,batchBase):
        # Not interested by anonymous map because there is no side effect.
        if batchBase.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return
        super( BatchLet_mmap,self).__init__(batchBase)

    def SignificantData(self):
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_fstat(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_fstat,self).__init__(batchBase)

    def SignificantData(self):
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_fcntl(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_fcntl,self).__init__(batchBase)

    def SignificantData(self):
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_clone(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_clone,self).__init__(batchBase)

    def SignificantData(self):
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_wait4(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_wait4,self).__init__(batchBase)

    def SignificantData(self):
        # The first argument is the PID.
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_newfstatat(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_newfstatat,self).__init__(batchBase)

    def SignificantData(self):
        dirNam = self.m_core.m_parsedArgs[0]
        filNam = self.m_core.m_parsedArgs[1]
        pathName = dirNam +"/" + filNam
        return [ pathName ]

class BatchLet_getdents(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_getdents,self).__init__(batchBase)

    def SignificantData(self):
        return [ self.m_core.m_parsedArgs[0] ]

class BatchLet_openat(BatchLetBase,object):
    def __init__(self,batchBase):
        super( BatchLet_openat,self).__init__(batchBase)

    def SignificantData(self):
        return [ self.m_core.m_parsedArgs[0] ]

batchModels = {
    "open"      : BatchLet_open,
    "close"     : BatchLet_close,
    "read"      : BatchLet_read,
    "write"     : BatchLet_write,
    "mmap"      : BatchLet_mmap,
    "fstat"     : BatchLet_fstat,
    "fcntl"     : BatchLet_fcntl,
    "clone"     : BatchLet_clone,
    "wait4"     : BatchLet_wait4,
    "newfstatat": BatchLet_newfstatat,
    "getdents"  : BatchLet_getdents,
    "openat"    : BatchLet_openat,
    "mprotect"  : None,
    "brk"       : None,
    "lseek"     : None,
    "arch_prctl": None,
}


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

    return btchLetDrv

class BatchTree:
    def __init__(self):
        self.m_treeBatches = []

    def AddBatch(self,btchLet):
        self.m_treeBatches.append( btchLet )

    def DumpTree(self,strm):
        for aBtch in self.m_treeBatches:
            aBtch.DumpBatch(strm)


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

    # strace -tt -T -s 1000 -y -yy ls
    aCmd = ["strace",
        "-f", "-tt", "-T", "-s", "1000", "-y", "-yy",
        "-e", "trace=desc,ipc,process,network,memory",
        ]
    aCmd += extCommand

    sys.stderr.write("aCmd=%s\n" % " ".join(aCmd) )

    # If shell=True, the command must be passed as a single line.
    pipPOpen = subprocess.Popen(aCmd, bufsize=100000, shell=False,
        stdin=sys.stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    btchTree = BatchTree()

    # for oneLine in pipErr:
    while True:
        oneLine = pipPOpen.stderr.readline()
        if oneLine == '':
            break

        # This could be done without intermediary string.
        aBatch = BatchFactory(oneLine)
        if aBatch:

            # Is it defined ?
            try:
                aBatch.m_core
                btchTree.AddBatch( aBatch )
            except AttributeError:
                pass

    btchTree.DumpTree(sys.stdout)

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
