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
import cim_objects_definitions

################################################################################

# Parsing of the arguments of the systems calls printed by strace and ltrace.
# This starts immediately after an open parenthesis or bracket.
# It returns an index on the closing parenthesis, or equal to the string length.
# This is called for each line and is on the critical path.
def ParseCallArguments(strArgs,ixStart = 0):
    lenStr = len(strArgs)

    theResult = []
    finished = False
    inQuotes = False
    levelParent = 0
    isEscaped = False
    while ixStart < lenStr and strArgs[ixStart] == ' ': ixStart += 1
    ixCurr = ixStart

    ixUnfinished = strArgs.find("<unfinished ...>",ixStart)
    if ixUnfinished >= 0:
        lenStr = ixUnfinished

    hasOctal = False
    while (ixCurr < lenStr) and not finished:

        aChr = strArgs[ixCurr]
        ixCurr += 1

        if isEscaped:
            isEscaped = False
            continue

        if aChr == '\\':
            # TODO: This might be an octal number as in ltrace.
            #if (ixCurr == lenStr) or (strArgs[ixCurr] != '0'):
            isEscaped = True
            continue

        if aChr == '"':
            # TODO: ltrace does not escape double-quotes:
            #  "\001$\001$\001\026\001"\0015\001\n\001\r\001\r\001\f\001(\020",
            # "read@SYS(3, "" + str(row) + "\\n")\n\n", 4096)"
            inQuotes = not inQuotes
            continue

        if inQuotes:
            continue

        # This assumes that [] and {} are paired by strace so no need to check parity.
        if aChr in ['[','{']:
            if ixCurr == ixStart +1:
                objToAdd, ixStart = ParseCallArguments( strArgs, ixCurr)
                theResult.append( objToAdd )
                while ixStart < lenStr and strArgs[ixStart] in [' ',',']: ixStart += 1
                ixCurr = ixStart
                continue
            levelParent += 1
        elif aChr == '(':
            levelParent += 1
        elif aChr in [')',']','}']:
            levelParent -= 1
            if levelParent == -1:
                finished = True
                if ixCurr == ixStart +1:
                    continue
            else:
                continue

        if (aChr == ',' and levelParent == 0) or finished :
            while ixStart < lenStr and strArgs[ixStart] in [' ','"']: ixStart += 1
            ixEnd = ixCurr-2
            while strArgs[ixEnd] == '"' and ixStart <= ixEnd: ixEnd -= 1

            argClean = strArgs[ixStart:ixEnd + 1]
            # Special case due to truncated strings.
            # TODO: Should we truncate ? If read()/write'), we know what the length should be."
            if argClean.endswith('"...'):
                argClean = argClean[:-4] + "..."

            theResult.append( argClean )

            while ixCurr < lenStr and strArgs[ixCurr] == ' ': ixCurr += 1
            ixStart = ixCurr

    if (ixStart < lenStr) and not finished:
        while ixStart < lenStr and strArgs[ixStart] in [' ','"']: ixStart += 1
        ixEnd = lenStr-1
        while strArgs[ixEnd] in [',',')',']','}',' ','"'] and ixStart <= ixEnd: ixEnd -= 1

        argClean = strArgs[ixStart:ixEnd + 1]
        # Special case due to truncated strings.
        # TODO: Should we truncate ? If read()/write'), we know what the length should be."
        if argClean.endswith('"...'):
            argClean = argClean[:-4] + "..."
        theResult.append( argClean )

    return theResult,ixCurr

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

# Read from a real process or from the log file name when replaying a session.
G_topProcessId = None

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
        self.m_unfinishedBatch = None # If this is a merged batch.
        self.m_resumedBatch = None # If this is a matched batch.

    # tracer = "strace|ltrace"
    def ParseLine(self, oneLine, tracer):
        # sys.stdout.write("%s oneLine1=%s" % (id(self),oneLine ) )
        self.m_tracer = tracer

        if oneLine.startswith("[pid"):
            idxAfterPid = oneLine.find("]")

            pidParsed = int(oneLine[4:idxAfterPid])

            # This is a sub-process.
            self.m_pid = pidParsed

            self.InitAfterPid(oneLine, idxAfterPid + 2)
        else:
            # This is the main process, but at this stage we do not have its pid.
            self.m_pid = G_topProcessId
            self.InitAfterPid(oneLine, 0)

        # If this process is just created, it receives the creation time-stamp.
        self.m_objectProcess = cim_objects_definitions.ToObjectPath_CIM_Process(self.m_pid)

        # If the creation date is uknown, it is at least equal to the current call time.
        if not self.m_objectProcess.CreationDate:
            self.m_objectProcess.CreationDate = self.m_timeStart

    def SetFunction(self, funcFull):
        # With ltrace, systems calls are suffix with the string "@SYS".
        if self.m_tracer == "strace":
            # strace can only intercept system calls.
            assert not funcFull.endswith("@SYS")
            assert not funcFull.startswith("SYS_")
            self.m_funcNam = funcFull + "@SYS"
        elif self.m_tracer == "ltrace":

            # This might be in a shared library, so this extracts the function name:
            # libaugeas.so.0->getenv
            # libaugeas.so.0->getenv
            # libclntsh.so.11.1->getenv
            # libclntsh.so.11.1->getenv
            # libpython2.7.so.1.0->getenv
            funcFull = funcFull.split("->")[-1]

            # ltrace does not add "@SYS" when the function is resumed:
            #[pid 18316] 09:00:22.600426 rt_sigprocmask@SYS(0, 0x7ffea10cd370, 0x7ffea10cd3f0, 8 <unfinished ...>
            #[pid 18316] 09:00:22.600494 <... rt_sigprocmask resumed> ) = 0 <0.000068>
            if self.m_status == BatchStatus.resumed:
                assert not funcFull.startswith("SYS_")
                self.m_funcNam = funcFull + "@SYS"
            else:
                # On RHEL4, the function is prefixed by "SYS_"
                if funcFull.startswith("SYS_"):
                    assert not funcFull.endswith("@SYS")
                    self.m_funcNam = funcFull[4:] + "@SYS"
                else:
                    assert funcFull.endswith("@SYS")
                    self.m_funcNam = funcFull

            # It does not work with this:
            #[pid 4784] 16:42:10.781324 Py_Main(2, 0x7ffed52a8038, 0x7ffed52a8050, 0 <unfinished ...>
            #[pid 4784] 16:42:12.166187 <... Py_Main resumed> ) = 0 <1.384547>
            #
            # The only thing we can do is register the function names which have been seen as unfinished,
            # store their prefix and use this to correctly suffix them or not.

        else:
            raise Exception("SetFunction tracer %s unsupported" % self.m_trace)

    def SetDefaultOnError(self):
        self.SetFunction("")
        self.m_parsedArgs = []
        self.m_retValue = None

    # This parsing is specific to strace and ltrace.
    def InitAfterPid(self, oneLine, idxStart):
        # "07:54:54.206113"
        aTimeStamp = oneLine[idxStart:idxStart+15]

        self.m_timeStart = aTimeStamp
        self.m_timeEnd = aTimeStamp
        theCall = oneLine[idxStart+16:]

        # "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=19332, si_uid=1000, si_status=1, si_utime=0, si_stime=0} ---"
        if theCall.startswith("--- "):
            raise ExceptionIsExit()

        # "+++ exited with 1 +++ ['+++ exited with 1 +++']"
        if theCall.startswith("+++ "):
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
        idxLT = theCall.rfind("<", 0, idxGT)
        # sys.stdout.write("idxLT=%d\n" % idxLT )
        self.m_status = BatchStatus.plain
        if idxLT >= 0 :
            exeTm = theCall[idxLT+1:idxGT]
            if exeTm == "unfinished ...":
                self.m_execTim = ""
                self.m_status = BatchStatus.unfinished
            else:
                ### ????? self.m_execTim = theCall[idxLT+1:idxGT]
                self.m_execTim = exeTm
        else:
            self.m_execTim = ""

        # Another scenario:
        # [pid 11761] 10:56:39.125823 close@SYS(4 <unfinished ...>
        # [pid 11762] 10:56:39.125896 mmap@SYS(nil, 4096, 3, 34, -1, 0 <unfinished ...>
        # [pid 11761] 10:56:39.125939 <... close resumed> ) = 0 <0.000116>
        # [pid 11762] 10:56:39.125955 <... mmap resumed> ) = 0x7f75198d5000 <0.000063>
        matchResume = re.match(r"<\.\.\. ([^ ]*) resumed> (.*)", theCall)
        if matchResume:
            self.m_status = BatchStatus.resumed
            # TODO: Should check if this is the correct function name.
            funcNameResumed = matchResume.group(1)
            self.SetFunction(funcNameResumed)

            # ") = 0 <0.000069>"
            # ", { 0x5612836832c0, <>, 0, nil }) = 0 <0.000361>"

            # Offset of the second match.
            # A 'resumed' function call does not have an opening parenthesis.
            idxPar = matchResume.start(2) - 1

        else:
            idxPar = theCall.find("(")

            if idxPar <= 0 :
                # With ltrace only, wrong detection: https://github.com/dkogan/ltrace/blob/master/TODO
                # oneLine='error: maximum array length seems negative, "\236\245\v", 8192) = -21'
                if self.m_tracer == "ltrace":
                    if oneLine.startswith("error:"):
                        sys.stdout.write("Warning ltrace:%s\n" % oneLine)
                        self.SetDefaultOnError()
                        return

                # Exception: No function in:22:50:11.879132 <... exit resumed>) = ?
                # Special case, when it is leaving:
                elif self.m_tracer == "strace":
                    if oneLine.find("<... exit resumed>) = ?") >= 0:
                        sys.stdout.write("Warning strace exit:%s"%oneLine)
                        self.SetDefaultOnError()
                        return

                    if oneLine.find("<... exit_group resumed>) = ?") >= 0:
                        sys.stdout.write("Warning strace exit_group:%s\n"%oneLine)
                        self.SetDefaultOnError()
                        return

                raise Exception("No function in:%s"%oneLine)

            self.SetFunction(theCall[:idxPar])

        self.m_parsedArgs, idxLastPar = ParseCallArguments(theCall,idxPar+1)

        if self.m_status == BatchStatus.unfinished:
            # 18:46:10.920748 execve("/usr/bin/ps", ["ps", "-ef"], [/* 33 vars */] <unfinished ...>
            self.m_retValue = None
        else:
            # The parameters list might be broken, with strings containing an embedded double-quote.
            if idxLastPar < 0:
                # The parameters list might be broken, with strings containing an embedded double-quote.
                # So the closing parenthesis could not be found.
                idxEq = theCall.rfind("=", 0, idxLT)
                if idxEq < 0:
                    raise Exception("No = from end: idxLT=%d. theCall=%s" % (idxLT, theCall))
            else:
                # Normal case where the '=' equal sign comes after the clolsing parenthese of the args list.
                idxEq = theCall.find("=", idxLastPar)
                if idxEq < 0:
                    # This is acceptable in this circumstance only.
                    if not theCall.endswith("<no return ...>\n") and not theCall.endswith("<detached ...>"):
                        if self.m_tracer != "ltrace":
                        # This can happen with ltrace which does not escape double-quotes. Example:
                        # read@SYS(8, "\003\363\r\n"|\314Vc", 4096) = 765 <0.000049>
                            raise Exception("No = from parenthesis: idxLastPar=%d. theCall=%s. Len=%d" % (idxLT, theCall, len(theCall)))

            assert idxEq >= 0 and idxEq < idxLT
            self.m_retValue = theCall[idxEq + 1:idxLT].strip()
            # sys.stdout.write("idxEq=%d idxLastPar=%d idxLT=%d retValue=%s\n"%(idxEq,idxLastPar,idxLT,self.m_retValue))

    def AsStr(self):
        return "%s %s s=%s" % (
            str(self.m_parsedArgs),
            self.m_retValue,
            BatchStatus.chrDisplayCodes[self.m_status])

class ExceptionIsExit(Exception):
    pass

class ExceptionIsSignal(Exception):
    pass

def CreateBatchCore(oneLine,tracer):

    try:
        batchCore = BatchLetCore()
        batchCore.ParseLine(oneLine, tracer)
        return batchCore
    except ExceptionIsExit:
        return None
    except ExceptionIsSignal:
        return None


################################################################################

# These system calls are not taken into account because they do not give
# any dependency between the process and other resources,
# so we are not interested by their return value.
G_ignoredSyscalls = [
    "arch_prctl",
    "brk",
    "futex",
    "clock_getres",
    "clock_gettime",
    "getegid",
    "geteuid",
    "getgid",
    "getpgid",
    "getpid",
    "getpgrp",
    "getppid",
    "getresgid",
    "getrlimit",
    "gettid",
    "getuid",
    "lseek",
    "mlock",
    "mprotect",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
    "set_robust_list",
    "set_tid_address",
    "setpgid",
    "setpgrp",
    "times",
]


# Each class is indexed with the name of the corresponding system call name.
# If the class is None, it means that this function is explicitly neglected.
# If it is not defined after metaclass registration, then it is processed by BatchLetBase.
# Derived classes of BatchLetBase self-register thanks to the metaclass.
# At init time, this map contains the systems calls which should be ignored.

G_batchModels = {sysCll + "@SYS": None for sysCll in G_ignoredSyscalls}

# This metaclass allows derived class of BatchLetBase to self-register their function name.
# So, the name of a system call is used to lookup the class which represents it.
class BatchMeta(type):
    # This registers function names using the name of the derived class which is properly truncated.
    # TODO: It would be cleaner to add members in the class cls, instead of using the class name
    # to characterize the function.
    def __init__(cls, name, bases, dct):
        global G_batchModels

        # This is for Linux system calls.
        btchSysPrefix = "BatchLetSys_"

        # This is for plain libraries functions: "__libc_start_main", "Py_Main" and
        # functions like "libpython2.7.so.1.0->getenv", "libperl.so.5.24->getenv" etc...
        btchLibPrefix = "BatchLetLib_"

        if name.startswith(btchSysPrefix):
            syscallName = name[len(btchSysPrefix):] + "@SYS"
            # sys.stdout.write("Registering sys function:%s\n"%syscallName)
            G_batchModels[syscallName] = cls
        elif name.startswith(btchLibPrefix):
            syscallName = name[len(btchLibPrefix):]
            # sys.stdout.write("Registering lib function:%s\n"%syscallName)
            G_batchModels[syscallName] = cls
        elif name not in ["NewBase", "BatchLetBase", "BatchLetSequence"]:
            # Enumerate the list of legal base classes, for safety only.
            raise Exception("Invalid class name:%s"%name)

        super(BatchMeta, cls).__init__(name, bases, dct)

# This is portable on Python 2 and Python 3.
# No need to import the modules six or future.utils
def my_with_metaclass(meta, *bases):
    return meta("NewBase", bases, {})

# All class modeling a system call inherit from this.
class BatchLetBase(my_with_metaclass(BatchMeta)):

    # The style tells if this is a native call or an aggregate of function
    # calls, made with some style: Factorization etc...
    def __init__(self, batchCore,style="Orig"):
        self.m_core = batchCore
        self.m_occurrences = 1
        self.m_style = style

        # Maybe we could get rid of the parsed args as they are not needed anymore.
        self.m_significantArgs = self.m_core.m_parsedArgs

    def __str__(self):
        return self.m_core.m_funcNam

    def SignificantArgs(self):
        return self.m_significantArgs

    # This is used to detect repetitions.
    def GetSignature(self):
        return self.m_core.m_funcNam

    def GetSignatureWithArgs(self):
        try:
            # This is costly so we calculate it once only.
            return self.m_signatureWithArgs
        except AttributeError:
            self.m_signatureWithArgs = self.m_core.m_funcNam + ":" + "&".join(map(str, self.m_significantArgs))
            return self.m_signatureWithArgs

    # This is very often used.
    def StreamName(self, idx=0):
        aFil = self.STraceStreamToFile(self.m_core.m_parsedArgs[idx])
        return [aFil]

    def SameCall(self, anotherBatch):
        if self.m_core.m_funcNam != anotherBatch.m_core.m_funcNam:
            return False

        return self.SameArguments(anotherBatch)

    # This assumes that the function calls are the same.
    # It compares the arguments one by one.
    def SameArguments(self, anotherBatch):
        args1 = self.SignificantArgs()
        args2 = anotherBatch.SignificantArgs()

        # sys.stdout.write("%s args1=%s\n" % ( self.m_core.m_funcNam, str(args1)) )
        # sys.stdout.write("%s args2=%s\n" % ( anotherBatch.m_core.m_funcNam, str(args2)) )

        # At least they should have the same number of arguments.
        if len(args1) != len(args2):
            return False

        idx = 0
        for val1 in args1:
            val2 = args2[idx]

            if val1 != val2:
                return False
            idx += 1

        return True

    invalid_hexadecimal_pathnames = set()

    # Returns the file associated to this path, and creates it if needed.
    # It also associates this file to the process.
    def ToObjectPath_Accessed_CIM_DataFile(self, pathName):
        # With lstat and calls like access() or lstat(), the pathname is not given.
        if pathName.startswith("0x") and not pathName in self.invalid_hexadecimal_pathnames:
            # Signal the error once only.
            self.invalid_hexadecimal_pathnames.add(pathName)
            raise Exception("Invalid hexadecimal pathname:%s" % pathName)
        return cim_objects_definitions.ToObjectPath_CIM_DataFile(pathName, self.m_core.m_pid)

    def STraceStreamToFile(self, strmStr):
        return cim_objects_definitions.ToObjectPath_CIM_DataFile(STraceStreamToPathname(strmStr), self.m_core.m_pid )

# This associates file descriptors to path names when strace and the option "-y"
# cannot be used. There are predefined values.
G_mapFilDesToPathName = None

def InitLinuxGlobals(withWarning):
    global G_stackUnfinishedBatches
    global G_mapFilDesToPathName

    G_stackUnfinishedBatches = UnfinishedBatches(withWarning)

    G_mapFilDesToPathName = {
        "0": "stdin",
        "1": "stdout",
        "2": "stderr"}


################################################################################

# There are displayed once only.
G_UnknownFunctions = set()


def BatchLetFactory(batchCore):
    try:
        # TODO: We will have to take the library into account.
        assert G_batchModels
        aModel = G_batchModels[batchCore.m_funcNam]
    except KeyError:
        # Default generic BatchLet, if the function is not associated to a derived class of BatchLetCore.
        if not batchCore.m_funcNam in G_UnknownFunctions:
            sys.stdout.write("Undefined function %s\n" % batchCore.m_funcNam)

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
        return BatchLetBase(batchCore)

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
            aModel.Incomplete_UnfinishedIsOk
            btchLetDrv = aModel(batchCore)
            # ResumedOnly
            # UnfinishedOnly
        except AttributeError:
            # We do not have the return value, and maybe not all the arguments,
            # so we simply store what we have and hope to merge
            # with the "resumed" part, later on.
            btchLetDrv = BatchLetBase(batchCore)

            # To match later with the "resumed" line.
            G_stackUnfinishedBatches.PushBatch(batchCore)
    elif batchCore.m_status == BatchStatus.resumed:
        # We should have the "unfinished" part somewhere.

        batchCoreMerged = G_stackUnfinishedBatches.MergePopBatch(batchCore)

        if batchCoreMerged:
            assert batchCoreMerged == batchCore
            try:
                btchLetDrv = aModel(batchCoreMerged)
            except:
                sys.stdout.write(
                    "Cannot create derived class %s from args:%s\n" % (aModel.__name__, str(batchCore.m_parsedArgs)))
                raise
        else:
            # Could not find the matching unfinished batch.
            # Still we try the degraded mode if it is available.
            try:
                aModel.Incomplete_ResumedWithoutUnfinishedIsOk
                btchLetDrv = aModel(batchCore)
            except AttributeError:
                pass

            btchLetDrv = BatchLetBase(batchCore)
    else:
        btchLetDrv = aModel(batchCore)

    # If the parameters makes it unusable anyway.
    try:
        btchLetDrv.m_core
        # sys.stdout.write("batchCore=%s\n"%id(batchCore))
        assert btchLetDrv.m_core == batchCore
        return btchLetDrv
    except AttributeError:
        return None


################################################################################

# strace associates file descriptors to the original file or socket which created it.
# Option "-y          Print paths associated with file descriptor arguments."
# read ['3</usr/lib64/libc-2.21.so>']
# This returns a WMI object path, which is self-descriptive.
# FIXME: Are file descriptors shared between processes ?
def STraceStreamToPathname(strmStr):
    idxLT = strmStr.find("<")
    if idxLT >= 0:
        pathName = strmStr[ idxLT + 1 : -1 ]
    else:
        # If the option "-y" is not available, with ltrace or truss.
        # Theoretically the path name should be in the map.
        try:
            assert G_mapFilDesToPathName is not None
            pathName = G_mapFilDesToPathName[ strmStr ]
        except KeyError:
            if strmStr == "-1": # Normal return value.
                pathName = "Invalid device"
            else:
                pathName = "UnknownFileDescr:%s" % strmStr

    return pathName

################################################################################

# Some Linux functions return a file descriptor which can be invalid:
# This is not shown the same way depending on the tracer: strace or ltrace.
# On Linux, ENOENT = 2.
def InvalidReturnedFileDescriptor(fileDes, tracer):
    if tracer == "strace":
        # 09:18:26.452764 open("/usr/lib/python2.7/numbersmodule.so", O_RDONLY|O_LARGEFILE) = -1 ENOENT (No such file or directory) <0.000012>
        if fileDes.find("ENOENT") >= 0:
            return True
    elif tracer == "ltrace":
        # [pid 4784] 16:42:12.033450 open@SYS("/usr/lib64/python2.7/numbersmodule.so", 0, 0666) = -2 <0.000195>
        if fileDes.find("-2") >= 0 :
            return True
    else:
        raise Exception("Tracer %s not supported yet" % tracer)
    return False

################################################################################



##### File descriptor system calls.

# Must be a new-style class.
class BatchLetSys_open(BatchLetBase, object):
    def __init__(self, batchCore):
        global G_mapFilDesToPathName

        # TODO: If the open is not successful, maybe it should be rejected.
        if InvalidReturnedFileDescriptor(batchCore.m_retValue, batchCore.m_tracer):
            return
        super(BatchLetSys_open, self).__init__(batchCore)

        if batchCore.m_tracer == "strace":
            # strace has the "-y" option which writes the complete path each time,
            # the file descriptor is used as an input argument.

            # If the open succeeds, the file actually opened might be different,
            # than the input argument. Example:
            # open("/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib64/libc-2.25.so>
            # Therefore the returned file should be SignificantArgs(),
            # not the input file.
            filObj = self.STraceStreamToFile(self.m_core.m_retValue)
        elif batchCore.m_tracer == "ltrace":
            # The option "-y" which writes the complete path after the file descriptor,
            # is not available for ltrace.
            # Therefore this mapping must be done here, by reading the result of open()
            # and other system calls which create a file descriptor.

            # This logic also should work with strace if the option "-y" is not there.
            pathName = self.m_core.m_parsedArgs[0]
            filDes = self.m_core.m_retValue

            # TODO: Should be cleaned up when closing ?
            G_mapFilDesToPathName[filDes] = pathName
            filObj = self.ToObjectPath_Accessed_CIM_DataFile(pathName)
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        self.m_significantArgs = [filObj]
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(filObj)
        aFilAcc.SetOpenTime(self.m_core.m_timeStart)


# The important file descriptor is the returned value.
# openat(AT_FDCWD, "../list_machines_in_domain.py", O_RDONLY|O_NOCTTY) = 3</home/rchateau/survol/Experimental/list_machines_in_domain.py> <0.000019>
class BatchLetSys_openat(BatchLetBase, object):
    def __init__(self, batchCore):
        global G_mapFilDesToPathName

        super(BatchLetSys_openat, self).__init__(batchCore)

        # Same logic as for open().
        if batchCore.m_tracer == "strace":
            filObj = self.STraceStreamToFile(self.m_core.m_retValue)
        elif batchCore.m_tracer == "ltrace":
            dirNam = self.m_core.m_parsedArgs[0]

            if dirNam == "AT_FDCWD":
                # A relative pathname is interpreted relative to the directory
                # referred to by the file descriptor passed as first parameter.
                dirPath = self.m_core.m_objectProcess.GetProcessCurrentDir()
            else:
                dirPath = self.STraceStreamToFile(dirNam)

            filNam = self.m_core.m_parsedArgs[1]

            pathName = cim_objects_definitions.ToAbsPath(dirPath, filNam)

            filDes = self.m_core.m_retValue

            # TODO: Should be cleaned up when closing ?
            G_mapFilDesToPathName[filDes] = pathName
            filObj = self.ToObjectPath_Accessed_CIM_DataFile(pathName)
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        self.m_significantArgs = [filObj]


class BatchLetSys_close(BatchLetBase, object):
    def __init__(self, batchCore):
        # Maybe no need to record it if close is unsuccessful.
        # [pid 10624] 14:09:55.350002 close(2902) = -1 EBADF (Bad file descriptor) <0.000006>
        super(BatchLetSys_close, self).__init__(batchCore)
        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])
        aFilAcc.SetOpenTime(self.m_core.m_timeStart)
        if batchCore.m_retValue.find("EBADF") >= 0:
            return
        aFilAcc.SetCloseTime(self.m_core.m_timeEnd)

class BatchLetSys_read(BatchLetBase, object):
    def __init__(self, batchCore):
        try:
            bytesRead = int(batchCore.m_retValue)
        except ValueError:
            # Probably a race condition: invalid literal for int() with base 10: 'read@SYS(31'
            # Or: "read(31</tmp>, 0x7ffdd2592930, 8192) = -1 EISDIR (Is a directory)"
            if batchCore.m_retValue.find("EISDIR") >= 0:
                return
            # Or: "read(9<pipe:[15588394]>, 0x7f77a332a7c0, 1024) = -1 EAGAIN"
            if batchCore.m_retValue.find("EAGAIN") >= 0:
                return

            # Or: "read(0</dev/pts/2>,  <detached ...>"
            # TODO: Should be processed specifically.
            # This happens if the buffer contains a double-quote. Example:
            # Error parsing retValue=read@SYS(8, "\003\363\r\n"|\314Vc", 4096)                                                  = 765
            sys.stdout.write("Error parsing retValue=%s\n" % (batchCore.m_retValue))
            return

        super(BatchLetSys_read, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])

        aFilAcc.SetRead(bytesRead, self.m_core.m_parsedArgs[1])


# The process id is the return value but does not have the same format
# with ltrace (hexadecimal) and strace (decimal).
# Example: pread@SYS(256, 0x255a200, 0x4000, 0) = 0x4000
def ConvertBatchCoreRetValue(batchCore):
    if batchCore.m_tracer == "ltrace":
        return int(batchCore.m_retValue, 16)
    elif batchCore.m_tracer == "strace":
        return int(batchCore.m_retValue)
    else:
        raise Exception("Invalid tracer")


# Pread() is like read() but reads from the specified position in the file without modifying the file pointer.
class BatchLetSys_preadx(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_preadx, self).__init__(batchCore)

        bytesRead = ConvertBatchCoreRetValue(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])
        aFilAcc.SetRead(bytesRead)


class BatchLetSys_pread64x(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_pread64x, self).__init__(batchCore)

        bytesRead = ConvertBatchCoreRetValue(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])
        aFilAcc.SetRead(bytesRead, self.m_core.m_parsedArgs[1])


class BatchLetSys_write(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_write, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])

        try:
            bytesWritten = int(self.m_core.m_retValue)
            aFilAcc.SetWritten(bytesWritten, self.m_core.m_parsedArgs[1])
        except ValueError:
            # Probably a race condition: invalid literal for int() with base 10: 'write@SYS(28, "\\372", 1'
            pass


class BatchLetSys_writev(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_writev, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()
        aFilAcc = self.m_core.m_objectProcess.GetFileAccess(self.m_significantArgs[0])

        try:
            bytesWritten = int(self.m_core.m_retValue)
            # The content is not processed yet.
            aFilAcc.SetWritten(bytesWritten, None)
        except ValueError:
            # Probably a race condition: invalid literal for int() with base 10: 'write@SYS(28, "\\372", 1'
            pass


class BatchLetSys_ioctl(BatchLetBase, object):
    def __init__(self, batchCore):
        # With strace: "ioctl(-1, TIOCGPGRP, 0x7ffc3b5287f4) = -1 EBADF (Bad file descriptor)"
        # TODO: Could use the parameter TIOCSPGRP to get the process id: ioctl(255</dev/pts/2>, TIOCSPGRP, [26531])

        if batchCore.m_retValue.find("EBADF") >= 0:
            return
        super(BatchLetSys_ioctl, self).__init__(batchCore)

        self.m_significantArgs = [self.STraceStreamToFile(self.m_core.m_parsedArgs[0])] + self.m_core.m_parsedArgs[1:0]


class BatchLetSys_stat(BatchLetBase, object):
    def __init__(self, batchCore):
        # TODO: If the stat is not successful, maybe it should be rejected.
        if InvalidReturnedFileDescriptor(batchCore.m_retValue, batchCore.m_tracer):
            return
        super(BatchLetSys_stat, self).__init__(batchCore)

        self.m_significantArgs = [self.ToObjectPath_Accessed_CIM_DataFile(self.m_core.m_parsedArgs[0])]


class BatchLetSys_lstat(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_lstat, self).__init__(batchCore)

        self.m_significantArgs = [self.ToObjectPath_Accessed_CIM_DataFile(self.m_core.m_parsedArgs[0])]


# With ltrace:
# lstat@SYS("./UnitTests/mineit_wget_hotmail.strace.866.xml", 0x55fd19026230) = 0
# lgetxattr@SYS("./UnitTests/mineit_wget_hotmail.strace.866.xml", "security.selinux", 0x55fd19029770, 255) = 37
# getxattr@SYS("./UnitTests/mineit_wget_hotmail.strace.866.xml", "system.posix_acl_access", nil, 0) = -61


class BatchLetSys_access(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_access, self).__init__(batchCore)

        self.m_significantArgs = [self.ToObjectPath_Accessed_CIM_DataFile(self.m_core.m_parsedArgs[0])]


class BatchLetSys_dup(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_dup, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

        self.m_significantArgs.append(self.STraceStreamToFile(self.m_core.m_retValue))
        # TODO: BEWARE, DUPLICATED ELEMENTS IN THE ARGUMENTS: SHOULD sort()+uniq()


class BatchLetSys_dup2(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_dup2, self).__init__(batchCore)

        # TODO: After that, the second file descriptor points to the first one.
        self.m_significantArgs = self.StreamName()


##### Memory system calls.

class BatchLetSys_mmap(BatchLetBase, object):
    def __init__(self, batchCore):
        # Not interested by anonymous map because there is no side effect.
        if batchCore.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return

        fdArg = batchCore.m_parsedArgs[4]
        if fdArg == "-1":
            return
        super(BatchLetSys_mmap, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName(4)


class BatchLetSys_munmap(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_munmap, self).__init__(batchCore)

        # The parameter is only an address and we cannot do much with it.
        self.m_significantArgs = []


# 'mmap2' ['NULL', '4096', 'PROT_READ|PROT_WRITE', 'MAP_PRIVATE|MAP_ANONYMOUS', '-1', '0'] ==>> 0xf7b21000 (09:18:26,09:18:26)
class BatchLetSys_mmap2(BatchLetBase, object):
    def __init__(self, batchCore):
        # Not interested by anonymous map because there is no side effect.
        if batchCore.m_parsedArgs[3].find("MAP_ANONYMOUS") >= 0:
            return
        super(BatchLetSys_mmap2, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName(4)


##### File system calls.

class BatchLetSys_fstat(BatchLetBase, object):
    def __init__(self, batchCore):
        # With strace: "fstat(-1, 0x7fff57630980) = -1 EBADF (Bad file descriptor)"
        if batchCore.m_retValue.find("EBADF") >= 0:
            return
        super(BatchLetSys_fstat, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_fstat64(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fstat64, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_fstatfs(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fstatfs, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_fadvise64(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fadvise64, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_fchdir(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fchdir, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()

        # This also stores the new current directory in the process.
        self.m_core.m_objectProcess.SetProcessCurrentDir(self.m_significantArgs[0])


class BatchLetSys_fcntl(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fcntl, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_fcntl64(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fcntl64, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_fchown(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fchown, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_ftruncate(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_ftruncate, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_fsync(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fsync, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_fchmod(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fchmod, self).__init__(batchCore)

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
class BatchLetSys_clone(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_clone, self).__init__(batchCore)

        # The process id is the return value but does not have the same format
        # with ltrace (hexadecimal) and strace (decimal).
        if batchCore.m_tracer == "ltrace":
            aPid = int(self.m_core.m_retValue, 16)

            # TODO: How to make the difference between thread and process ?
            isThread = True
        elif batchCore.m_tracer == "strace":
            aPid = int(self.m_core.m_retValue)
            flagsClone = self.m_core.m_parsedArgs[1].strip()
            if flagsClone.find("CLONE_VM") >= 0:
                isThread = True
            else:
                # flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD
                isThread = False
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        # sys.stdout.write("CLONE %s %s PID=%d\n" % ( batchCore.m_tracer, self.m_core.m_retValue, aPid) )

        # This is the created process.
        objNewProcess = cim_objects_definitions.ToObjectPath_CIM_Process(aPid)

        if isThread:
            objNewProcess.SetThread()

        self.m_significantArgs = [objNewProcess]

        objNewProcess.AddParentProcess(self.m_core.m_timeStart, self.m_core.m_objectProcess)

    # Process creations are not aggregated, not to lose the new pid.
    def SameCall(self, anotherBatch):
        return False


# It does not matter if the first "unfinished" cannot be found because only
# the "resumed" part is important as it constains the sub-PID/
class BatchLetSys_vfork(BatchLetBase, object):
    Incomplete_ResumedWithoutUnfinishedIsOk = True

    def __init__(self, batchCore):
        super(BatchLetSys_vfork, self).__init__(batchCore)

        # The process id is the return value but does not have the same format
        # with ltrace (hexadecimal) and strace (decimal).
        if batchCore.m_tracer == "ltrace":
            aPid = int(self.m_core.m_retValue, 16)
        elif batchCore.m_tracer == "strace":
            aPid = int(self.m_core.m_retValue)
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        # This is the created process.
        objNewProcess = cim_objects_definitions.ToObjectPath_CIM_Process(aPid)
        self.m_significantArgs = [objNewProcess]

        objNewProcess.AddParentProcess(self.m_core.m_timeStart, self.m_core.m_objectProcess)

    # Process creations are not aggregated, not to lose the new pid.
    def SameCall(self, anotherBatch):
        return False


# This is detected by strace.
# execve("/usr/bin/grep", ["grep", "toto", "../TestMySql.py"], [/* 34 vars */]) = 0 <0.000175>

# This is detected by ltrace also, with several situation:
# execve@SYS("/usr/local/bin/as", 0xd1a138, 0xd1a2b0) = -2 <0.000243>
# execve@SYS("/usr/bin/as", 0xd1a138, 0xd1a2b0 <no return ...>
# execve@SYS("/usr/bin/wc", 0x55e291ac8950, 0x55e291ac8f00 <unfinished ...>

class BatchLetSys_execve(BatchLetBase, object):
    def __init__(self, batchCore):

        # strace:
        # ['/usr/lib64/qt-3.3/bin/grep', '[grep, toto, ..]'] ==>> -1 ENOENT (No such file or directory)
        # ltrace:
        # execve@SYS("/usr/bin/ls", 0x55e291ac9bd0, 0x55e291ac8830 <no return ...>
        # If the executable could not be started, no point creating a batch node.
        if batchCore.m_retValue.find("ENOENT") >= 0:
            return
        super(BatchLetSys_execve, self).__init__(batchCore)

        # The first argument is the executable file name,
        # while the second is an array of command-line parameters.
        objNewDataFile = self.ToObjectPath_Accessed_CIM_DataFile(self.m_core.m_parsedArgs[0])

        if batchCore.m_tracer == "ltrace":
            # This contains just a pointer so we reuse
            commandLine = None  # [ self.m_core.m_parsedArgs[0] ]
        elif batchCore.m_tracer == "strace":
            commandLine = self.m_core.m_parsedArgs[1]
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        self.m_significantArgs = [
            objNewDataFile,
            commandLine]

        self.m_core.m_objectProcess.SetExecutable(objNewDataFile)
        self.m_core.m_objectProcess.SetCommandLine(commandLine)
        objNewDataFile.SetIsExecuted()

        # TODO: Specifically filter the creation of a new process.

    # Process creations or setup are not aggregated.
    def SameCall(self, anotherBatch):
        return False


# This is detected by ltrace.
# __libc_start_main([ "python", "TestProgs/mineit_mysql_select.py" ] <unfinished ...>
# It does not matter if it is not technically finished: We only need the executable.
# BEWARE: See difference with BatchLetSys_xxx classes.
class BatchLetLib___libc_start_main(BatchLetBase, object):
    Incomplete_UnfinishedIsOk = True

    def __init__(self, batchCore):
        super(BatchLetLib___libc_start_main, self).__init__(batchCore)

        # TODO: Take the path of the executable name.
        commandLine = self.m_core.m_parsedArgs[0]
        execName = commandLine[0]
        objNewDataFile = self.ToObjectPath_Accessed_CIM_DataFile(execName)
        self.m_significantArgs = [
            objNewDataFile,
            commandLine]
        self.m_core.m_objectProcess.SetExecutable(objNewDataFile)
        self.m_core.m_objectProcess.SetCommandLine(commandLine)
        objNewDataFile.SetIsExecuted()

    # Process creations or setup are not aggregated.
    def SameCall(self, anotherBatch):
        return False


class BatchLetSys_wait4(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_wait4, self).__init__(batchCore)

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
                aPid = int(self.m_core.m_retValue, 16)
                # sys.stdout.write("WAITzzz=%d\n" % aPid )
        elif batchCore.m_tracer == "strace":
            if self.m_core.m_retValue.find("ECHILD") >= 0:
                # wait4(-1, 0x7fff9a7a6cd0, WNOHANG, NULL) = -1 ECHILD (No child processes)
                aPid = None
            else:
                # <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 27037
                try:
                    aPid = int(self.m_core.m_retValue.split(" ")[0])
                except ValueError:
                    sys.stdout.write("wait4: Cannot decode pid from:%s\n" % self.m_core.m_retValue)
                    aPid = None
                # sys.stdout.write("WAITxxx=%d\n" % aPid )
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        if aPid:
            # sys.stdout.write("WAIT=%d\n" % aPid )
            waitedProcess = cim_objects_definitions.ToObjectPath_CIM_Process(aPid)
            self.m_significantArgs = [waitedProcess]
            waitedProcess.WaitProcessEnd(self.m_core.m_timeStart, self.m_core.m_objectProcess)


class BatchLetSys_exit_group(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_exit_group, self).__init__(batchCore)

        self.m_significantArgs = []


#####

# int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
class BatchLetSys_newfstatat(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_newfstatat, self).__init__(batchCore)

        dirNam = self.m_core.m_parsedArgs[0]

        if dirNam == "AT_FDCWD":
            dirPath = self.m_core.m_objectProcess.GetProcessCurrentDir()
        else:
            dirPath = STraceStreamToPathname(dirNam)
            if not dirPath:
                raise Exception("Invalid directory:%s" % dirNam)

        filNam = self.m_core.m_parsedArgs[1]

        pathName = cim_objects_definitions.ToAbsPath(dirPath, filNam)

        self.m_significantArgs = [self.ToObjectPath_Accessed_CIM_DataFile(pathName)]


class BatchLetSys_getdents(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_getdents, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_getdents64(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_getdents64, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


##### Sockets system calls.

class BatchLetSys_sendmsg(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_sendmsg, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


# sendmmsg(3<socket:[535040600]>, {{{msg_name(0)=NULL, msg_iov(1)=[{"\270\32\1\0\0\1\0\0
class BatchLetSys_sendmmsg(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_sendmmsg, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


class BatchLetSys_recvmsg(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_recvmsg, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


# recvfrom(3<socket:[535040600]>, "\270\32\201\203\0\1\0\0\0\1\0\0\
class BatchLetSys_recvfrom(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_recvfrom, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


# getsockname(1<TCPv6:[::ffff:54.36.162.150:21->::ffff:82.45.12.63:63703]>, {sa_family=AF_INET6, sin6_port=htons(21), inet_pton(AF_INET6, "::ffff:54.36.162.150", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, [28]) = 0 <0.000008>
class BatchLetSys_getsockname(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_getsockname, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


# getpeername(1<TCPv6:[::ffff:54.36.162.150:21->::ffff:82.45.12.63:63703]>, {sa_family=AF_INET6, sin6_port=htons(63703), inet_pton(AF_INET6, "::ffff:82.45.12.63", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, [28]) = 0 <0.000007>
class BatchLetSys_getpeername(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_getpeername, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


# ['[{fd=5<UNIX:[73470->73473]>, events=POLLIN}]', '1', '25000'] ==>> 1 ([{fd=5, revents=POLLIN}])
class BatchLetSys_poll(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_poll, self).__init__(batchCore)

        arrStrms = self.m_core.m_parsedArgs[0]

        if batchCore.m_tracer == "strace":
            if type(arrStrms) in (list, tuple):
                retList = []
                for oneStream in arrStrms:
                    # oneStream: {'fd=5<anon_inode:[eventfd]>', 'events=POLLIN'}
                    for elt in oneStream:
                        if elt.startswith('fd='):
                            fdName = elt[3:]
                            break

                filOnly = self.STraceStreamToFile(fdName)
                retList.append(filOnly)
                self.m_significantArgs = [retList]
            else:
                # It might be the string "NULL":
                sys.stdout.write("poll: Unexpected arrStrms=%s\n" % str(arrStrms))
                self.m_significantArgs = []
        else:
            self.m_significantArgs = []


# int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
#
# If strace:
# select ['1', ['0</dev/pts/2>'], [], ['0</dev/pts/2>'], {'tv_sec': '0', 'tv_usec': '0'}] ==>> 0 (Timeout) (07:43:14,07:43:14)
# select(13, [0<TCPv6:[:::21]> 12<pipe:[10567127]>], NULL, NULL, {tv_sec=30, tv_usec=0}) = 1 (in [12], left {tv_sec=29, tv_usec=999997})
# If strace and kill -9:
# "select(1, [0</dev/pts/2>], [], [0</dev/pts/2>], NULL <unfinished ...>)"
#
# If ltrace and kill -9 the process:
# "select@SYS(1, 0x7ffd06327760, 0x7ffd063277e0, 0x7ffd06327860 <no return ...>"
class BatchLetSys_select(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_select, self).__init__(batchCore)

        if batchCore.m_tracer == "strace":
            def ArrFdNameToArrString(arrStrms):
                # The program strace formats the parameters of the system call select(), as three arrays
                # of file descriptors, each of them starting with the number, followed by the path name.
                if arrStrms == "NULL":
                    # If the array of file descriptors is empty.
                    return []
                else:
                    # The delimiter is a space:
                    # "1 arrStrms=['0<TCPv6:[:::21]> 12<pipe:[10567127]>']"
                    # sys.stdout.write("%d arrStrms=%s\n"%(len(arrStrms),str(arrStrms)))
                    filStrms = []
                    for fdName in arrStrms:
                        # Most of times there should be one element only.
                        splitFdName = fdName.split(" ")
                        for oneFdNam in splitFdName:
                            filStrms.append(self.STraceStreamToFile(oneFdNam))
                    return filStrms

            arrArgs = self.m_core.m_parsedArgs
            arrFilRead = ArrFdNameToArrString(arrArgs[1])
            arrFilWrit = ArrFdNameToArrString(arrArgs[2])
            arrFilExcp = ArrFdNameToArrString(arrArgs[3])

            self.m_significantArgs = [arrFilRead, arrFilWrit, arrFilExcp]
        elif batchCore.m_tracer == "ltrace":
            self.m_significantArgs = []
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)


class BatchLetSys_setsockopt(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_setsockopt, self).__init__(batchCore)

        self.m_significantArgs = [self.m_core.m_retValue]


# socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 6<UNIX:[2038057]>
class BatchLetSys_socket(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_socket, self).__init__(batchCore)

        self.m_significantArgs = [self.STraceStreamToFile(self.m_core.m_retValue)]


# Different output depending on the tracer:
# strace: connect(6<UNIX:[2038057]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110)
# ltrace: connect@SYS(3, 0x25779f0, 16, 0x1999999999999999)
class BatchLetSys_connect(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_connect, self).__init__(batchCore)
        objPath = self.STraceStreamToFile(self.m_core.m_parsedArgs[0])

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
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        self.m_significantArgs = [objPath]


class BatchLetSys_bind(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_bind, self).__init__(batchCore)
        objPath = self.STraceStreamToFile(self.m_core.m_parsedArgs[0])
        if batchCore.m_tracer == "strace":
            # bind(4<NETLINK:[7274795]>, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 0
            objPath.SocketAddress = self.m_core.m_parsedArgs[1]

        elif batchCore.m_tracer == "ltrace":
            pass
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        self.m_significantArgs = [objPath]


# sendto(7<UNIX:[2038065->2038073]>, "\24\0\0", 16, MSG_NOSIGNAL, NULL, 0) = 16
class BatchLetSys_sendto(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_sendto, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


# TODO: If the return value is not zero, maybe reject.
# pipe([3<pipe:[255278]>, 4<pipe:[255278]>]) = 0
class BatchLetSys_pipe(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_pipe, self).__init__(batchCore)

        arrPipes = self.m_core.m_parsedArgs[0]
        arrFil0 = self.STraceStreamToFile(arrPipes[0])
        arrFil1 = self.STraceStreamToFile(arrPipes[1])

        self.m_significantArgs = [arrFil0, arrFil1]


# TODO: If the return value is not zero, maybe reject.
# pipe([3<pipe:[255278]>, 4<pipe:[255278]>]) = 0
class BatchLetSys_pipe2(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_pipe2, self).__init__(batchCore)

        arrPipes = self.m_core.m_parsedArgs[0]
        arrFil0 = self.STraceStreamToFile(arrPipes[0])
        arrFil1 = self.STraceStreamToFile(arrPipes[1])

        self.m_significantArgs = [arrFil0, arrFil1]


class BatchLetSys_shutdown(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_shutdown, self).__init__(batchCore)

        self.m_significantArgs = self.StreamName()


#####

# This is detected by ltrace.
# There can be several types of instantiations:
# libaugeas.so.0->getenv("HOME")            = "/home/rchateau"
# libaugeas.so.0->getenv("XDG_CACHE_HOME")  = nil
# libclntsh.so.11.1->getenv("HOME")         = "/home/rchateau"
# libclntsh.so.11.1->getenv("ORACLE_HOME")  = "/u01/app/oracle/product/11.2.0/xe"
# libpython2.7.so.1.0->getenv("PYTHONHOME") = nil
#
# This assumes that all shared libraries instianting a function with this same
# are actually doing the same thing. This might be wrong.
class BatchLetLib_getenv(BatchLetBase, object):

    def __init__(self, batchCore):
        # We could also take the environment variables of each process but
        # It does not tell which ones are actually useful.

        # The base class is never created because we do not need it.
        # We just need to intercept the environment variables reading.
        # super( BatchLetLib_getenv, self).__init__(batchCore)

        envNam = batchCore.m_parsedArgs[0]
        envVal = batchCore.m_retValue
        if envVal == "nil":
            envVal = ""

        # FIXME: Should have one map per process ?
        cim_objects_definitions.G_EnvironmentVariables[envNam] = envVal

# F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python', '', '4096'] ==>> 7 (16:42:10,16:42:10)
# F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python2', 'python2', '4096'] ==>> 9 (16:42:10,16:42:10)
# F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python2.7', 'python2.7', '4096'] ==>> -22 (16:42:10,16:42:10)

################################################################################

class UnfinishedBatches:
    def __init__(self, withWarning):
        # This must be specific to processes.
        # Because when a system call is resumed, it is in the same process.
        self.m_mapStacks = {}
        self.m_withWarning = withWarning

    # PROBLEM. A vfork() is started in the main process but "appears" in another one.
    # What we could do is infer the main process number when a pid appreas without having been created before.
    # 08:53:31.301860 vfork( <unfinished ...>
    # [pid 23944] 08:53:31.304901 <... vfork resumed> ) = 23945 <0.003032>

    def PushBatch(self, batchCoreUnfinished):
        # sys.stdout.write("PushBatch pid=%s m_funcNam=%s\n"%(batchCoreUnfinished.m_pid,batchCoreUnfinished.m_funcNam))
        try:
            mapByPids = self.m_mapStacks[batchCoreUnfinished.m_pid]
            try:
                mapByPids[batchCoreUnfinished.m_funcNam].append(batchCoreUnfinished)
            except KeyError:
                mapByPids[batchCoreUnfinished.m_funcNam] = [batchCoreUnfinished]
        except KeyError:
            self.m_mapStacks[batchCoreUnfinished.m_pid] = {batchCoreUnfinished.m_funcNam: [batchCoreUnfinished]}

        # sys.stdout.write("PushBatch m_funcNam=%s\n"%batchCoreUnfinished.m_funcNam)

    def MergePopBatch(self, batchCoreResumed):
        # sys.stdout.write("MergePopBatch pid=%s m_funcNam=%s\n"%(batchCoreResumed.m_pid,batchCoreResumed.m_funcNam))
        try:
            stackPerFunc = self.m_mapStacks[batchCoreResumed.m_pid][batchCoreResumed.m_funcNam]
        except KeyError:
            if self.m_withWarning > 1:
                sys.stdout.write("Resuming %s: cannot find unfinished call\n" % batchCoreResumed.m_funcNam)

            # This is strange, we could not find the unfinished call.
            # sys.stdout.write("MergePopBatch NOTFOUND1 m_funcNam=%s\n"%batchCoreResumed.m_funcNam)
            return None

        # They should have the same pid.
        try:
            batchCoreUnfinished = stackPerFunc[-1]
        except IndexError:
            if self.m_withWarning > 1:
                sys.stdout.write("MergePopBatch pid=%d m_funcNam=%s cannot find call\n"
                                 % (batchCoreResumed.m_pid, batchCoreResumed.m_funcNam))
            # Same problem, we could not find the unfinished call.
            # sys.stdout.write("MergePopBatch NOTFOUND2 m_funcNam=%s\n"%batchCoreResumed.m_funcNam)
            return None

        del stackPerFunc[-1]

        # Sanity check
        if batchCoreUnfinished.m_funcNam != batchCoreResumed.m_funcNam:
            raise Exception("Inconsistency batchCoreUnfinished.m_funcNam=%s batchCoreResumed.m_funcNam=%s\n"
                            % (batchCoreUnfinished.m_funcNam, batchCoreResumed.m_funcNam))

        # Now, the unfinished and the resumed batches are merged.
        argsMerged = batchCoreUnfinished.m_parsedArgs + batchCoreResumed.m_parsedArgs
        batchCoreResumed.m_parsedArgs = argsMerged

        # Sanity check
        if batchCoreUnfinished.m_status != BatchStatus.unfinished:
            raise Exception("Unfinished status is not plain:%d" % batchCoreUnfinished.m_status)

        batchCoreUnfinished.m_status = BatchStatus.matched
        batchCoreUnfinished.m_resumedBatch = batchCoreResumed

        # Sanity check
        if batchCoreResumed.m_status != BatchStatus.resumed:
            raise Exception("Resumed status is not plain:%d" % batchCoreResumed.m_status)

        batchCoreResumed.m_status = BatchStatus.merged
        batchCoreResumed.m_unfinishedBatch = batchCoreUnfinished

        return batchCoreResumed

    def PrintUnfinished(self, strm):
        if self.m_withWarning == 0:
            return
        for onePid in self.m_mapStacks:
            # strm.write("onePid=%s\n"%onePid)
            mapPid = self.m_mapStacks[onePid]

            isPidWritten = False

            for funcNam in mapPid:
                arrCores = mapPid[funcNam]
                if not arrCores: break

                if not isPidWritten:
                    isPidWritten = True
                    strm.write("Unfinished calls pid=%s\n" % onePid)

                strm.write("    Call name=%s\n" % funcNam)
                arrCores = mapPid[funcNam]
                for batchCoreUnfinished in arrCores:
                    strm.write("        %s\n" % (batchCoreUnfinished.AsStr()))
                strm.write("\n")
        strm.write("\n")


# This is used to collect system or function calls which are unfinished and cannot be matched
# with the corresponding "resumed" line. In some circumstances, the beginning of a "wait4()" call
# might appear in one process, and the resumed part in another. Therefore this container
# is global for all processes. The "withWarning" flag allows to hide detection of unmatched calls.
G_stackUnfinishedBatches = None

################################################################################
# These libc calls can be detected by ltrace but must be filtered
# because they do not bring information we want (And there are loads of them))
# G_ignoredCallLTrace = [
#     "strncmp",
#     "strlen",
#     "malloc",
#     "strcmp",
#     "memcmp",
#     "memcpy",
#     "calloc",
#     "malloc",
#     "free",
#     "memset",
#     "strcasecmp",
#     "__strdup",
#     "strchr",
#     "sprintf",
#     "__errno_location",
#     "bfd*",
#     "fopen",
# ]

# Many libc calls are created by several libraries because they are static.
# For example:
#    gcc->getenv("GNUTARGET") = nil <0.000182>
#    liblto_plugin.so.0->getenv("COLLECT_GCC_OPTIONS") = "'-mtune=generic' '-march=x86-64'" <0.000321>
# Note that the results are visible.
#
# Also, there are many libc calls, and in general, we do not know how to process
# their arguments.
# So we filter them additively.
################################################################################
