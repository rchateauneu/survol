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
import logging
import signal
import subprocess
import six

if __package__:
    from . import cim_objects_definitions
else:
    import cim_objects_definitions

################################################################################

# Parsing of the arguments of the systems calls printed by strace and ltrace.
# This starts immediately after an open parenthesis or bracket.
# It returns an index on the closing parenthesis, or equal to the string length.
# This is called for each line and is on the critical path.
def parse_call_arguments(strArgs, ixStart = 0):
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

    #hasOctal = False
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
                objToAdd, ixStart = parse_call_arguments(strArgs, ixCurr)
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
    no_return  = 7
    chrDisplayCodes = "? URmM "

# Read from a real process or from the log file name when replaying a session.
#G_topProcessId = None

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
        self._return_value = "N/A"
        self.m_status = BatchStatus.unknown

        # Both cannot be set at the same time.
        self.m_unfinishedBatch = None # If this is a merged batch.
        self.m_resumedBatch = None # If this is a matched batch.

    # tracer = "strace|ltrace"
    def parse_line_to_object(self, trace_line, tracer):
        # sys.stdout.write("%s oneLine1=%s" % (id(self),oneLine ) )
        self.m_tracer = tracer

        if trace_line.startswith("[pid "):
            index_after_pid = trace_line.find("]", 5)
            # This is a sub-process.
            self.m_pid = int(trace_line[5:index_after_pid])
            self._init_after_pid(trace_line, index_after_pid + 2)
        else:
            # This is the main process, but at this stage we do not have its pid.
            self.m_pid = cim_objects_definitions.G_topProcessId
            self._init_after_pid(trace_line, 0)

        # If this process is just created, it receives the creation time-stamp.
        self.m_objectProcess = self.cim_context().ToObjectPath_CIM_Process(self.m_pid)

        # If the creation date is uknown, it is at least equal to the current call time.
        if not self.m_objectProcess.CreationDate:
            self.m_objectProcess.CreationDate = self._time_start

    def cim_context(self):
        return cim_objects_definitions.ObjectsContext(self.m_pid)

    def _set_function(self, funcFull):
        # With ltrace, systems calls are suffix with the string "@SYS".
        if self.m_tracer == "strace":
            # strace can only intercept system calls.
            assert not funcFull.endswith("@SYS")
            assert not funcFull.startswith("SYS_")
            self._function_name = funcFull + "@SYS"
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
                if funcFull.startswith("SYS_"):
                    raise Exception("Wrong prefix:%s" % funcFull)
                self._function_name = funcFull + "@SYS"
            else:
                # On RHEL4, the function is prefixed by "SYS_"
                if funcFull.startswith("SYS_"):
                    if funcFull.endswith("@SYS"):
                        raise Exception("Wrong suffix:%s" % funcFull)
                    self._function_name = funcFull[4:] + "@SYS"
                else:
                    if not funcFull.endswith("@SYS"):
                        raise Exception("Missing suffix:%s" % funcFull)
                    self._function_name = funcFull

            # It does not work with this:
            #[pid 4784] 16:42:10.781324 Py_Main(2, 0x7ffed52a8038, 0x7ffed52a8050, 0 <unfinished ...>
            #[pid 4784] 16:42:12.166187 <... Py_Main resumed> ) = 0 <1.384547>
            #
            # The only thing we can do is register the function names which have been seen as unfinished,
            # store their prefix and use this to correctly suffix them or not.

        else:
            raise Exception("_set_function tracer %s unsupported" % self.m_trace)

    def _set_default_on_error(self):
        self._set_function("")
        self.m_parsedArgs = []
        self._return_value = None

    # This parsing is specific to strace and ltrace.
    def _init_after_pid(self, oneLine, idxStart):
        # "07:54:54.206113"
        aTimeStamp = oneLine[idxStart:idxStart+15]

        self._time_start = aTimeStamp
        self._time_end = aTimeStamp
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
            elif exeTm == "no return ...":
                # 18:10:13.109143 SYS_execve("/bin/sh", 0x9202d50, 0xff861d28 <no return ...>
                self.m_execTim = ""
                self.m_status = BatchStatus.no_return
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
            self._set_function(funcNameResumed)

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
                        self._set_default_on_error()
                        return

                # Exception: No function in:22:50:11.879132 <... exit resumed>) = ?
                # Special case, when it is leaving:
                elif self.m_tracer == "strace":
                    if oneLine.find("<... exit resumed>) = ?") >= 0:
                        sys.stdout.write("Warning strace exit:%s"%oneLine)
                        self._set_default_on_error()
                        return

                    if oneLine.find("<... exit_group resumed>) = ?") >= 0:
                        sys.stdout.write("Warning strace exit_group:%s\n"%oneLine)
                        self._set_default_on_error()
                        return

                raise Exception("No function in:%s"%oneLine)

            self._set_function(theCall[:idxPar])

        self.m_parsedArgs, idxLastPar = parse_call_arguments(theCall, idxPar + 1)

        if self.m_status == BatchStatus.unfinished:
            # 18:46:10.920748 execve("/usr/bin/ps", ["ps", "-ef"], [/* 33 vars */] <unfinished ...>
            self._return_value = None
        elif self.m_status == BatchStatus.no_return:
            # ltrace version 4.5
            # 18:46:45.766007 SYS_execve("/python/bin/python3-config", 0x941aff8, 0xfff25bf8 <no return ...>
            self._return_value = None
        else:
            # The parameters list might be broken, with strings containing an embedded double-quote.
            if idxLastPar < 0:
                # The parameters list might be broken, with strings containing an embedded double-quote.
                # So the closing parenthesis could not be found.
                idxEq = theCall.rfind("=", 0, idxLT)
                if idxEq < 0:
                    raise Exception("No = from end: idxLT=%d. function=%s" % (idxLT, theCall))
            else:
                # Normal case where the '=' equal sign comes after the clolsing parenthese of the args list.
                idxEq = theCall.find("=", idxLastPar)
                if idxEq < 0:
                    # This is acceptable in this circumstance only.
                    if not theCall.endswith("<no return ...>\n") and not theCall.endswith("<detached ...>"):
                        if self.m_tracer != "ltrace":
                        # This can happen with ltrace which does not escape double-quotes. Example:
                        # read@SYS(8, "\003\363\r\n"|\314Vc", 4096) = 765 <0.000049>
                            raise Exception("No = from parenthesis: idxLastPar=%d. function=%s. Len=%d" % (idxLT, theCall, len(theCall)))

            if not(idxEq >= 0 and idxEq < idxLT):
                # If this is the last line, not a problem
                # 20:20:34.510927 exit_group(0)           = ?
                if not theCall.startswith("exit_group"):
                    raise Exception("idxEq=%d idxLT=%d function=%s" % (idxEq, idxLT, theCall.strip()))
            self._return_value = theCall[idxEq + 1:idxLT].strip()
            # sys.stdout.write("idxEq=%d idxLastPar=%d idxLT=%d retValue=%s\n"%(idxEq,idxLastPar,idxLT,self._return_value))

    def convert_to_string(self):
        return "%s %s s=%s" % (
            str(self.m_parsedArgs),
            self._return_value,
            BatchStatus.chrDisplayCodes[self.m_status])


class ExceptionIsExit(Exception):
    pass


class ExceptionIsSignal(Exception):
    pass


def CreateBatchCore(oneLine,tracer):

    try:
        batchCore = BatchLetCore()
        batchCore.parse_line_to_object(oneLine, tracer)
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
        return self.m_core._function_name

    def get_significant_args(self):
        return self.m_significantArgs

    def cim_context_core(self):
        return self.m_core.cim_context()

    # This is used to detect repetitions.
    def get_signature_without_args(self):
        return self.m_core._function_name

    def get_signature_with_args(self):
        try:
            # This is costly so we calculate it once only.
            return self.m_signatureWithArgs
        except AttributeError:
            self.m_signatureWithArgs = self.m_core._function_name + ":" + "&".join(map(str, self.m_significantArgs))
            return self.m_signatureWithArgs

    # This is very often used.
    def get_stream_name(self, idx=0):
        aFil = self._strace_stream_to_file(self.m_core.m_parsedArgs[idx])
        return [aFil]

    def is_same_call(self, anotherBatch):
        if self.m_core._function_name != anotherBatch.m_core._function_name:
            return False

        return self._has_same_arguments(anotherBatch)

    # This assumes that the function calls are the same.
    # It compares the arguments one by one.
    def _has_same_arguments(self, anotherBatch):
        args1 = self.get_significant_args()
        args2 = anotherBatch.get_significant_args()

        # sys.stdout.write("%s args1=%s\n" % ( self.m_core._function_name, str(args1)) )
        # sys.stdout.write("%s args2=%s\n" % ( anotherBatch.m_core._function_name, str(args2)) )

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
        # return cim_objects_definitions.ToObjectPath_CIM_DataFile(pathName, self.m_core.m_pid)
        return self.cim_context_core().ToObjectPath_CIM_DataFile(pathName)

    def _strace_stream_to_file(self, strmStr):
        return self.cim_context_core().ToObjectPath_CIM_DataFile(_strace_stream_to_pathname(strmStr))

# This associates file descriptors to path names when strace and the option "-y"
# cannot be used. There are predefined values.
G_mapFilDesToPathName = None

def init_linux_globals(with_warning):
    global G_stackUnfinishedBatches
    global G_mapFilDesToPathName

    G_stackUnfinishedBatches = UnfinishedBatches(with_warning)

    G_mapFilDesToPathName = {
        "0": "stdin",
        "1": "stdout",
        "2": "stderr"}


################################################################################

# There are displayed once only.
G_UnknownFunctions = set()


def _batchlet_factory(batchCore):
    try:
        # TODO: We will have to take the library into account.
        assert G_batchModels
        aModel = G_batchModels[batchCore._function_name]
    except KeyError:
        # Default generic BatchLet, if the function is not associated to a derived class of BatchLetCore.
        if not batchCore._function_name in G_UnknownFunctions:
            sys.stdout.write("Undefined function %s\n" % batchCore._function_name)

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

            G_UnknownFunctions.add(batchCore._function_name)
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
            G_stackUnfinishedBatches.push_unfinished_batch(batchCore)
    elif batchCore.m_status == BatchStatus.resumed:
        # We should have the "unfinished" part somewhere.

        batchCoreMerged = G_stackUnfinishedBatches.merge_pop_resumed_batch(batchCore)

        if batchCoreMerged:
            assert batchCoreMerged == batchCore
            try:
                btchLetDrv = aModel(batchCoreMerged)
            except:
                sys.stderr.write(
                    "Cannot create derived class %s from args:%s\n" % (aModel.__name__, str(batchCore.m_parsedArgs)))
                raise
        else:
            # Could not find the matching unfinished batch.
            # Still we try the degraded mode if it is available.
            try:
                aModel.Incomplete_ResumedWithoutUnfinishedIsOk
                btchLetDrv = aModel(batchCore)
            except AttributeError:
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
def _strace_stream_to_pathname(strm_str):
    idxLT = strm_str.find("<")
    if idxLT >= 0:
        path_name = strm_str[idxLT + 1: -1]
    else:
        # If the option "-y" is not available, with ltrace or truss.
        # Theoretically the path name should be in the map.
        try:
            assert G_mapFilDesToPathName is not None
            path_name = G_mapFilDesToPathName[strm_str]
        except KeyError:
            if strm_str == "-1": # Normal return value.
                path_name = "Invalid device"
            else:
                path_name = "UnknownFileDescr:%s" % strm_str

    return path_name


################################################################################

# Some Linux functions return a file descriptor which can be invalid:
# This is not shown the same way depending on the tracer: strace or ltrace.
# On Linux, ENOENT = 2.
def _invalid_returned_file_descriptor(fileDes, tracer):
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
        if _invalid_returned_file_descriptor(batchCore._return_value, batchCore.m_tracer):
            return
        super(BatchLetSys_open, self).__init__(batchCore)

        if batchCore.m_tracer == "strace":
            # strace has the "-y" option which writes the complete path each time,
            # the file descriptor is used as an input argument.

            # If the open succeeds, the file actually opened might be different,
            # than the input argument. Example:
            # open("/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib64/libc-2.25.so>
            # Therefore the returned file should be get_significant_args(), not the input file.
            #
            # But with a deprecated version, it is also possible to have this format:
            # open("/lib/x86_64-linux-gnu/libpthread.so.0", O_RDONLY|O_CLOEXEC) = 10 <0.000016>
            filObj = self._strace_stream_to_file(self.m_core._return_value)
        elif batchCore.m_tracer == "ltrace":
            # The option "-y" which writes the complete path after the file descriptor,
            # is not available for ltrace.
            # Therefore this mapping must be done here, by reading the result of open()
            # and other system calls which create a file descriptor.

            # This logic also should work with strace if the option "-y" is not there.
            pathName = self.m_core.m_parsedArgs[0]
            filDes = self.m_core._return_value

            # TODO: Should be cleaned up when closing ?
            G_mapFilDesToPathName[filDes] = pathName
            filObj = self.ToObjectPath_Accessed_CIM_DataFile(pathName)
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        self.m_significantArgs = [filObj]
        aFilAcc = self.m_core.m_objectProcess.get_file_access(filObj)
        aFilAcc.SetOpenTime(self.m_core._time_start)


# The important file descriptor is the returned value.
# openat(AT_FDCWD, "../list_machines_in_domain.py", O_RDONLY|O_NOCTTY) = 3</home/rchateau/survol/Experimental/list_machines_in_domain.py> <0.000019>
class BatchLetSys_openat(BatchLetBase, object):
    def __init__(self, batchCore):
        global G_mapFilDesToPathName

        super(BatchLetSys_openat, self).__init__(batchCore)

        # Same logic as for open().
        if batchCore.m_tracer == "strace":
            filObj = self._strace_stream_to_file(self.m_core._return_value)
        elif batchCore.m_tracer == "ltrace":
            dirNam = self.m_core.m_parsedArgs[0]

            if dirNam == "AT_FDCWD":
                # A relative pathname is interpreted relative to the directory
                # referred to by the file descriptor passed as first parameter.
                dirPath = self.m_core.m_objectProcess.GetProcessCurrentDir()
            else:
                dirPath = self._strace_stream_to_file(dirNam)

            filNam = self.m_core.m_parsedArgs[1]

            pathName = cim_objects_definitions.to_real_absolute_path(dirPath, filNam)

            filDes = self.m_core._return_value

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
        self.m_significantArgs = self.get_stream_name()
        aFilAcc = self.m_core.m_objectProcess.get_file_access(self.m_significantArgs[0])
        aFilAcc.SetOpenTime(self.m_core._time_start)
        if batchCore._return_value.find("EBADF") >= 0:
            return
        aFilAcc.SetCloseTime(self.m_core._time_end)


class BatchLetSys_read(BatchLetBase, object):
    def __init__(self, batchCore):
        try:
            read_bytes_number = int(batchCore._return_value)
        except ValueError:
            # Probably a race condition: invalid literal for int() with base 10: 'read@SYS(31'
            # Or: "read(31</tmp>, 0x7ffdd2592930, 8192) = -1 EISDIR (Is a directory)"
            if batchCore._return_value.find("EISDIR") >= 0:
                return
            # Or: "read(9<pipe:[15588394]>, 0x7f77a332a7c0, 1024) = -1 EAGAIN"
            if batchCore._return_value.find("EAGAIN") >= 0:
                return

            # Or: "read(0</dev/pts/2>,  <detached ...>"
            # TODO: Should be processed specifically.
            # This happens if the buffer contains a double-quote. Example:
            # Error parsing retValue=read@SYS(8, "\003\363\r\n"|\314Vc", 4096) = 765
            sys.stdout.write("Error parsing retValue=%s\n" % (batchCore._return_value))
            return

        super(BatchLetSys_read, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()
        aFilAcc = self.m_core.m_objectProcess.get_file_access(self.m_significantArgs[0])

        aFilAcc.set_read_bytes_number(read_bytes_number, self.m_core.m_parsedArgs[1])


# The process id is the return value but does not have the same format
# with ltrace (hexadecimal) and strace (decimal).
# Example: pread@SYS(256, 0x255a200, 0x4000, 0) = 0x4000
def _convert_batch_core_return_value(batchCore):
    if batchCore.m_tracer == "ltrace":
        return int(batchCore._return_value, 16)
    elif batchCore.m_tracer == "strace":
        return int(batchCore._return_value)
    else:
        raise Exception("Invalid tracer")


# Pread() is like read() but reads from the specified position in the file without modifying the file pointer.
class BatchLetSys_preadx(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_preadx, self).__init__(batchCore)

        read_bytes_number = _convert_batch_core_return_value(batchCore)

        self.m_significantArgs = self.get_stream_name()
        aFilAcc = self.m_core.m_objectProcess.get_file_access(self.m_significantArgs[0])
        aFilAcc.set_read_bytes_number(read_bytes_number)


class BatchLetSys_pread64x(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_pread64x, self).__init__(batchCore)

        read_bytes_number = _convert_batch_core_return_value(batchCore)

        self.m_significantArgs = self.get_stream_name()
        aFilAcc = self.m_core.m_objectProcess.get_file_access(self.m_significantArgs[0])
        aFilAcc.set_read_bytes_number(read_bytes_number, self.m_core.m_parsedArgs[1])


class BatchLetSys_write(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_write, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()
        aFilAcc = self.m_core.m_objectProcess.get_file_access(self.m_significantArgs[0])

        try:
            written_bytes_number = int(self.m_core._return_value)
            aFilAcc.set_written_bytes_number(written_bytes_number, self.m_core.m_parsedArgs[1])
        except ValueError:
            # Probably a race condition: invalid literal for int() with base 10: 'write@SYS(28, "\\372", 1'
            pass


class BatchLetSys_writev(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_writev, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()
        aFilAcc = self.m_core.m_objectProcess.get_file_access(self.m_significantArgs[0])

        try:
            written_bytes_number = int(self.m_core._return_value)
            # The content is not processed yet.
            aFilAcc.set_written_bytes_number(written_bytes_number, None)
        except ValueError:
            # Probably a race condition: invalid literal for int() with base 10: 'write@SYS(28, "\\372", 1'
            pass


class BatchLetSys_ioctl(BatchLetBase, object):
    def __init__(self, batchCore):
        # With strace: "ioctl(-1, TIOCGPGRP, 0x7ffc3b5287f4) = -1 EBADF (Bad file descriptor)"
        # TODO: Could use the parameter TIOCSPGRP to get the process id: ioctl(255</dev/pts/2>, TIOCSPGRP, [26531])

        if batchCore._return_value.find("EBADF") >= 0:
            return
        super(BatchLetSys_ioctl, self).__init__(batchCore)

        self.m_significantArgs = [self._strace_stream_to_file(self.m_core.m_parsedArgs[0])] + self.m_core.m_parsedArgs[1:0]


class BatchLetSys_stat(BatchLetBase, object):
    def __init__(self, batchCore):
        # TODO: If the stat is not successful, maybe it should be rejected.
        if _invalid_returned_file_descriptor(batchCore._return_value, batchCore.m_tracer):
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

        self.m_significantArgs = self.get_stream_name()

        self.m_significantArgs.append(self._strace_stream_to_file(self.m_core._return_value))
        # TODO: BEWARE, DUPLICATED ELEMENTS IN THE ARGUMENTS: SHOULD sort()+uniq()


class BatchLetSys_dup2(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_dup2, self).__init__(batchCore)

        # TODO: After that, the second file descriptor points to the first one.
        self.m_significantArgs = self.get_stream_name()


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

        self.m_significantArgs = self.get_stream_name(4)


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

        self.m_significantArgs = self.get_stream_name(4)


##### File system calls.

class BatchLetSys_fstat(BatchLetBase, object):
    def __init__(self, batchCore):
        # With strace: "fstat(-1, 0x7fff57630980) = -1 EBADF (Bad file descriptor)"
        if batchCore._return_value.find("EBADF") >= 0:
            return
        super(BatchLetSys_fstat, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_fstat64(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fstat64, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_fstatfs(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fstatfs, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_fadvise64(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fadvise64, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_fchdir(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fchdir, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()

        # This also stores the new current directory in the process.
        self.m_core.m_objectProcess.set_process_current_directory(self.m_significantArgs[0])


class BatchLetSys_fcntl(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fcntl, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_fcntl64(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fcntl64, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_fchown(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fchown, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_ftruncate(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_ftruncate, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_fsync(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fsync, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_fchmod(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_fchmod, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


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
            aPid = int(self.m_core._return_value, 16)

            # TODO: How to make the difference between thread and process ?
            isThread = True
        elif batchCore.m_tracer == "strace":
            aPid = int(self.m_core._return_value)
            flagsClone = self.m_core.m_parsedArgs[1].strip()
            if flagsClone.find("CLONE_VM") >= 0:
                isThread = True
            else:
                # flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD
                isThread = False
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        # sys.stdout.write("CLONE %s %s PID=%d\n" % ( batchCore.m_tracer, self.m_core._return_value, aPid) )

        # This is the created process.
        objNewProcess = self.cim_context_core().ToObjectPath_CIM_Process(aPid)

        if isThread:
            objNewProcess.SetThread()

        self.m_significantArgs = [objNewProcess]

        objNewProcess.add_parent_process(self.m_core._time_start, self.m_core.m_objectProcess)

    # Process creations are not aggregated, not to lose the new pid.
    def is_same_call(self, anotherBatch):
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
            aPid = int(self.m_core._return_value, 16)
        elif batchCore.m_tracer == "strace":
            aPid = int(self.m_core._return_value)
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        # This is the created process.
        objNewProcess = self.cim_context_core().ToObjectPath_CIM_Process(aPid)
        self.m_significantArgs = [objNewProcess]

        objNewProcess.add_parent_process(self.m_core._time_start, self.m_core.m_objectProcess)

    # Process creations are not aggregated, not to lose the new pid.
    def is_same_call(self, anotherBatch):
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
        #   ['/usr/lib64/qt-3.3/bin/grep', '[grep, toto, ..]'] ==>> -1 ENOENT (No such file or directory)
        # ltrace:
        #   execve@SYS("/usr/bin/ls", 0x55e291ac9bd0, 0x55e291ac8830 <no return ...>
        #   In this case, _return_value is None.
        # If the executable could not be started, no point creating a batch node.
        if batchCore._return_value and batchCore._return_value.find("ENOENT") >= 0:
            return
        super(BatchLetSys_execve, self).__init__(batchCore)

        # The first argument is the executable file name,
        # while the second is an array of command-line parameters.
        objNewDataFile = self.ToObjectPath_Accessed_CIM_DataFile(self.m_core.m_parsedArgs[0])

        if batchCore.m_tracer == "ltrace":
            # This contains just a pointer so we reuse
            command_line = None  # [ self.m_core.m_parsedArgs[0] ]
        elif batchCore.m_tracer == "strace":
            command_line = self.m_core.m_parsedArgs[1]
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        self.m_significantArgs = [
            objNewDataFile,
            command_line]

        self.m_core.m_objectProcess.set_executable_path(objNewDataFile)
        self.m_core.m_objectProcess.set_command_line(command_line)
        objNewDataFile.set_is_executed()

        # TODO: Specifically filter the creation of a new process.

    # Process creations or setup are not aggregated.
    def is_same_call(self, anotherBatch):
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
        command_line = self.m_core.m_parsedArgs[0]
        exec_name = command_line[0]
        objNewDataFile = self.ToObjectPath_Accessed_CIM_DataFile(exec_name)
        self.m_significantArgs = [
            objNewDataFile,
            command_line]
        self.m_core.m_objectProcess.set_executable_path(objNewDataFile)
        self.m_core.m_objectProcess.set_command_line(command_line)
        objNewDataFile.set_is_executed()

    # Process creations or setup are not aggregated.
    def is_same_call(self, anotherBatch):
        return False


class BatchLetSys_wait4(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_wait4, self).__init__(batchCore)

        # sys.stdout.write("CLONE %s %s PID=%d\n" % ( batchCore.m_tracer, self.m_core._return_value, aPid) )

        # sys.stdout.write("WAIT A=%s\n" % self.m_core._return_value )
        # This is the terminated pid.
        if batchCore.m_tracer == "ltrace":
            if self.m_core._return_value.find("-10") >= 0:
                # ECHILD = 10
                # wait4@SYS(-1, 0x7ffea10cd110, 1, 0) = -10
                aPid = None
            else:
                # <... wait4 resumed> ) = 0x2df2
                aPid = int(self.m_core._return_value, 16)
                # sys.stdout.write("WAITzzz=%d\n" % aPid )
        elif batchCore.m_tracer == "strace":
            if self.m_core._return_value.find("ECHILD") >= 0:
                # wait4(-1, 0x7fff9a7a6cd0, WNOHANG, NULL) = -1 ECHILD (No child processes)
                aPid = None
            else:
                # <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 27037
                try:
                    aPid = int(self.m_core._return_value.split(" ")[0])
                except ValueError:
                    sys.stdout.write("wait4: Cannot decode pid from:%s\n" % self.m_core._return_value)
                    aPid = None
                # sys.stdout.write("WAITxxx=%d\n" % aPid )
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        if aPid:
            # sys.stdout.write("WAIT=%d\n" % aPid )
            waitedProcess = self.cim_context_core().ToObjectPath_CIM_Process(aPid)
            self.m_significantArgs = [waitedProcess]
            waitedProcess.WaitProcessEnd(self.m_core._time_start, self.m_core.m_objectProcess)


class BatchLetSys_exit_group(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_exit_group, self).__init__(batchCore)

        self.m_significantArgs = []


##### Others.

# int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
class BatchLetSys_newfstatat(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_newfstatat, self).__init__(batchCore)

        dirNam = self.m_core.m_parsedArgs[0]

        if dirNam == "AT_FDCWD":
            dirPath = self.m_core.m_objectProcess.GetProcessCurrentDir()
        else:
            dirPath = _strace_stream_to_pathname(dirNam)
            if not dirPath:
                raise Exception("Invalid directory:%s" % dirNam)

        filNam = self.m_core.m_parsedArgs[1]

        pathName = cim_objects_definitions.to_real_absolute_path(dirPath, filNam)

        self.m_significantArgs = [self.ToObjectPath_Accessed_CIM_DataFile(pathName)]


class BatchLetSys_getdents(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_getdents, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_getdents64(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_getdents64, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


##### Sockets system calls.

class BatchLetSys_sendmsg(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_sendmsg, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


# sendmmsg(3<socket:[535040600]>, {{{msg_name(0)=NULL, msg_iov(1)=[{"\270\32\1\0\0\1\0\0
class BatchLetSys_sendmmsg(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_sendmmsg, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


class BatchLetSys_recvmsg(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_recvmsg, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


# recvfrom(3<socket:[535040600]>, "\270\32\201\203\0\1\0\0\0\1\0\0\
class BatchLetSys_recvfrom(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_recvfrom, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


# getsockname(1<TCPv6:[::ffff:54.36.162.150:21->::ffff:82.45.12.63:63703]>, {sa_family=AF_INET6, sin6_port=htons(21), inet_pton(AF_INET6, "::ffff:54.36.162.150", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, [28]) = 0 <0.000008>
class BatchLetSys_getsockname(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_getsockname, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


# getpeername(1<TCPv6:[::ffff:54.36.162.150:21->::ffff:82.45.12.63:63703]>, {sa_family=AF_INET6, sin6_port=htons(63703), inet_pton(AF_INET6, "::ffff:82.45.12.63", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, [28]) = 0 <0.000007>
class BatchLetSys_getpeername(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_getpeername, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


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

                filOnly = self._strace_stream_to_file(fdName)
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
            def _file_descriptors_to_strings(file_descriptors_list):
                # The program strace formats the parameters of the system call select(), as three arrays
                # of file descriptors, each of them starting with the number, followed by the path name.
                if file_descriptors_list == "NULL":
                    # If the list of file descriptors is empty.
                    return []
                else:
                    # The delimiter is a space:
                    # "1 arrStrms=['0<TCPv6:[:::21]> 12<pipe:[10567127]>']"
                    # sys.stdout.write("%d arrStrms=%s\n"%(len(arrStrms),str(arrStrms)))
                    filStrms = []
                    for fdName in file_descriptors_list:
                        # Most of times there should be one element only.
                        splitFdName = fdName.split(" ")
                        for oneFdNam in splitFdName:
                            filStrms.append(self._strace_stream_to_file(oneFdNam))
                    return filStrms

            arguments_list = self.m_core.m_parsedArgs
            arrFilRead = _file_descriptors_to_strings(arguments_list[1])
            arrFilWrit = _file_descriptors_to_strings(arguments_list[2])
            arrFilExcp = _file_descriptors_to_strings(arguments_list[3])

            self.m_significantArgs = [arrFilRead, arrFilWrit, arrFilExcp]
        elif batchCore.m_tracer == "ltrace":
            self.m_significantArgs = []
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)


class BatchLetSys_setsockopt(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_setsockopt, self).__init__(batchCore)

        self.m_significantArgs = [self.m_core._return_value]


# socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 6<UNIX:[2038057]>
class BatchLetSys_socket(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_socket, self).__init__(batchCore)

        self.m_significantArgs = [self._strace_stream_to_file(self.m_core._return_value)]


# Different output depending on the tracer:
# strace: connect(6<UNIX:[2038057]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110)
# ltrace: connect@SYS(3, 0x25779f0, 16, 0x1999999999999999)
class BatchLetSys_connect(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_connect, self).__init__(batchCore)
        object_path = self._strace_stream_to_file(self.m_core.m_parsedArgs[0])

        if batchCore.m_tracer == "strace":
            # 09:18:26.465799 socket(PF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_IP) = 3 <0.000013>
            # 09:18:26.465839 connect(3<socket:[535040600]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = 0 <0.000016>

            # TODO: Should link this file descriptor to the IP-addr+port pair.
            # But this is not very important because strace does the job of remapping the file descriptor,
            # so things are consistent as long as we follow the same logic, in the same order:
            #    socket(PF_INET, SOCK_STREAM, IPPROTO_IP) = 3<TCP:[7275805]>
            #    connect(3<TCP:[7275805]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("204.79.197.212")}, 16) = 0
            #    select(4, NULL, [3<TCP:[192.168.0.17:48318->204.79.197.212:80]>], NULL, {900, 0}) = 1
            object_path.SocketAddress = self.m_core.m_parsedArgs[1]

        elif batchCore.m_tracer == "ltrace":
            pass
        else:
            raise Exception("Tracer %s not supported yet" % batchCore.m_tracer)

        self.m_significantArgs = [object_path]


class BatchLetSys_bind(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_bind, self).__init__(batchCore)
        objPath = self._strace_stream_to_file(self.m_core.m_parsedArgs[0])
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

        self.m_significantArgs = self.get_stream_name()


# TODO: If the return value is not zero, maybe reject.
# pipe([3<pipe:[255278]>, 4<pipe:[255278]>]) = 0
class BatchLetSys_pipe(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_pipe, self).__init__(batchCore)

        arrPipes = self.m_core.m_parsedArgs[0]
        arrFil0 = self._strace_stream_to_file(arrPipes[0])
        arrFil1 = self._strace_stream_to_file(arrPipes[1])

        self.m_significantArgs = [arrFil0, arrFil1]


# TODO: If the return value is not zero, maybe reject.
# pipe([3<pipe:[255278]>, 4<pipe:[255278]>]) = 0
class BatchLetSys_pipe2(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_pipe2, self).__init__(batchCore)

        arrPipes = self.m_core.m_parsedArgs[0]
        arrFil0 = self._strace_stream_to_file(arrPipes[0])
        arrFil1 = self._strace_stream_to_file(arrPipes[1])

        self.m_significantArgs = [arrFil0, arrFil1]


class BatchLetSys_shutdown(BatchLetBase, object):
    def __init__(self, batchCore):
        super(BatchLetSys_shutdown, self).__init__(batchCore)

        self.m_significantArgs = self.get_stream_name()


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
        envVal = batchCore._return_value
        if envVal == "nil":
            envVal = ""

        # FIXME: Should have one map per process ?
        cim_objects_definitions.G_EnvironmentVariables[envNam] = envVal

# F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python', '', '4096'] ==>> 7 (16:42:10,16:42:10)
# F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python2', 'python2', '4096'] ==>> 9 (16:42:10,16:42:10)
# F=  4784 {   1/Orig} 'readlink            ' ['/usr/bin/python2.7', 'python2.7', '4096'] ==>> -22 (16:42:10,16:42:10)

################################################################################

class UnfinishedBatches:
    def __init__(self, with_warning):
        # This must be specific to processes.
        # Because when a system call is resumed, it is in the same process.
        self._map_stacks = {}
        self.m_withWarning = with_warning

    # PROBLEM. A vfork() is started in the main process but "appears" in another one.
    # What we could do is infer the main process number when a pid appreas without having been created before.
    # 08:53:31.301860 vfork( <unfinished ...>
    # [pid 23944] 08:53:31.304901 <... vfork resumed> ) = 23945 <0.003032>

    def push_unfinished_batch(self, batchCoreUnfinished):
        # sys.stdout.write("push_unfinished_batch pid=%s _function_name=%s\n"%(batchCoreUnfinished.m_pid,batchCoreUnfinished._function_name))
        try:
            mapByPids = self._map_stacks[batchCoreUnfinished.m_pid]
            try:
                mapByPids[batchCoreUnfinished._function_name].append(batchCoreUnfinished)
            except KeyError:
                mapByPids[batchCoreUnfinished._function_name] = [batchCoreUnfinished]
        except KeyError:
            self._map_stacks[batchCoreUnfinished.m_pid] = {batchCoreUnfinished._function_name: [batchCoreUnfinished]}

        # sys.stdout.write("push_unfinished_batch _function_name=%s\n"%batchCoreUnfinished._function_name)

    def merge_pop_resumed_batch(self, batchCoreResumed):
        # sys.stdout.write("merge_pop_resumed_batch pid=%s _function_name=%s\n"%(batchCoreResumed.m_pid,batchCoreResumed._function_name))
        try:
            stackPerFunc = self._map_stacks[batchCoreResumed.m_pid][batchCoreResumed._function_name]
        except KeyError:
            if self.m_withWarning > 1:
                sys.stdout.write("Resuming %s: cannot find unfinished call\n" % batchCoreResumed._function_name)

            # This is strange, we could not find the unfinished call.
            # sys.stdout.write("merge_pop_resumed_batch NOTFOUND1 _function_name=%s\n"%batchCoreResumed._function_name)
            return None

        # They should have the same pid.
        try:
            batchCoreUnfinished = stackPerFunc[-1]
        except IndexError:
            if self.m_withWarning > 1:
                sys.stdout.write("merge_pop_resumed_batch pid=%d _function_name=%s cannot find call\n"
                                 % (batchCoreResumed.m_pid, batchCoreResumed._function_name))
            # Same problem, we could not find the unfinished call.
            # sys.stdout.write("merge_pop_resumed_batch NOTFOUND2 _function_name=%s\n"%batchCoreResumed._function_name)
            return None

        del stackPerFunc[-1]

        # Sanity check
        if batchCoreUnfinished._function_name != batchCoreResumed._function_name:
            raise Exception("Inconsistency batchCoreUnfinished._function_name=%s batchCoreResumed._function_name=%s\n"
                            % (batchCoreUnfinished._function_name, batchCoreResumed._function_name))

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

    def display_unfinished_unmerged_batches(self, strm):
        if self.m_withWarning == 0:
            return
        for onePid in self._map_stacks:
            # strm.write("onePid=%s\n"%onePid)
            mapPid = self._map_stacks[onePid]

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
                    strm.write("        %s\n" % (batchCoreUnfinished.convert_to_string()))
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


# This executes a Linux command and returns the stderr pipe.
# It is used to get the return content of strace or ltrace, so it can be parsed.
# stderr contains one line for each system function call.
def _generate_linux_stream_from_command(linux_trace_command, process_id):
    def quote_argument(elt):
        # Quotes in command-line arguments must be escaped.
        elt = str(elt).replace('"', '\\"').replace("'", "\\'")
        # Quotes the command-line argument if it contains spaces or tabs.
        if " " in elt or "\t" in elt:
            elt = '"%s"' % elt
        return elt

    command_as_list = [quote_argument(elt) for elt in linux_trace_command]
    assert isinstance(process_id, int)
    sys.stdout.write("Starting trace command:%s\n" % " ".join(command_as_list))

    # If shell=True, the command must be passed as a single line.
    kwargs = {"bufsize":100000, "shell":False,
        "stdin":sys.stdin, "stdout":subprocess.PIPE, "stderr":subprocess.PIPE}
    if sys.version_info >= (3,):
        kwargs["encoding"] = "utf-8"
    object_popen = subprocess.Popen(command_as_list, **kwargs)

    # If shell argument is True, this is the process ID of the spawned shell.
    if process_id > 0:
        # The process already exists and strace/ltrace attaches to it.
        created_process_id = process_id
    else:
        # We want the pid of the process created by strace/ltrace.
        # ltrace always prefixes each line with the pid, so no ambiguity.
        # strace does not always prefixes the top process calls with the pid.
        created_process_id = int(object_popen.pid)

    return created_process_id, object_popen.stderr

################################################################################
# This is set by a signal handler when a control-C is typed.
# It then triggers a clean exit, and creation of output results.
# This allows to monitor a running process, just for a given time
# without stopping it.
G_Interrupt = False

def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    global G_Interrupt
    G_Interrupt = True

# This applies to strace and ltrace.
# The input is a stream of lines coming from strace or ltrace.
# It isolates single lines describing an individual function or system call.
# This yields objects which model a function call.
def _create_flows_from_generic_linux_log(logStream, tracer):
    # Generates output files if interrupt with control-C.
    original_sigint_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal_handler)
    logging.info('Press Ctrl+C to exit cleanly')

    # "[pid 18196] 08:26:47.199313 close(255</tmp/shell.sh> <unfinished ...>"
    # "08:26:47.197164 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 18194 <0.011216>"
    # This test is not reliable because we cannot really control what a spurious output can be:
    def _is_log_ending(trace_line):
        if trace_line.endswith(">\n"):
            ixLT = trace_line.rfind("<")
            if ixLT >= 0:
                strBrack = trace_line[ixLT + 1:-2]
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
            if trace_line.startswith("[pid ") and trace_line.endswith(" = ?\n"):
                return True

            # "08:26:47.197304 --- SIGCHLD {si_signo=SIGCHLD, si_status=0, si_utime=0, si_stime=0} ---"
            # Not reliable because this could be a plain string ending like this.
            if trace_line.endswith(" ---\n"):
                return True

        return False


    # This is parsed from each line corresponding to a syztem call.
    batchCore = None

    last_time_stamp = 0

    line_number = 0
    one_new_line = ""
    while True:
        previous_line = one_new_line
        one_new_line = ""

        # There are several cases of line ending with strace.
        # If a function has a string parameter which contain a carriage-return,
        # this is not filtered and this string is split on multiple lines.
        # We cannot reliably count the double-quotes.
        # FIXME: Problem if several processes.
        while not G_Interrupt:
            # sys.stdout.write("000:\n")
            tmpLine = logStream.readline()
            # sys.stdout.write("AAA:%s"%tmpLine)
            line_number += 1
            # sys.stdout.write("tmpLine after read=%s"%tmpLine)
            if not tmpLine:
                break

            # "[pid 18196] 08:26:47.199313 close(255</tmp/shell.sh> <unfinished ...>"
            # "08:26:47.197164 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 18194 <0.011216>"
            # This test is not reliable because we cannot really control what a spurious output can be:
            if _is_log_ending(tmpLine):
                # TODO: The most common case is that the call is on one line only.
                one_new_line += tmpLine
                break

            # If the call is split on several lines, maybe because a write() contains a "\n".
            one_new_line += tmpLine[:-1]

        if not one_new_line:
            # If this is the last line and therefore the last call.
            sys.stdout.write("Last line=%s\n" % previous_line)

            # This is the terminate date of the last process still running.
            if last_time_stamp:
                cim_objects_definitions.CIM_Process.GlobalTerminationDate(last_time_stamp)

            break

        # This parses the line into the basic parameters of a function call.
        try:
            batchCore = CreateBatchCore(one_new_line,tracer)
        except Exception as exc:
            if line_number == 2:
                # If the command does not exist:
                # "strace: Can't stat 'qklsjhdflksd': No such file or directory"
                # "Can't open qklsjhdflksd: No such file or directory"
                if one_new_line.find("No such file or directory") >= 0:
                    raise Exception("Invalid command: %s: %s" % (one_new_line, exc))

                # If the pid is invalid, the scond contains "No such process"
                # "strace: attach: ptrace(PTRACE_SEIZE, 11111): No such process"
                # "Cannot attach to pid 11111: No such process"
                if one_new_line.find("No such process") >= 0:
                    raise Exception("Invalid process id: %s" % exc)

            sys.stderr.write("ERROR '%s' Caught invalid line %d:%s\n" % (exc, line_number, one_new_line))

        # Maybe the line cannot be parsed.
        if batchCore:
            last_time_stamp = batchCore._time_end

            # This creates a derived class deduced from the system call.
            try:
                new_batchlet = _batchlet_factory(batchCore)
            except Exception as exc:
                sys.stderr.write("ERROR '%s' Line:%d Error parsing:%s" % (exc, line_number, one_new_line))

            # Some functions calls should simply be forgotten because there are
            # no side effects, so simply forget them.
            if new_batchlet:
                yield new_batchlet

    logging.info("Restoring SIGINT handler")
    signal.signal(signal.SIGINT, original_sigint_handler)

################################################################################

#
# 22:41:05.094710 rt_sigaction(SIGRTMIN, {0x7f18d70feb20, [], SA_RESTORER|SA_SIGINFO, 0x7f18d7109430}, NULL, 8) = 0 <0.000008>
# 22:41:05.094841 rt_sigaction(SIGRT_1, {0x7f18d70febb0, [], SA_RESTORER|SA_RESTART|SA_SIGINFO, 0x7f18d7109430}, NULL, 8) = 0 <0.000018>
# 22:41:05.094965 rt_sigprocmask(SIG_UNBLOCK, [RTMIN RT_1], NULL, 8) = 0 <0.000007>
# 22:41:05.095113 getrlimit(RLIMIT_STACK, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0 <0.000008>
# 22:41:05.095350 statfs("/sys/fs/selinux", 0x7ffd5a97f9e0) = -1 ENOENT (No such file or directory) <0.000019>
#
# The command parameters and the parsing are specific to strace.
# It returns a data structure which is generic.

################################################################################

# Max bytes number when strace or ltrace display read() and write() calls.
G_StringSize = "500"

class GenericTraceTracer:
    def tee_calls_stream(self, log_stream, output_files_prefix):
        class TeeStream:
            def __init__(self):
                self._log_stream = log_stream
                assert output_files_prefix[-1] != '.'
                log_filename = output_files_prefix + ".log"
                self._out_file_descriptor = open(log_filename, "w")
                print("Creating log file:%s" % log_filename)

            def readline(self):
                duplicate_line = self._log_stream.readline()
                # sys.stdout.write("tee=%s" % aLin)
                # This is will be read during a replay session.
                self._out_file_descriptor.write(duplicate_line)
                return duplicate_line

        calls_stream = TeeStream()
        return calls_stream

    # This returns a pair of a process id and a stream of lines, each modelling a function call.
    def create_logfile_stream(self, external_command, process_id):
        trace_command = self.build_trace_command(external_command, process_id)
        if external_command:
            logging.info("Command " + " ".join(external_command))
        else:
            logging.info("Process %s\n" % process_id)
        return _generate_linux_stream_from_command(trace_command, process_id)

    # Used when replaying a trace session. This returns an object, on which each read access
    # return a conceptual function call, similar to what is returned when monitoring a process.
    # For Linux, strace and ltrace returns one line for each function call.
    # To replay these sessions, these lines are saved as is in a text file,
    # which just needs to be open and read when replying a session.
    def logfile_pathname_to_stream(self, input_log_file):
        return open(input_log_file)


class STraceTracer(GenericTraceTracer):
    # The command options generate a specific output file format,
    # and therefore parsing it is specific to these options.
    def build_trace_command(self, external_command, aPid):
        # -f  Trace  child  processes as a result of the fork, vfork and clone.
        trace_command = ["strace", "-q", "-qq", "-f", "-tt", "-T", "-s", G_StringSize]

        if self.deprecated_version():
            trace_command += ["-e", "trace=desc,ipc,process,network"]
        else:
            trace_command += ["-y", "-yy", "-e", "trace=desc,ipc,process,network,memory"]

        if external_command:
            # Run tracer process as a detached grandchild, not as parent of the tracee. This reduces the visible
            # effect of strace by keeping the tracee a direct child of the calling process.
            trace_command += ["-D"]
            trace_command += external_command
        else:
            trace_command += ["-p", aPid]
        return trace_command

    def deprecated_version(self):
        # (4,21) is OK
        # (4,5,19) does not have the option "-y".
        return self.trace_software_version() < (4, 11)

    # This yields objects which model a function call.
    def create_flows_from_calls_stream(self, log_stream):
        return _create_flows_from_generic_linux_log(log_stream, "strace")

    def trace_software_version(self):
        # "strace -- version 4.21"
        strace_version_str = subprocess.check_output('strace -V', shell=True).split()[3]
        return tuple(map(int, strace_version_str.split(b'.')))


class LTraceTracer(GenericTraceTracer):
    # The command options generate a specific output file format,
    # and therefore parsing it is specific to these options.
    def build_trace_command(self, external_command, aPid):
        # This selects:
        # libpython2.7.so.1.0->getenv, cx_Oracle.so->getenv, libclntsh.so.11.1->getenv, libresolv.so.2->getenv etc...
        strMandatoryLibc = "-*+getenv+*@SYS"

        # TODO: Consider filtering read.
        # -S  Display system calls as well as library calls
        # -f  Trace  child  processes as a result of the fork, vfork and clone.
        # This needs long strings because path names are truncated like normal strings.
        trace_command = [
            "ltrace",
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

        if external_command:
            trace_command += external_command
        else:
            trace_command += ["-p", aPid]

        return trace_command

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

    def create_flows_from_calls_stream(self, logStream):
        # The output format of the command ltrace seems very similar to strace
        # so for the moment, no reason not to use it.
        return _create_flows_from_generic_linux_log(logStream, "ltrace")

    def trace_software_version(self):
        # "ltrace version 0.5."
        # "ltrace 0.7.91"
        # 0.7.3 on Travis.
        ltrace_version_bytes = subprocess.check_output('ltrace -V', shell=True).split(b'\n')[0].split()[-1]
        ltrace_version_str = ltrace_version_bytes.decode()
        if ltrace_version_str[-1] == '.':
            ltrace_version_str = ltrace_version_str[:-1]
        return tuple(map(int, ltrace_version_str.split('.')))

