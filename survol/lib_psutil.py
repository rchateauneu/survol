# Replacement of psutil if it cannot be installed (mutualised hosting, embedded hardware etc...)

import os
import sys
import lib_common
import lib_util

################################################################################

import psutil

from psutil import NoSuchProcess
from psutil import AccessDenied
################################################################################

def PsutilGetProcObj(pid):
    # Very often, a process vanishes quickly so this error happens often.
    try:
        return psutil.Process(pid)
    except NoSuchProcess:
        lib_common.ErrorMessageHtml("No such process:"+str(pid))


# If psutil is not available, consider "getpass.getuser()"
# This returns the username, not prefixed by the hostname.
def GetCurrentUser():
    currProc = PsutilGetProcObj(os.getpid())
    # u'rchateau-HP\\rchateau' on Windows and 'rchateau' on Linux.
    psUser = PsutilProcToUser(currProc)
    # This truncates the hostname if there is one.
    # We do not want the hostname but instead the SERVER_NAME,
    # which is "LCOALHOST" when running locally this library in lib_client.py
    if lib_util.isPlatformWindows:
        psUser = psUser.rpartition("\\")[2]
    return psUser


# https://pythonhosted.org/psutil/
# rss: this is the non-swapped physical memory a process has used.
# On UNIX it matches "top" RES column (see doc).
# On Windows this is an alias for wset field and it matches "Mem Usage" column of taskmgr.exe.
def PsutilResidentSetSize(proc):
    return lib_util.AddSIUnit(proc.memory_info().rss,"B")


# https://pythonhosted.org/psutil/
# vms: this is the total amount of virtual memory used by the process.
# On UNIX it matches "top" VIRT column (see doc).
# On Windows this is an alias for pagefile field and it matches "Mem Usage" "VM Size" column of taskmgr.exe.
def PsutilVirtualMemorySize(proc):
    return lib_util.AddSIUnit(proc.memory_info().vms,"B")

################################################################################


def PsutilProcToName(proc):
    procNam = proc.name()
    # Very often, the process name will just be the executable file name.
    # So we shorten because it is nicer.
    if procNam.upper().endswith(".EXE"):
        procNam = procNam[:-4]
    return procNam


def PsutilProcToUser(proc, dflt_user="AccessDenied"):
    try:
        return proc.username()
    except AccessDenied:
        return dflt_user
    except KeyError:
        # This does not make sense but it happens.
        # KeyError: 'getpwuid(): uid not found: 56413'
        return "usr" + str(proc.pid)


def PsutilProcToExe(proc):
    try:
        return (proc.exe(), "")
    except AccessDenied:
        return ("", "Access denied")


def PsutilProcToCmdlineArray(proc):
    try:
        return proc.cmdline()
    except AccessDenied:
        return ["Access denied"]


def PsutilProcToCmdline(proc):
    cmd_arr = PsutilProcToCmdlineArray(proc)

    cmd_line = ' '.join(cmd_arr)
    # There might be non-printable characters.
    if not lib_util.is_py3:
        cmd_line = cmd_line.decode("ascii", errors="ignore")
    return cmd_line


def PsutilProcConnections(proc, kind='inet'):
    try:
        return proc.connections(kind)
    except AccessDenied:
        return []


def PsutilProcCwd(proc):
    """Returns the current working directory."""
    try:
        proc_cwd = proc.cwd()
        proc_msg = None
    except AccessDenied:
        proc_cwd = None
        proc_msg = "Process %d: Cannot get current working directory: %s" % (proc.pid, str(sys.exc_info()))

    return (proc_cwd, proc_msg)

