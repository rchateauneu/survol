# This is needed to avoid the message:
# "Hint: make sure your test modules/packages have valid Python names"
# Confusing and incomplete explanation here:
# https://stackoverflow.com/questions/41748464/pytest-cannot-import-module-while-python-can

import os
import sys
import socket
import psutil
import pkgutil

CurrentMachine = socket.gethostname().lower()
try:
    CurrentUsername = os.environ["USERNAME"]
    # The class of users is different on Linux and Windows.
    #CurrentUserPath = "Win32_UserAccount.Name=%s,Domain=localhost" % CurrentUsername
    CurrentUserPath = "Win32_UserAccount.Name=%s,Domain=%s" % (CurrentUsername, CurrentMachine)
except KeyError:
    # This is for Linux.
    CurrentUsername = os.environ["USER"]
    #CurrentUserPath = "LMI_Account.Name=%s,Domain=localhost" % CurrentUsername
    CurrentUserPath = "LMI_Account.Name=%s,Domain=%s" % (CurrentUsername, CurrentMachine)

CurrentPid = os.getpid()
CurrentProcessPath = 'CIM_Process.Handle=%d' % CurrentPid
CurrentParentPid = psutil.Process().ppid()

# For example /usr/bin/python2.7
# Typical situation of symbolic links:
# /usr/bin/python => python2 => python2.7
# Several Python scripts return this executable as a node.
execPath = os.path.realpath( sys.executable )
if sys.platform.startswith("win"):
    # When running in PyCharm with virtualenv, the path is correct:
    # "C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/venv/Scripts/python.exe"
    # When running from pytest, it is converted to lowercase.
    # "c:/python27/python.exe" instead of "C:/Python27/python.exe"
    #
    # But it is not possible at this stage, to detect if we run in pytest,
    # because the environment variable 'PYTEST_CURRENT_TEST' is not set yet;
    # 'PYTEST_CURRENT_TEST': 'tests/test_client_library.py::SurvolLocalTest::test_process_cwd (call)'

    try:
        import win32api
        execPath = win32api.GetLongPathName(win32api.GetShortPathName(execPath))

        # The drive must be in uppercase too:
        execPath = execPath[0].upper() + execPath[1:]
    except ImportError:
        # Here we cannot do anything.
        pass


    execPath = execPath.replace("\\","/"),

CurrentExecutablePath = 'CIM_DataFile.Name=%s' % execPath

# https://stackoverflow.com/questions/46978624/python-multiprocessing-process-to-use-virtualenv
print(__file__+" sys.execPath=%s" % execPath)
print(__file__+" sys.executable=%s" % sys.executable)
print(__file__+" sys.exec_prefix=%s" % sys.exec_prefix)

def ServerDumpContent(log_filename):
    sys.stdout.write("Agent log file: %s\n" % log_filename)
    try:
        agent_stream = open(log_filename)
        for line_stream in agent_stream:
            sys.stdout.write(">>> %s" % line_stream)
        agent_stream.close()
        sys.stdout.write("Agent log file end\n")
    except Exception as exc:
        sys.stdout.write("No agent log file:%s\n" % exc)

def is_pytest():
    print("argv=",sys.argv)
    for one_arg in sys.argv:
        if one_arg.find("pytest") >= 0:
            return True
    return False

# This tests if an executable is present.
def linux_check_program_exists(program_name):
    import subprocess
    p = subprocess.Popen(['/usr/bin/which', program_name], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    p.communicate()
    return p.returncode == 0

def is_travis_machine():
    # /home/travis/build/rchateauneu/survol : See "lib_credentials.py" for the same test.
    # Some tests cannot be run on a Travis machine if some tools are not there.
    return os.getcwd().find("travis") >= 0

def is_linux_wbem():
    # WBEM is not available on TravisCI.
    return sys.platform.startswith("linux") and pkgutil.find_loader('pywbem') and not is_travis_machine()


# This defines a file which is present on all platforms.
if sys.platform.startswith("linux"):
    FileAlwaysThere = "/etc/hosts"
    DirAlwaysThere = "/etc"
    AnyLogicalDisk = ""
else:
    FileAlwaysThere = "C:\\Windows\\explorer.exe"
    DirAlwaysThere = "C:\\Windows"
    AnyLogicalDisk = "D:"
