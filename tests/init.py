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

# "vps516494.localdomain": "http://vps516494.ovh.net/Survol/survol" }[CurrentMachine]
# Name = "vps516494.ovh.net")
SurvolServerHostname = "vps516494.ovh.net"
SurvolServerAgent = "http://vps516494.ovh.net/Survol/survol"

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

is_platform_windows = sys.platform.startswith("win")
is_platform_linux = sys.platform.startswith("linux")


def is_linux_wbem():
    # WBEM is not available on TravisCI.
    return is_platform_linux and pkgutil.find_loader('pywbem') and not is_travis_machine()


# This loads the module from the source, so no need to install it, and no need of virtualenv.
def update_test_path():
    sys.path.insert(0,"../survol")

# This defines a file which is present on all platforms.
if is_platform_linux:
    FileAlwaysThere = "/etc/hosts"
    DirAlwaysThere = "/etc"
    AnyLogicalDisk = ""
else:
    FileAlwaysThere = "C:\\Windows\\explorer.exe"
    DirAlwaysThere = "C:\\Windows"
    AnyLogicalDisk = "D:"

import atexit
import time

def CgiAgentStart(agent_url, agent_port):
    INFO("CgiAgentStart agent_url=%s agent_port=%d", agent_url, agent_port)
    try:
        # For Python 3.0 and later
        from urllib.request import urlopen as portable_urlopen
    except ImportError:
        # Fall back to Python 2's urllib2
        from urllib2 import urlopen as portable_urlopen

    try:
        agent_process = None
        response = portable_urlopen(agent_url + "/survol/entity.py", timeout=5)
        INFO("CgiAgentStart: Using existing CGI Survol agent")
    except:
        import multiprocessing
        INFO("CgiAgentStart: agent_url=%s agent_port=%d hostname=%s", agent_url, agent_port, socket.gethostname())

        import scripts.cgiserver
        # cwd = "PythonStyle/tests", must be "PythonStyle".
        # AgentHost = "127.0.0.1"
        AgentHost = socket.gethostname()
        try:
            # Running the tests scripts from PyCharm is from the current directory.
            os.environ["PYCHARM_HELPERS_DIR"]
            current_dir = ".."
        except KeyError:
            current_dir = ""
        INFO("CgiAgentStart: current_dir=%s", current_dir)
        #print("sys.path=",sys.path)
        agent_process = multiprocessing.Process(
            target=scripts.cgiserver.StartParameters,
            args=(True, AgentHost, agent_port, current_dir))

        atexit.register(ServerDumpContent, scripts.cgiserver.CgiServerLogFileName )

        agent_process.start()
        INFO("CgiAgentStart: Waiting for CGI agent to start")
        time.sleep(5.0)
        local_agent_url = "http://%s:%s/survol/entity.py" % (AgentHost, agent_port)
        try:
            response = portable_urlopen( local_agent_url, timeout=5)
        except Exception as exc:
            ERROR("Caught:%s", exc)
            ServerDumpContent(scripts.cgiserver.CgiServerLogFileName)
            raise

    data = response.read().decode("utf-8")
    INFO("CGI Survol agent OK")
    return agent_process


def CgiAgentStop(agent_process):
    print("tearDownModule")
    if agent_process:
        agent_process.terminate()
        agent_process.join()

def WsgiAgentStart(agent_url, agent_port):
    print("setUpModule")
    try:
        # For Python 3.0 and later
        from urllib.request import urlopen as portable_urlopen
    except ImportError:
        # Fall back to Python 2's urllib2
        from urllib2 import urlopen as portable_urlopen

    try:
        # No SVG because Travis might not have dot/Graphviz. Also, the script must be compatible with WSGI.
        agent_process = None
        response = portable_urlopen(agent_url + "/survol/entity.py?mode=json", timeout=5)
        INFO("WsgiAgentStart: Using existing WSGI Survol agent")
    except:
        import multiprocessing
        INFO("Starting test survol agent_url=%s hostnqme=%s", agent_url, socket.gethostname())

        import scripts.wsgiserver
        # cwd = "PythonStyle/tests", must be "PythonStyle".
        # AgentHost = "127.0.0.1"
        AgentHost = socket.gethostname()
        try:
            # Running the tests scripts from PyCharm is from the current directory.
            os.environ["PYCHARM_HELPERS_DIR"]
            current_dir = ".."
        except KeyError:
            current_dir = ""
        INFO("current_dir=%s",current_dir)
        INFO("sys.path=%s",str(sys.path))

        atexit.register(ServerDumpContent,scripts.wsgiserver.WsgiServerLogFileName )

        agent_process = multiprocessing.Process(
            target=scripts.wsgiserver.StartWsgiServer,
            args=(AgentHost, agent_port, current_dir))
        agent_process.start()
        INFO("Waiting for WSGI agent ready")
        time.sleep(8.0)
        # Check again if the server is started. This can be done only with scripts compatible with WSGI.
        local_agent_url = "http://%s:%s/survol/entity.py?mode=json" % (AgentHost, agent_port)
        try:
            response = portable_urlopen( local_agent_url, timeout=5)
        except Exception as exc:
            ERROR("Caught:", exc)
            ServerDumpContent( scripts.wsgiserver.WsgiServerLogFileName )
            raise

    data = response.read().decode("utf-8")
    print("WSGI Survol agent OK")
    return agent_process

def WsgiAgentStop(agent_process):
    print("tearDownModule")
    if agent_process:
        agent_process.terminate()
        agent_process.join()

