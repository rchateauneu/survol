# This is needed to avoid the message:
# "Hint: make sure your test modules/packages have valid Python names"
# Confusing and incomplete explanation here:
# https://stackoverflow.com/questions/41748464/pytest-cannot-import-module-while-python-can

from __future__ import print_function

import os
import sys
import json
import socket
import psutil
import pkgutil
import atexit
import time
import tempfile
import subprocess

import scripts.cgiserver

################################################################################

is_platform_windows = sys.platform.startswith("win")
is_platform_linux = sys.platform.startswith("linux")

is_py3 = sys.version_info >= (3,)

if is_platform_windows:
    import win32process
    import win32con

# os.sys.getwindowsversion()
# sys.getwindowsversion(major=6, minor=1, build=7601, platform=2, service_pack='Service Pack 1')
# platform.release()
# '7'
# platform.win32_ver()
# ('7', '6.1.7601', 'SP1', 'Multiprocessor Free')

def is_travis_machine():
    # /home/travis/build/rchateauneu/survol : See "lib_credentials.py" for the same test.
    # Some tests cannot be run on a Travis machine if some tools are not there.
    return os.getcwd().find("travis") >= 0

# Some tests start a DOS box process. The processes application is checked.
windows_system32_cmd_exe = r'C:\Windows\system32\cmd.exe' if is_travis_machine() else r'C:\windows\system32\cmd.exe'

# "vps516494.localdomain": "http://vps516494.ovh.net/Survol/survol" }[CurrentMachine]
# Name = "vps516494.ovh.net")
SurvolServerHostname = "vps516494.ovh.net"
SurvolServerAgent = "http://vps516494.ovh.net:80/Survol"
SurvolWbemCimom = "http://vps516494.ovh.net:5988"

################################################################################

CurrentMachine = socket.gethostname().lower()
try:
    CurrentUsername = os.environ["USERNAME"]
    # The class of users is different on Linux and Windows.
    CurrentUserPath = "Win32_UserAccount.Name=%s,Domain=%s" % (CurrentUsername, CurrentMachine)
except KeyError:
    # This is for Linux.
    CurrentUsername = os.environ["USER"]
    CurrentUserPath = "LMI_Account.Name=%s,Domain=%s" % (CurrentUsername, CurrentMachine)

CurrentPid = os.getpid()
CurrentProcessPath = 'CIM_Process.Handle=%d' % CurrentPid
CurrentParentPid = psutil.Process().ppid()

# TODO: This should be a parameter.
# It points to the Survol adhoc CGI server: "http://rchateau-hp:8000"
RemoteTestPort = 8000
RemoteTestAgent = "http://%s:%d" % (CurrentMachine, RemoteTestPort)
RemoteEventsTestPort = 8001
RemoteEventsTestAgent = "http://%s:%d" % (CurrentMachine, RemoteEventsTestPort)
RemoteSparqlServerPort = 8002
RemoteSparqlServerAgent = "http://%s:%d" % (CurrentMachine, RemoteSparqlServerPort)


# For example /usr/bin/python2.7
# Typical situation of symbolic links:
# /usr/bin/python => python2 => python2.7
# Several Python scripts return this executable as a node.
CurrentExecutable = os.path.realpath(sys.executable)
if is_platform_windows:
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
        CurrentExecutable = win32api.GetLongPathName(win32api.GetShortPathName(CurrentExecutable))

        # The drive must be in uppercase too:
        CurrentExecutable = CurrentExecutable[0].upper() + CurrentExecutable[1:]
        # sys.stderr.write(__file__ + " Fixed sys.executable:%s\n" % CurrentExecutable)
    except ImportError:
        # Here we cannot do anything.

        # https://stackoverflow.com/questions/27465610/how-can-i-get-the-proper-capitalization-for-a-path
        # This is an undocumented function, for Python 3 only.
        # os.path._getfinalpathname("c:/python27/python.exe") => '\\\\?\\C:\\Python27\\python.exe'
        # os.path._getfinalpathname("c:/python27/python.exe").lstrip(r'\?') => 'C:\\Python27\\python.exe'
        CurrentExecutable = os.path._getfinalpathname(CurrentExecutable).lstrip(r'\?')
        sys.stderr.write(__file__ + " Cannot import win32api to fix sys.executable:%s\n" % CurrentExecutable)

    CurrentExecutable = CurrentExecutable.replace("\\","/")

CurrentExecutablePath = 'CIM_DataFile.Name=%s' % CurrentExecutable

def __dump_server_content(log_filename):
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
    p = subprocess.Popen(['/usr/bin/which', program_name], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    p.communicate()
    return p.returncode == 0

# Problem on Travis: Domain = 'PACKER-5D93E860', machine='packer-5d93e860-43ba-c2e7-85d2-3ea0696b8fc8'
if is_platform_windows:
    if is_travis_machine():
        # FIXME: Horrible temporary hard-code.
        # TODO:
        # wmi.WMI().CIM_ComputerSystem()[0].Name
        # u'RCHATEAU-HP'
        #  wmi.WMI().CIM_ComputerSystem()[0].Workgroup
        # u'WORKGROUP'
        # For example: 'packer-5d93e860-43ba-c2e7-85d2-3ea0696b8fc8'
        split_machine = CurrentMachine.lower().split('-')
        assert split_machine[0] == 'packer'
        # For example: 'packer-5d93e860'
        CurrentDomainWin32 = split_machine[0] + '-' + split_machine[1]
    else:
        CurrentDomainWin32 = CurrentMachine.lower()

def is_linux_wbem():
    # WBEM is not available on TravisCI.
    return is_platform_linux and has_wbem() and not is_travis_machine()

def has_wbem():
    # WBEM is not available on TravisCI.
    return False
    # Temporarily disable WBEM because firewall blocks wbem port.
    return pkgutil.find_loader('pywbem')


# This loads the module from the source, so no need to install it, and no need of virtualenv.
def update_test_path():
    if sys.path[0] != "../survol":
        sys.path.insert(0,"../survol")

def unique_temporary_path(prefix, extension):
    temp_file = "%s_%d_%d%s" % (prefix, CurrentPid, int(time.time()), extension)
    temp_path = os.path.join(tempfile.gettempdir(), temp_file)
    return temp_path

################################################################################

# This defines a file and a directory present on all platforms, for testing.
# This is deprecated and should be replaced by "always_present_*" constants.
if is_platform_linux:
    AnyLogicalDisk = ""
else:
    if is_travis_machine():
        AnyLogicalDisk = "C:"
    else:
        AnyLogicalDisk = "D:"

# These files are garanteed to exist, so it is possible to rely on this assumption.

# https://stackoverflow.com/questions/7783308/os-path-dirname-file-returns-empty
absolute_dir = os.path.dirname(os.path.abspath(__file__))
always_present_dir = os.path.join(absolute_dir, "SampleDir")
always_present_file = os.path.join(absolute_dir, "SampleDir", "SampleFile.txt")
always_present_sub_dir = os.path.join(absolute_dir, "SampleDir", "SampleSubDir")
always_present_sub_file = os.path.join(absolute_dir, "SampleDir", "SampleSubDir", "SampleSubFile.txt")
# This is necessary for some tests.
assert always_present_file.startswith(always_present_dir)
assert always_present_sub_dir.startswith(always_present_dir)
assert always_present_sub_file.startswith(always_present_sub_dir)

################################################################################

# See lib_util.survol_urlopen
try:
    # For Python 3.0 and later
    from urllib.request import urlopen as portable_urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen as portable_urlopen

# FIXME: BEWARE: The subprocess should not inherit the handles because
# FIXME: ... with Python 3, when communicating with sockets, it does not work,
# FIXME: ... losing characters...
def _start_cgiserver_subprocess_windows(agent_url, agent_port, current_dir):
    print("_start_cgiserver_subprocess_windows: agent_url=%s agent_port=%d hostname=%s" % (agent_url, agent_port, socket.gethostname()))

    # cwd = "PythonStyle/tests", must be "PythonStyle".
    # agent_host = "127.0.0.1"
    agent_host = socket.gethostname()

    cgiserver_module = "survol.scripts.cgiserver"
    cgi_command_str = sys.executable + ' -c "import %s as ssc;ssc.start_server_forever(True,\'%s\',%d,\'%s\')"' % (
            cgiserver_module, agent_host, agent_port, current_dir)
    print("cgi_command=", cgi_command_str)

    start_info = win32process.STARTUPINFO()
    start_info.dwFlags = win32con.STARTF_USESHOWWINDOW

    current_abs_dir = os.path.abspath(current_dir)

    hProcess, hThread, dwProcessId, dwThreadId = win32process.CreateProcess(
        None,  # appName
        cgi_command_str,  # commandLine
        None,  # processAttributes
        None,  # threadAttributes
        False,  # bInheritHandles
        win32con.CREATE_NEW_CONSOLE,  # dwCreationFlags
        None,  # newEnvironment
        current_abs_dir,  # currentDirectory
        start_info)  # startupinfo

    class AgentProcess(object):
        def __init__(self, hProcess):
            self._process_handle = hProcess
        def terminate(self):
            win32process.TerminateProcess(self._process_handle, 0)
        def join(self):
            pass

    agent_process = AgentProcess(hProcess)
    return agent_process


def _start_cgiserver_subprocess_portable_OLD(agent_url, agent_port, current_dir):
    # cwd = "PythonStyle/tests", must be "PythonStyle".
    # agent_host = "127.0.0.1"
    agent_host = socket.gethostname()

    cgiserver_module = "survol.scripts.cgiserver"
    cgi_command = [
        sys.executable,
        "-c",
        'import %s as ssc;ssc.start_server_forever(True,\'%s\',%s,\'%s\')' % (
            cgiserver_module, agent_host, agent_port, current_dir)
    ]
    print("cgi_command=", " ".join(cgi_command))
    agent_process = subprocess.Popen(cgi_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    print("agent_process.returncode=", agent_process.returncode)
    print("agent_process.pid=", agent_process.pid)
    #(cmd_output, cmd_error) = agent_process.communicate()
    #print("cmd_output=", cmd_output)
    #print("cmd_error=", cmd_error)

    return agent_process


def _start_cgiserver_subprocess_portable(agent_url, agent_port, current_dir):
    # cwd = "PythonStyle/tests", must be "PythonStyle".
    # agent_host = "127.0.0.1"
    import multiprocessing

    agent_host = socket.gethostname()
    agent_process = multiprocessing.Process(
        target=scripts.cgiserver.start_server_forever,
        args=(True, agent_host, agent_port, current_dir))
    agent_process.start()

    print("agent_process.pid=", agent_process.pid)

    return agent_process


def _start_cgiserver_subprocess(agent_url, agent_port):
    print("_start_cgiserver_subprocess: agent_url=%s agent_port=%d hostname=%s" % (agent_url, agent_port, socket.gethostname()))
    try:
        # Running the tests scripts from PyCharm is from the current directory.
        os.environ["PYCHARM_HELPERS_DIR"]
        current_dir = ".."
    except KeyError:
        current_dir = ""
    if is_platform_windows:
        return _start_cgiserver_subprocess_windows(agent_url, agent_port, current_dir)
    else:
        return _start_cgiserver_subprocess_portable(agent_url, agent_port, current_dir)


def start_cgiserver(agent_url, agent_port):
    print("start_cgiserver agent_url=%s agent_port=%d" % (agent_url, agent_port))

    # The CGI agent creates a log file, the old one must be removed first.
    logfile_name = scripts.cgiserver.cgi_server_logfile_name(agent_port)
    if os.path.exists(logfile_name):
        try:
            os.remove(logfile_name)
        except:
            print("Cannot remove", logfile_name)

    # agent_host = "127.0.0.1"
    agent_host = socket.gethostname()
    try:
        agent_process = None
        response = portable_urlopen(agent_url + "/survol/print_internal_data_as_json.py", timeout=2)
        print("start_cgiserver: Using existing CGI Survol agent")
    except:
        agent_process = _start_cgiserver_subprocess(agent_url, agent_port)
        print("_start_cgiserver_subprocess: Waiting for CGI agent to start")
        # This delay to allow the reuse of the socket port.
        # TODO: A better solution would be to override server_bind()
        time.sleep(0.5)
        atexit.register(__dump_server_content, logfile_name)

        # It was using "entity.py" in the past, but it is slower.
        local_agent_url = "http://%s:%s/survol/print_internal_data_as_json.py" % (agent_host, agent_port)
        print("start_cgiserver local_agent_url=", local_agent_url)
        try:
            response = portable_urlopen(local_agent_url, timeout=5)
        except Exception as exc:
            print("Caught:%s", exc)
            __dump_server_content(logfile_name)
            raise

    internal_data = response.read().decode("utf-8")
    json_internal_data = json.loads(internal_data)

    # RootUri	"http://rchateau-hp:8000/survol/print_internal_data_as_json.py"
    # uriRoot	"http://rchateau-hp:8000/survol"
    # HttpPrefix	"http://rchateau-hp:8000"
    # RequestUri	"/survol/print_internal_data_as_json.py"
    root_uri = json_internal_data['RootUri']
    uri_root = json_internal_data['uriRoot']
    http_prefix = json_internal_data['HttpPrefix']
    request_uri = json_internal_data['RequestUri']

    print("CGI Survol agent OK:", root_uri, uri_root, http_prefix, request_uri)
    return agent_process

def stop_cgiserver(agent_process):
    if agent_process:
        agent_process.terminate()
        agent_process.join()

def start_wsgiserver(agent_url, agent_port):
    try:
        # No SVG because Travis might not have dot/Graphviz. Also, the script must be compatible with WSGI.
        agent_process = None
        response = portable_urlopen(agent_url + "/survol/entity.py?mode=json", timeout=5)
        INFO("start_wsgiserver: Using existing WSGI Survol agent")
    except:
        import multiprocessing
        INFO("Starting test survol agent_url=%s hostnqme=%s", agent_url, socket.gethostname())

        import scripts.wsgiserver
        # cwd = "PythonStyle/tests", must be "PythonStyle".
        # AgentHost = "127.0.0.1"
        agent_host = socket.gethostname()
        try:
            # Running the tests scripts from PyCharm is from the current directory.
            os.environ["PYCHARM_HELPERS_DIR"]
            current_dir = ".."
        except KeyError:
            current_dir = ""
        INFO("current_dir=%s",current_dir)
        INFO("sys.path=%s",str(sys.path))

        agent_process = multiprocessing.Process(
            target=scripts.wsgiserver.start_server_forever,
            args=(True, agent_host, agent_port, current_dir))
        agent_process.start()
        atexit.register(__dump_server_content, scripts.wsgiserver.WsgiServerLogFileName)
        INFO("Waiting for WSGI agent ready")
        time.sleep(8.0)
        # Check again if the server is started. This can be done only with scripts compatible with WSGI.
        local_agent_url = "http://%s:%s/survol/entity.py?mode=json" % (agent_host, agent_port)
        try:
            response = portable_urlopen( local_agent_url, timeout=5)
        except Exception as exc:
            ERROR("Caught:", exc)
            __dump_server_content(scripts.wsgiserver.WsgiServerLogFileName)
            raise

    data = response.read().decode("utf-8")
    print("WSGI Survol agent OK")
    return agent_process

def stop_wsgiserver(agent_process):
    print("tearDownModule")
    if agent_process:
        agent_process.terminate()
        agent_process.join()

################################################################################

update_test_path()

# The query function from lib_sparql module, returns RDF nodes.
# This is not very convenient to test.
# Therefore, for tests, this is a helper function which returns dict of strings,
# which are easier to compare.
def __queries_entities_to_value_pairs(iter_entities_dicts):
    import lib_properties

    for one_entities_dict in iter_entities_dicts:

        one_entities_dict_qname = {}
        for variable_name, one_entity in one_entities_dict.items():
            #print("__queries_entities_to_value_pairs one_entity=", one_entity)

            # Special attribute for debugging.
            dict_qname_value = {"__class__": one_entity.m_entity_class_name}
            for key_node, val_node in one_entity.m_predicate_object_dict.items():
                qname_key = lib_properties.PropToQName(key_node)
                str_val = str(val_node)
                dict_qname_value[qname_key] = str_val
            one_entities_dict_qname[variable_name] = dict_qname_value
        yield one_entities_dict_qname

def query_see_also_key_value_pairs(grph, sparql_query):
    # This is imported here so rdflib is not mandatory for all tests.
    import lib_sparql

    WARNING("query_see_also_key_value_pairs")
    iter_entities_dicts = lib_sparql.QuerySeeAlsoEntities(grph, sparql_query)
    iter_dict_objects = __queries_entities_to_value_pairs(iter_entities_dicts)
    list_dict_objects = list(iter_dict_objects)
    return list_dict_objects

################################################################################
