# This is needed to avoid the message:
# "Hint: make sure your test modules/packages have valid Python names"
# Confusing and incomplete explanation here:
# https://stackoverflow.com/questions/41748464/pytest-cannot-import-module-while-python-can

from __future__ import print_function

import os
import sys
import socket
import psutil
import pkgutil
import atexit
import time

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

# "vps516494.localdomain": "http://vps516494.ovh.net/Survol/survol" }[CurrentMachine]
# Name = "vps516494.ovh.net")
SurvolServerHostname = "vps516494.ovh.net"
SurvolServerAgent = "http://vps516494.ovh.net:80/Survol"
SurvolWbemCimom = "http://vps516494.ovh.net:5988"

is_platform_windows = sys.platform.startswith("win")
is_platform_linux = sys.platform.startswith("linux")

# For example /usr/bin/python2.7
# Typical situation of symbolic links:
# /usr/bin/python => python2 => python2.7
# Several Python scripts return this executable as a node.
execPath = os.path.realpath(sys.executable)
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
        execPath = win32api.GetLongPathName(win32api.GetShortPathName(execPath))

        # The drive must be in uppercase too:
        execPath = execPath[0].upper() + execPath[1:]
        sys.stderr.write(__file__ + " Fixed sys.executable")
    except ImportError:
        # Here we cannot do anything.
        sys.stderr.write(__file__ + " Cannot import win32api to fix sys.executable. Trying _getfinalpathname")

        # https://stackoverflow.com/questions/27465610/how-can-i-get-the-proper-capitalization-for-a-path
        # This is an undocumented function, for Python 3 only.
        # os.path._getfinalpathname("c:/python27/python.exe") => '\\\\?\\C:\\Python27\\python.exe'
        # os.path._getfinalpathname("c:/python27/python.exe").lstrip(r'\?') => 'C:\\Python27\\python.exe'
        execPath = os.path._getfinalpathname(execPath).lstrip(r'\?')

    execPath = execPath.replace("\\","/"),

CurrentExecutablePath = 'CIM_DataFile.Name=%s' % execPath

# https://stackoverflow.com/questions/46978624/python-multiprocessing-process-to-use-virtualenv
#print(__file__+" sys.execPath=%s" % execPath)
#print(__file__+" sys.executable=%s" % sys.executable)
#print(__file__+" sys.exec_prefix=%s" % sys.exec_prefix)

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

# This defines a file and a directory present on all platforms, for testing.
if is_platform_linux:
    FileAlwaysThere = "/etc/hosts"
    DirAlwaysThere = "/etc"
    AnyLogicalDisk = ""
else:
    if is_travis_machine():
        # This file is there because it is installed by choco, see .travis.yml
        FileAlwaysThere = "C:\\Python37\\python.exe"
        DirAlwaysThere = "C:\\Python37"
        AnyLogicalDisk = "C:"
    else:
        FileAlwaysThere = "C:\\Windows\\explorer.exe"
        DirAlwaysThere = "C:\\Windows"
        AnyLogicalDisk = "D:"

# See lib_util.survol_urlopen
try:
    # For Python 3.0 and later
    from urllib.request import urlopen as portable_urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen as portable_urlopen


def CgiAgentStart(agent_url, agent_port):
    INFO("CgiAgentStart agent_url=%s agent_port=%d", agent_url, agent_port)

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

        # This delay to allow the reuse of the socket.
        # TODO: A better solution would be to override server_bind()
        time.sleep(2.0)
        agent_process = multiprocessing.Process(
            target=scripts.cgiserver.StartParameters,
            args=(True, AgentHost, agent_port, current_dir))

        atexit.register(ServerDumpContent, scripts.cgiserver.CgiServerLogFileName(agent_port) )

        agent_process.start()
        INFO("CgiAgentStart: Waiting for CGI agent to start")
        time.sleep(3.0)
        local_agent_url = "http://%s:%s/survol/entity.py" % (AgentHost, agent_port)
        print("CgiAgentStart local_agent_url=", local_agent_url)
        try:
            response = portable_urlopen(local_agent_url, timeout=15)
        except Exception as exc:
            ERROR("Caught:%s", exc)
            ServerDumpContent(scripts.cgiserver.CgiServerLogFileName(agent_port))
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

        atexit.register(ServerDumpContent,scripts.wsgiserver.WsgiServerLogFileName)

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
            ServerDumpContent( scripts.wsgiserver.WsgiServerLogFileName)
            raise

    data = response.read().decode("utf-8")
    print("WSGI Survol agent OK")
    return agent_process

def WsgiAgentStop(agent_process):
    print("tearDownModule")
    if agent_process:
        agent_process.terminate()
        agent_process.join()

################################################################################

update_test_path()

import lib_util
import lib_kbase
import lib_sparql
import lib_properties

# The query function from lib_sparql module, returns RDF nodes.
# This is not very convenient to test.
# Therefore, for tests, this is a helper function which returns dict of strings,
# which are easier to compare.
def QueriesEntitiesToValuePairs(iter_entities_dicts):
    for one_entities_dict in iter_entities_dicts:

        one_entities_dict_qname = {}
        for variable_name, one_entity in one_entities_dict.items():
            #print("QueriesEntitiesToValuePairs one_entity=", one_entity)

            # Special attribute for debugging.
            dict_qname_value = {"__class__": one_entity.m_entity_class_name}
            for key_node, val_node in one_entity.m_predicate_object_dict.items():
                qname_key = lib_properties.PropToQName(key_node)
                str_val = str(val_node)
                dict_qname_value[qname_key] = str_val
            one_entities_dict_qname[variable_name] = dict_qname_value
        yield one_entities_dict_qname

def QuerySeeAlsoKeyValuePairs(grph, sparql_query):
    WARNING("QuerySeeAlsoKeyValuePairs")
    iter_entities_dicts = lib_sparql.QuerySeeAlsoEntities(grph, sparql_query)
    iter_dict_objects = QueriesEntitiesToValuePairs(iter_entities_dicts)
    list_dict_objects = list(iter_dict_objects)
    return list_dict_objects


def UrlToRdf(url_rdf):
    print("url_rdf=",url_rdf)

    response = lib_util.survol_urlopen(url_rdf)
    doc_xml_rdf = response.read().decode("utf-8")

    print("doc_xml_rdf=",doc_xml_rdf)

    # We could use lib_client GetTripleStore because we just need to deserialize XML into RDF.
    # On the other hand, this would imply that a SparQL endpoint works just like that, and this is not sure.
    grphKBase = lib_kbase.triplestore_from_rdf_xml(doc_xml_rdf)
    return grphKBase

################################################################################
