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
import platform
import tempfile
import subprocess
import multiprocessing
import logging

# The logging level is set in pytest.ini

def update_test_path():
    """This loads the module from the source, so no need to install it, and no need of virtualenv."""
    if "../survol" not in sys.path:
        sys.path.append("../survol")

if ".." not in sys.path:
    sys.path.append("..")

update_test_path()

import scripts.cgiserver
import scripts.wsgiserver

import lib_util
import lib_uris
import lib_properties
import lib_sparql
import lib_credentials

################################################################################

is_platform_windows = lib_util.isPlatformWindows
is_platform_linux = lib_util.isPlatformLinux
# uname() is something like: uname_result(system='Linux', node='LAPTOP-R89KG6V1', release='4.4.0-18362-Microsoft',
# version='#1049-Microsoft Thu Aug 14 12:01:00 PST 2020', machine='x86_64', processor='x86_64')
is_platform_wsl = lib_util.isPlatformWsl

# Another possible test is: pkgutil.find_loader('win32file')
pytest_pypy = platform.python_implementation() == "PyPy"

is_py3 = sys.version_info >= (3,)

if is_platform_windows:
    # os.sys.getwindowsversion()
    # sys.getwindowsversion(major=6, minor=1, build=7601, platform=2, service_pack='Service Pack 1')
    # platform.release()
    # '7'
    # platform.win32_ver()
    # ('7', '6.1.7601', 'SP1', 'Multiprocessor Free')
    is_windows7 = os.sys.getwindowsversion()[0] == 6
    is_windows10 = os.sys.getwindowsversion()[0] == 10
else:
    is_windows7 = None
    is_windows10 = None


def is_travis_machine():
    """Some tests cannot be run on a Travis machine if some tools are not there."""
    return "TRAVIS" in os.environ


# Some tests start a DOS box process. The processes application is checked. Beware of capitalizing.
windows_system32_cmd_exe = r'C:\Windows\system32\cmd.exe' if is_windows10 else r'C:\windows\system32\cmd.exe'

windows_wow64_cmd_exe = r"C:\Windows\SysWOW64\cmd.exe"

is_32_bits = platform.architecture()[0] != '64bit'

################################################################################

# This is our host machine and its URLs. It is used for tests.

# "vps516494.localdomain": "http://vps516494.ovh.net/Survol/survol" }[CurrentMachine]
# Name = "vps516494.ovh.net")
SurvolServerHostname = "vps516494.ovh.net"
SurvolServerAgent = "http://vps516494.ovh.net:80/Survol"
SurvolWbemCimom = "http://vps516494.ovh.net:5988"

################################################################################


agent_host = socket.gethostname()
CurrentMachine = agent_host.lower()
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

# The agent urls point to the Survol adhoc CGI server: "http://myhost-hp:8000"
# The tests use different port numbers to avoid interferences between servers,
# if port numbers are not freed etc... Problems are easier to find.
# Port numbers are roughly associated to the type of tests.
RemoteGeneralTestServerPort = 8000
RemoteEventsTestServerPort = 8001
RemoteSparqlTestServerPort = 8002
RemoteGraphvizTestServerPort = 8003
RemoteHtmlTestServerPort = 8004
RemotePortalTestServerPort = 8005
RemoteRdf0TestServerPort = 8010
RemoteRdf1TestServerPort = 8011
RemoteRdf2TestServerPort = 8012
RemoteRdf3TestServerPort = 8013
RemoteRdf4TestServerPort = 8014
RemoteMimeTestServerPort = 8020

# This is used for test of Survol wsgiserver based on wsgiref
RemoteWsgi1TestServerPort = 8500
RemoteWsgi2TestServerPort = 8501

# Beware of supervisord.conf and port=localhost:9001

# This is used for testing Twisted WSGI server.
RemoteTwistedWsgi1TestServerPort = 9100

# Several Survol scripts return this executable among their results, so it can be tested.
CurrentExecutable = lib_util.standardized_file_path(sys.executable)

CurrentExecutablePath = lib_uris.PathFactory().CIM_DataFile(Name=CurrentExecutable)


def __dump_server_content(log_filename):
    """This is called at the end of the execution of a Survol agent created here for tests.
    It displays the content of a log file created by this agent."""
    try:
        agent_stream = open(log_filename)
        log_lines = agent_stream.readlines()

        # Maybe nothing special happened so it is not worth printing the content.
        if len(log_lines) == 2 \
                and log_lines[0].startswith(r"survol\scripts\cgiserver.py") \
                and log_lines[1].startswith(r"survol\scripts\cgiserver.py startup"):
            return
        logging.debug("Agent log file: %s" % log_filename)
        for line_stream in log_lines:
            sys.stdout.write("Dump >>> %s" % line_stream)
        agent_stream.close()
        logging.debug("Agent log file end")
    except Exception as exc:
        logging.error("No agent log file:%s" % exc)


def is_pytest():
    """This tells if the current process is started by pytest."""
    for one_arg in sys.argv:
        if one_arg.find("pytest") >= 0:
            return True
    return False


check_program_exists = lib_util.check_program_exists


# This sets the domain name on Windows. It is a bit clunky.
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
    """WBEM is not available on TravisCI."""
    return is_platform_linux and has_wbem() and not is_travis_machine()


def has_wbem():
    """WBEM is not available on TravisCI."""
    return False
    # Temporarily disable WBEM because firewall blocks wbem port.
    return pkgutil.find_loader('pywbem')


def unique_temporary_path(prefix, extension):
    """
    "It is a wrapper around temporary file creation, and ensures that the resulting filename
    can be used everywhere in Survol library.
    """
    temp_file = "%s_%d_%d%s" % (prefix, CurrentPid, int(time.time()), extension)

    # This is done in two stages because the case of the file is OK, but not the directory.
    # This function does not change non existent files.
    temp_dir = lib_util.standardized_file_path(tempfile.gettempdir())
    temp_path = os.path.join(temp_dir, temp_file)
    temp_path = lib_util.standardized_file_path(temp_path)
    return temp_path


def has_credentials(credential_type):
    return lib_credentials.get_credentials_names(credential_type)


################################################################################

if is_platform_linux:
    """This defines a disk present on all platforms, for testing."""
    AnyLogicalDisk = ""
else:
    AnyLogicalDisk = "C:"

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


# See lib_util.survol_urlopen which does something similar.
try:
    # For Python 3.0 and later
    from urllib.request import urlopen as portable_urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen as portable_urlopen


def _start_cgiserver_subprocess(agent_port):
    """
    This start cgiserver.py in a separate process by importing it as a module.
    This module is therefore not started form the command line.
    """
    print("_start_cgiserver_subprocess: agent_port=%d hostname=%s" % (agent_port, agent_host))
    try:
        # PyCharm runs test scripts from the current directory, therefore this change.
        os.environ["PYCHARM_HELPERS_DIR"]
        current_dir = ".."
    except KeyError:
        current_dir = ""

    agent_process = multiprocessing.Process(
        target=scripts.cgiserver.start_server_forever,
        args=(agent_host, agent_port, current_dir))
    agent_process.start()

    print("agent_process.pid=", agent_process.pid)

    return agent_process


def check_existing_server(agent_url):
    returned_exception = None
    try:
        # Maybe a server with this port number is already running ?
        # response = portable_urlopen(agent_url + "/survol/entity.py", timeout=2)

        # Any URL is OK as long as it returns JSON data.
        response = portable_urlopen(agent_url + "/survol/entity.py?mode=json", timeout=2)
        logging.info("Testing agent at %s", agent_url)
        internal_data = response.read().decode("utf-8")
        json_internal_data = json.loads(internal_data)
        logging.info("Existing server at %s", agent_url)
    except Exception as exc:
        logging.info("No existing server at %s:%s", agent_url, exc)
        returned_exception = exc
    return returned_exception


def start_cgiserver(agent_port):
    """This is used to start a CGI HTTP server which runs cgiserver.py.
    This processes executes Python scripts on request from the tests run by pytest.
    These Python scripts are run as CGI scripts. """
    agent_url = "http://%s:%d" % (CurrentMachine, agent_port)
    print("start_cgiserver agent_url=%s agent_port=%d" % (agent_url, agent_port))

    # The CGI agent creates a log file, the old one must be removed first.
    logfile_name = scripts.cgiserver.cgi_server_logfile_name(agent_port)
    if os.path.exists(logfile_name):
        try:
            os.remove(logfile_name)
        except Exception as exc:
            print("Cannot remove", logfile_name, exc)

    returned_exception = check_existing_server(agent_url)
    if returned_exception is None:
        return None, agent_url

    # No server with this port number, so there is o server, so this creates a process.
    agent_process = _start_cgiserver_subprocess(agent_port)
    print("_start_cgiserver_subprocess: Waiting for CGI agent to start")
    # This delay for the server to warmup.
    # TODO: A better solution would be to override server_bind()
    time.sleep(0.5)
    atexit.register(__dump_server_content, logfile_name)

    # An optional extra test to ensure that the server is ready.
    if is_travis_machine():
        print("start_cgiserver local_agent_url=", agent_url)

        returned_exception = check_existing_server(agent_url)
        if returned_exception is not None:
            logging.error("Could not start server")
            __dump_server_content(logfile_name)
            raise returned_exception

    return agent_process, agent_url


def stop_cgiserver(agent_process):
    stop_agent_process(agent_process)


def start_wsgiserver(agent_port):
    """This is used to start a WSGI HTTP server which runs wsgiserver.py.
    This processes executes Python scripts on request from the tests run by pytest.
    These Python scripts are imported as Python module and run in WSGI. """
    agent_url = "http://%s:%d" % (CurrentMachine, agent_port)

    returned_exception = check_existing_server(agent_url)
    if returned_exception is None:
        return None, agent_url

    try:
        # Running the tests scripts from PyCharm is from the current directory.
        os.environ["PYCHARM_HELPERS_DIR"]
        current_dir = ".."
    except KeyError:
        current_dir = ""
    logging.info("current_dir=%s", current_dir)
    logging.info("sys.path=%s", str(sys.path))

    agent_process = multiprocessing.Process(
        target=scripts.wsgiserver.start_server_forever,
        args=(agent_host, agent_port, True))
    agent_process.start()
    atexit.register(__dump_server_content, scripts.wsgiserver.WsgiServerLogFileName)
    logging.info("Waiting for WSGI agent ready")
    time.sleep(8.0)

    # Check again if the server is started. This can be done only with scripts compatible with WSGI.
    #local_agent_url = "http://%s:%s/survol/entity.py?mode=json" % (agent_host, agent_port)
    #returned_exception = _check_existing_server(local_agent_url)
    returned_exception = check_existing_server(agent_url)
    if returned_exception is not None:
        logging.error("Could not start server")
        __dump_server_content(scripts.wsgiserver.WsgiServerLogFileName)
        raise returned_exception

    #local_agent_url = "http://%s:%s/survol/entity.py?mode=json" % (agent_host, agent_port)
    #try:
    #    response = portable_urlopen(local_agent_url, timeout=5)
    #except Exception as exc:
    #    logging.error("Caught:%s", exc)
    #    __dump_server_content(scripts.wsgiserver.WsgiServerLogFileName)
    #    raise

    #data = response.read().decode("utf-8")
    print("WSGI Survol agent OK")
    return agent_process, agent_url


def stop_wsgiserver(agent_process):
    stop_agent_process(agent_process)

def stop_agent_process(agent_process):
    if agent_process:
        assert isinstance(agent_process, multiprocessing.Process)
        logging.info("Killing agent process %d", agent_process.pid)
        agent_process.terminate()
        agent_process.join()
        logging.info("Killed agent process %d", agent_process.pid)
    else:
        logging.info("Agent was already started")


################################################################################


# The query function from lib_sparql module, returns RDF nodes.
# This is not very convenient to test.
# Therefore, for tests, this is a helper function which returns dict of strings,
# which are easier to compare.
def __queries_entities_to_value_pairs(iter_entities_dicts):
    for one_entities_dict in iter_entities_dicts:

        one_entities_dict_qname = {}
        for variable_name, one_entity in one_entities_dict.items():
            # Special attribute for debugging.
            dict_qname_value = {"__class__": one_entity.m_entity_class_name}
            for key_node, val_node in one_entity.m_predicate_object_dict.items():
                qname_key = lib_properties.PropToQName(key_node)
                str_val = str(val_node)
                dict_qname_value[qname_key] = str_val
            one_entities_dict_qname[variable_name] = dict_qname_value
        yield one_entities_dict_qname


def query_see_also_key_value_pairs(grph, sparql_query):
    logging.debug("query_see_also_key_value_pairs")
    iter_entities_dicts = lib_sparql.QuerySeeAlsoEntities(grph, sparql_query)
    iter_dict_objects = __queries_entities_to_value_pairs(iter_entities_dicts)
    list_dict_objects = list(iter_dict_objects)
    return list_dict_objects


def create_temporary_sqlite_filename():
    """This simply creates a filename used as a sqlite database."""
    temporary_database_file = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
    database_path = temporary_database_file.name.replace("\\", "/")
    temporary_database_file.close()
    return database_path


################################################################################
