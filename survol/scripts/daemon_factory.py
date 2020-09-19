# This should avoid using lib_util, lib_common etc... because the intention of code
# in the "scripts/" directory is to be stand-alone, as much as possible.
import os
import sys
import subprocess
import configparser
import psutil
import time

# This is used to communicate with the supervisor.
if sys.version_info < (3,):
    import xmlrpclib
else:
    import xmlrpc.client as xmlrpclib

_xmlrpc_error = "XMLRPC Server proxy not started."

# This starts a supervisor process in interactive mode, except if a daemon is already started.
try:
    import supervisor
except ImportError as exc:
    _xmlrpc_error += str(exc) + ". "
    sys.stderr.write("Cannot import supervisor\n")
    supervisor = None


def _must_start_factory():
    global _xmlrpc_error
    # It is not started when run in pytest, except if explicitly asked.
    # Also, it must NOT be started
    if not supervisor:
        _xmlrpc_error += "Could not import supervisor. "
        sys.stderr.write("Could not import supervisor\n")
        return False

    if "PYTEST_CURRENT_TEST" in os.environ:
        _xmlrpc_error += "PYTEST_CURRENT_TEST=" + os.environ["PYTEST_CURRENT_TEST"] + ". "
    else:
        _xmlrpc_error += "PYTEST_CURRENT_TEST not here. "

    if "START_DAEMON_FACTORY" in os.environ:
        _xmlrpc_error += "START_DAEMON_FACTORY=" + os.environ["START_DAEMON_FACTORY"] + ". "
    else:
        _xmlrpc_error += "START_DAEMON_FACTORY not here. "

        # This is for performance reasons.
    # PYTEST_CURRENT_TEST= tests/test_lib_daemon.py::CgiScriptTest::test_start_events_generator_daemon
    return "PYTEST_CURRENT_TEST" not in os.environ or "START_DAEMON_FACTORY" in os.environ


# This is not stored with credentials because the supervisor might be part of the machine setup,
# so Survol would use it instead of starting its own supervisord process.
# Also, code in "scripts/" directory must be as standalone as possible.
# C:\Users\rchateau\supervisord.conf
# config_file = r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\survol\scripts\supervisord.conf"
_supervisor_config_file = os.path.join(os.path.dirname(__file__), "supervisord.conf")


def _get_supervisor_url():
    """This parses the supervisord configuration file to get the url, username and password.
    It does not do any connection. """

    parsed_config = configparser.ConfigParser()
    if not os.path.exists(_supervisor_config_file):
        raise Exception("Cannot find supervisor config file:" + _supervisor_config_file)
    sys.stderr.write("_get_supervisor_url config_file=%s\n" % _supervisor_config_file)
    config_status = parsed_config.read(_supervisor_config_file)
    if not config_status:
        raise Exception("config_status should be True")
    sys.stderr.write("config_status=%s\n" % config_status)
    sys.stderr.write("Sections=%s\n" % parsed_config.sections())

    # https://bugs.python.org/issue27762
    # Python 2 bug when the value contains a semicolon after a space which normally should be stripped.
    # This can be avoided from Python 3.2 with ConfigParser(inline_comment_prefixes=';')
    # However, this portable function optimistically parses the value for hosts, usernames and passwords.
    def _clean_config_value(config_value):
        config_value = config_value.strip()
        # TODO: Beware if a semicolon in the password.
        config_value = config_value.split(";")[0]
        config_value = config_value.strip()
        return config_value

    # u'127.0.0.1:9001
    supervisor_port = _clean_config_value(parsed_config['inet_http_server']['port'])

    # TODO: Use https instead of http.
    try:
        supervisor_user = _clean_config_value(parsed_config['inet_http_server']['username'])
        supervisor_pass = _clean_config_value(parsed_config['inet_http_server']['password'])
        # 'http://chris:123@127.0.0.1:9001'
        supervisor_url = 'http://%s:%s@%s' % (supervisor_user, supervisor_pass, supervisor_port)
    except KeyError:
        supervisor_user = None
        supervisor_pass = None
        # 'http://127.0.0.1:9001'
        supervisor_url = 'http://%s' % (supervisor_port)

    sys.stderr.write("supervisor_url=%s\n" % supervisor_url)
    return supervisor_url


# First, a ServerProxy object must be configured.
# If supervisord is listening on an inet socket, ServerProxy configuration is simple:

# Typical call: srv_prox = xmlrpclib.ServerProxy('http://chris:123@127.0.0.1:9001')
_xmlrpc_server_proxy = None

_supervisor_process = None


def _local_supervisor_start():
    """This starts a local supervisor process."""
    global _supervisor_process
    sys.stderr.write("_local_supervisor_start begin\n")

    # Maybe it is already started.
    if _supervisor_process:
        # TODO: Should check that it is still there.
        sys.stderr.write("_local_supervisor_start leaving _supervisor_process.pid=%d\n" % _supervisor_process.pid)
        is_running = psutil.pid_exists(_supervisor_process.pid)
        if is_running:
            sys.stderr.write("_local_supervisor_start running fine\n")
        else:
            sys.stderr.write("_local_supervisor_start NOT RUNNING\n")
        return

    supervisor_command = [sys.executable, "-m", "supervisor.supervisord", "-c", _supervisor_config_file]
    sys.stderr.write("_local_supervisor_start supervisor_command=%s\n" % str(supervisor_command))

    # No Shell, otherwise the subprocess running supervisor, will not be stopped.
    proc_popen = subprocess.Popen(supervisor_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

    sys.stderr.write("_local_supervisor_start proc_popen=%s\n" % proc_popen)
    sys.stderr.write("_local_supervisor_start proc_popen.pid=%d\n" % proc_popen.pid)

    for counter in range(3):
        is_running = psutil.pid_exists(proc_popen.pid)
        if is_running:
            sys.stderr.write("_local_supervisor_start proc_popen.pid=%d RUNNING OK\n" % proc_popen.pid)
        else:
            process_stdout, process_stderr = proc_popen.communicate()
            sys.stderr.write("_local_supervisor_start process_stdout=%s\n" % process_stdout)
            sys.stderr.write("_local_supervisor_start process_stderr=%s\n" % process_stderr)
            break
        time.sleep(1)

    _supervisor_process = proc_popen


def _local_supervisor_stop():
    """This starts a local supervisor process."""
    global _supervisor_process
    if _supervisor_process is None:
        sys.stderr.write("_local_supervisor_stop already stopped\n")
        return

    sys.stderr.write("_local_supervisor_stop _supervisor_process.pid=%d\n" % _supervisor_process.pid)

    is_running = psutil.pid_exists(_supervisor_process.pid)
    if is_running:
        sys.stderr.write("_local_supervisor_stop running fine\n")
    else:
        sys.stderr.write("_local_supervisor_stop SHOULD BE RUNNING\n")

    _supervisor_process.kill()
    _supervisor_process.communicate()
    _supervisor_process.terminate()
    del _supervisor_process
    _supervisor_process = None

    # TODO: Should call _xmlrpc_server_proxy.supervisor.shutdown()


# This starts the supervisor process as a subprocess.
# This can be done only by web servers which are persistent.
# TODO: Check that maybe a supervisord process is already there,
def supervisor_startup():
    global _xmlrpc_server_proxy
    global _xmlrpc_error

    # Do not start the supervisor if:
    # - Testing and a specific environment variable is not set.
    # - The Python package supervisor is not available.
    if not _must_start_factory():
        error_message = "supervisor_startup: Do not start. "
        _xmlrpc_error += error_message
        sys.stderr.write(error_message + "\n")
        return None

    # The proxy is already started.
    if _xmlrpc_server_proxy is not None:
        error_message = "supervisor_startup _supervisor_process.pid=%d RUNNING. " % _supervisor_process.pid
        _xmlrpc_error += error_message
        sys.stderr.write("supervisor_startup _xmlrpc_error=%s" % _xmlrpc_error)
        return _supervisor_process.pid

    # Maybe this is a supervisor service, or a local process.

    # TODO: The process should not be started if a service is already runing supervisor
    sys.stderr.write("supervisor_startup about to start _supervisor_process\n")
    try:
        _local_supervisor_start()
    except Exception as exc:
        error_message = str(exc)
        _xmlrpc_error += error_message + ". "
        sys.stderr.write("EXCEPTION _xmlrpc_error=%s\n" % _xmlrpc_error)
        raise

    sys.stderr.write("supervisor_startup _supervisor_process.pid=%d\n" % _supervisor_process.pid)
    # Extra test to be sure that supervisor is running.
    if not psutil.pid_exists(_supervisor_process.pid):
        error_message = "supervisor_startup not running _supervisor_process.pid=%d\n" % _supervisor_process.pid
        _xmlrpc_error += ". " + error_message
        sys.stderr.write(error_message + "\n")
        raise Exception("_xmlrpc_error=" + _xmlrpc_error)

    try:
        # This is done once only.
        supervisor_url = _get_supervisor_url()

        # Now, create the connection the supervisor process.
        _xmlrpc_server_proxy = xmlrpclib.ServerProxy(supervisor_url)

        sys.stderr.write("supervisor_startup supervisor_url=%s Before wait\n" % supervisor_url)
        time.sleep(1)
        sys.stderr.write("supervisor_startup supervisor_url=%s After wait\n" % supervisor_url)
        if not is_supervisor_running():
            error_message = "Could not start:%s\n" % supervisor_url
            _xmlrpc_error += ". " + error_message
            raise Exception(error_message)

        _xmlrpc_error += ". XMLRPC started OK"
        return _supervisor_process.pid
    except Exception as exc:
        error_message = "Cannot start server proxy:%s" % exc
        sys.stderr.write(error_message + "\n")
        sys.stderr.write("supervisor_url:%s\n" % supervisor_url)
        _local_supervisor_stop()
        return None


def supervisor_stop():
    global _supervisor_process
    global _xmlrpc_server_proxy

    sys.stderr.write("supervisor_stop\n")

    if _xmlrpc_server_proxy is None:
        sys.stderr.write("supervisor_stop proxy already deleted\n")
    else:
        # Stops the connection.
        del _xmlrpc_server_proxy
        _xmlrpc_server_proxy = None
        sys.stderr.write("supervisor_stop deleting proxy\n")

    _local_supervisor_stop()
    return True


def is_supervisor_running():
    global _xmlrpc_server_proxy
    sys.stderr.write("is_supervisor_running entering _xmlrpc_error=%s\n" % _xmlrpc_error)
    if _xmlrpc_server_proxy is None:
        raise Exception("_xmlrpc_server_proxy should be set: " + _xmlrpc_error)
    sys.stderr.write("is_supervisor_running _xmlrpc_server_proxy=%s\n" % str(_xmlrpc_server_proxy))

    try:
        api_version = _xmlrpc_server_proxy.supervisor.getAPIVersion()
        sys.stderr.write("is_supervisor_running api_version=%s\n" % api_version)
    except Exception as exc:
        sys.stderr.write("is_supervisor_running exc=%s\n" % exc)
        api_version = None

    if _supervisor_process is None:
        sys.stderr.write("is_supervisor_running SUPERVISOR NOT CREATED\n")
    else:
        if psutil.pid_exists(_supervisor_process.pid):
            sys.stderr.write("is_supervisor_running OK _supervisor_process.pid=%d\n" % _supervisor_process.pid)
        else:
            sys.stderr.write("is_supervisor_running NOT HERE _supervisor_process.pid=%d\n" % _supervisor_process.pid)

    return api_version


_survol_group_name = "survol_group"


def start_user_process(process_name, user_command, environment_parameter=""):
    """This returns the newly created process id."""
    sys.stderr.write("start_user_process: python_command=%s\n" % user_command)
    sys.stderr.write("start_user_process: _xmlrpc_error=%s\n" % _xmlrpc_error)
    if _xmlrpc_server_proxy is None:
        sys.stderr.write("start_user_process: Server proxy not set: " + _xmlrpc_error)
        return None

    full_process_name = _survol_group_name + ":" + process_name
    sys.stderr.write("start_user_process: full_process_name=%s\n" % full_process_name)

    # Aff the program and starts it immediately: This is faster
    program_options = {
        'command': user_command,
        'autostart': 'true',
        'autorestart': 'false',
        'environment': environment_parameter}

    try:
        sys.stderr.write("start_user_process: Before addProgramToGroup\n")
        sys.stderr.write("start_user_process: process_name=%s\n" % str(process_name))
        sys.stderr.write("start_user_process: program_options=%s\n" % str(program_options))
        add_status = _xmlrpc_server_proxy.twiddler.addProgramToGroup(
            _survol_group_name,
            process_name,
            program_options)
        sys.stderr.write("start_user_process: After addProgramToGroup\n")
    except Exception as exc:
        sys.stderr.write("start_user_process: start_user_process exc=%s\n" % exc)
        raise
    sys.stderr.write("start_user_process: add_status=%s\n" % add_status)

    # 'logfile': 'C:\\Users\\rchateau\\AppData\\Local\\Temp\\survol_url_1597910058-stdout---survol_supervisor-g1bg9mxg.log',
    # 'name': 'survol_url_1597910058',
    # 'now': 1597910059,
    # 'pid': 0,
    # 'spawnerr': '',
    # 'start': 0,
    # 'state': 0,
    # 'statename': 'STOPPED',
    # 'stderr_logfile': 'C:\\Users\\rchateau\\AppData\\Local\\Temp\\survol_url_1597910058-stderr---survol_supervisor-1k6bm7jz.log',
    # 'stdout_logfile': 'C:\\Users\\rchateau\\AppData\\Local\\Temp\\survol_url_1597910058-stdout---survol_supervisor-g1bg9mxg.log',
    process_info = _xmlrpc_server_proxy.supervisor.getProcessInfo(full_process_name)
    sys.stderr.write("start_user_process: process_info=%s\n" % process_info)

    if process_info['logfile'] != process_info['stdout_logfile']:
        raise Exception("start_user_process Inconsistent log files:%s %s" % (
            process_info['logfile'], process_info['stdout_logfile']))

    # Various errors.
    # xmlrpc.client.Fault: <Fault 50: 'SPAWN_ERROR: thegroupname:dir4'>
    # xmlrpc.client.Fault: <Fault 10: 'BAD_NAME: dir4'>

    # Here, it is already started.
    # xmlrpc.client.Fault: <Fault 60: 'ALREADY_STARTED: survol_group:test_start_user_process_20732'>
    # _xmlrpc_server_proxy.supervisor.startProcess(full_process_name)

    created_process_id = process_info['pid']
    # This expects the process to be continuously running.
    if not psutil.pid_exists(created_process_id):
        with open(process_info['stdout_logfile']) as stdout_logfile:
            sys.stderr.write("==== stdout_logfile ====\n%s" % "\n".join(stdout_logfile.readlines()))
        with open(process_info['stderr_logfile']) as stderr_logfile:
            sys.stderr.write("==== stderr_logfile ====\n%s" % "\n".join(stderr_logfile.readlines()))
        raise Exception("created_process_id=%d not started" % created_process_id)
    return created_process_id



def _get_user_process_info(process_name):
    if _xmlrpc_server_proxy is None:
        sys.stderr.write("is_user_process_running: No proxy")
        return False
    full_process_name = _survol_group_name + ":" + process_name
    try:
        process_info = _xmlrpc_server_proxy.supervisor.getProcessInfo(full_process_name)
    except xmlrpclib.Fault as exc:
        # xmlrpc.client.Fault: <Fault 10: 'BAD_NAME: survol_group:non_existent_url.py?arg=11132'>
        if "BAD_NAME" in str(exc):
            return False
        # Otherwise it is an unexpected exception.
        raise
    if process_info['logfile'] != process_info['stdout_logfile']:
        raise Exception("is_user_process_running Inconsistent log files:%s %s" % (
            process_info['logfile'], process_info['stdout_logfile']))
    return process_info


def is_user_process_running(process_name):
    process_info = _get_user_process_info(process_name)
    is_stopped = process_info['statename'] != 'STOPPED'

    # The logic should be the same: 'STOPPED' means that the process left.
    # This does not check the process id because it might have been reused (although extremely improbable).
    return is_stopped


def get_user_process_stdout(process_name):
    process_info = _get_user_process_info(process_name)

    with open(process_info['stdout_logfile']) as file_stdout:
        return " ".join(file_stdout.readlines())


def get_user_process_stderr(process_name):
    process_info = _get_user_process_info(process_name)

    with open(process_info['stderr_logfile']) as file_stderr:
        return " ".join(file_stderr.readlines())


def stop_user_process(process_name):
    """It stops a process, process group names are unique.
    It does not wait for the result.
    Consider killing the process if it does not stop after X seconds.
    It will protect against hanging. """
    full_process_name = _survol_group_name + ":" + process_name
    _xmlrpc_server_proxy.supervisor.stopProcess(full_process_name, False)
    return True
