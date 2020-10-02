# This should avoid using lib_util, lib_common etc... because the intention of code
# in the "scripts/" directory is to be stand-alone, as much as possible.
import os
import sys
import subprocess
import configparser
import psutil
import time
import datetime
import tempfile

# This is used to communicate with the supervisor.
_is_py3 = sys.version_info >= (3,)
if _is_py3:
    import xmlrpc.client as xmlrpclib
else:
    import xmlrpclib

#_xmlrpc_error = "XMLRPC Server proxy not started."

# This starts a supervisor process in interactive mode, except if a daemon is already started.
try:
    # Linux  : Module supervisor.
    # Windows: Module supervisor-win
    import supervisor
    from supervisor.xmlrpc import Faults as SupervisorFaults
except ImportError:
    sys.stderr.write(__file__ + ": Cannot import supervisor\n")
    supervisor = None


def _must_start_factory():
    # It is not started when run in pytest, except if explicitly asked.
    # Also, it must NOT be started
    if not supervisor:
        sys.stderr.write("Could not import supervisor\n")
        return False

    # This is for performance reasons.
    # PYTEST_CURRENT_TEST= tests/test_lib_daemon.py::CgiScriptTest::test_start_events_generator_daemon
    return "PYTEST_CURRENT_TEST" not in os.environ or "START_DAEMON_FACTORY" in os.environ


# This is not stored with credentials because the supervisor might be part of the machine setup,
# so Survol would use it instead of starting its own supervisord process.
# Also, code in "scripts/" directory must be as standalone as possible.
_supervisor_config_file = os.path.join(os.path.dirname(__file__), "supervisord.conf")


def _log_supervisor_access(function_name, step_name, **kwargs):
    """This writes into a file showing all accesses to the supervisor."""
    # TODO: This file should be truncated when the CGI server starts.
    if "TRAVIS" in os.environ:
        log_supervisor_file = None
    else:
        tmp_dir = tempfile.gettempdir()
        log_supervisor_file = os.path.join(tmp_dir, "_survol_supervisor.log")

    if not log_supervisor_file:
        return

    timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Three retries in case another process accesses it at the same time.
    open_try_count = 3
    for counter in range(open_try_count):
        try:
            db_log_file = open(log_supervisor_file, "a")
            arguments_as_string = str(kwargs)
            db_log_file.write("%s %6d f=%25s s=%s a=%s\n" % (
                timestamp_now,
                os.getpid(),
                function_name,
                step_name,
                arguments_as_string))
            db_log_file.flush()
            db_log_file.close()
            break
        except Exception as exc:
            sys.stderr.write("Did not work: %s. Retry\n" % exc)
            time.sleep(1)


_log_supervisor_access("", "import")


def _get_parsed_configuration():
    """This parses the supervisord configuration file into a dict. It does not connect to anything. """
    parsed_config = configparser.ConfigParser()
    if not os.path.exists(_supervisor_config_file):
        raise Exception("Cannot find supervisor config file:" + _supervisor_config_file)
    sys.stderr.write("_get_supervisor_url config_file=%s\n" % _supervisor_config_file)
    if _is_py3:
        config_status = parsed_config.read(_supervisor_config_file)
    else:
        config_status = parsed_config.read(_supervisor_config_file.decode())
    if not config_status:
        raise Exception("config_status should be True")
    sys.stderr.write("config_status=%s\n" % config_status)
    sys.stderr.write("Sections=%s\n" % parsed_config.sections())
    return parsed_config


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


def _get_supervisor_url():
    """This parses the supervisord configuration file to get the url, username and password."""

    parsed_config = _get_parsed_configuration()

    # For example '127.0.0.1:9001'
    supervisor_port = _clean_config_value(parsed_config['inet_http_server']['port'])

    # TODO: Use https instead of http.
    try:
        supervisor_user = _clean_config_value(parsed_config['inet_http_server']['username'])
        supervisor_pass = _clean_config_value(parsed_config['inet_http_server']['password'])
        # 'http://chris:123@127.0.0.1:9001'
        supervisor_url = 'http://%s:%s@%s' % (supervisor_user, supervisor_pass, supervisor_port)
    except KeyError:
        # 'http://127.0.0.1:9001'
        supervisor_url = 'http://%s' % supervisor_port

    return supervisor_url


#_cache_xmlrpc_server_proxy = None


def _create_server_proxy():
    #global _cache_xmlrpc_server_proxy
    #if _cache_xmlrpc_server_proxy is not None:
    #    return _cache_xmlrpc_server_proxy
    supervisor_url = _get_supervisor_url()

    # Now, create the connection the supervisor process.
    # Typical call: srv_prox = xmlrpclib.ServerProxy('http://chris:123@127.0.0.1:9001')
    # _cache_xmlrpc_server_proxy = xmlrpclib.ServerProxy(supervisor_url)
    xmlrpc_server_proxy = xmlrpclib.ServerProxy(supervisor_url)
    #return _cache_xmlrpc_server_proxy
    return xmlrpc_server_proxy


def supervisorctl_url():
    """This parses supervisord.conf which contains the URL of supervisorctl."""

    parsed_config = _get_parsed_configuration()

    # For example 'http://localhost:9001'
    control_url = _clean_config_value(parsed_config['supervisorctl']['serverurl'])

    sys.stderr.write("control_url=%s\n" % control_url)
    return control_url


_supervisor_process = None


def _local_supervisor_start():
    """This starts a local supervisor process."""
    global _supervisor_process
    sys.stderr.write("_local_supervisor_start begin\n")

    # Maybe it is already started.
    if not _supervisor_process is None:
        # TODO: Should check that it is still there.
        sys.stderr.write("_local_supervisor_start leaving _supervisor_process.pid=%d\n" % _supervisor_process.pid)
        is_running = psutil.pid_exists(_supervisor_process.pid)
        if is_running:
            sys.stderr.write("_local_supervisor_start running fine\n")
        else:
            sys.stderr.write("_local_supervisor_start SHOULD BE RUNNING\n")
            process_stdout, process_stderr = _supervisor_process.communicate()
        return

    supervisor_command = [sys.executable, "-m", "supervisor.supervisord", "-c", _supervisor_config_file]
    sys.stderr.write("_local_supervisor_start supervisor_command=%s\n" % str(supervisor_command))

    if "TRAVIS" in os.environ:
        if _is_py3:
            null_device = subprocess.DEVNULL
        else:
            null_device = open(os.devnull, 'wb')
        supervisor_stdout = null_device
        supervisor_stderr = null_device
    else:
        supervisor_files_directory = tempfile.gettempdir()
        supervisor_stdout_name = os.path.join(supervisor_files_directory, "_supervisor_stdout.log")
        supervisor_stderr_name = os.path.join(supervisor_files_directory, "_supervisor_stderr.log")

        supervisor_stdout = open(supervisor_stdout_name, "w")
        supervisor_stderr = open(supervisor_stderr_name, "w")

    # No Shell, otherwise the subprocess running supervisor, will not be stopped.
    # BEWARE: DO NOT WRITE IN stdout AND stderr, it collides and blocks !!!
    _supervisor_process = subprocess.Popen(
        supervisor_command,
        stdout=supervisor_stdout, # subprocess.PIPE,
        stderr=supervisor_stderr, # subprocess.PIPE,
        shell=False)

    sys.stderr.write("_local_supervisor_start proc_popen.pid=%d\n" % _supervisor_process.pid)


def _local_supervisor_stop():
    """This starts a local supervisor process."""
    global _supervisor_process
    # global _cache_xmlrpc_server_proxy

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
    try:
        _supervisor_process.terminate()
    except Exception as exc:
        sys.stderr.write("_local_supervisor_stop terminating _supervisor_process.pid=%d: %s\n"
            % (_supervisor_process.pid, str(exc)))

    if _supervisor_process is not None:
        del _supervisor_process
        _supervisor_process = None

    #if _cache_xmlrpc_server_proxy is not None:
    #    del _cache_xmlrpc_server_proxy
    #    _cache_xmlrpc_server_proxy = None

    # TODO: Should call _xmlrpc_server_proxy.supervisor.shutdown()


def supervisor_startup():
    """This starts the supervisor process as a subprocess.
    This can be done only by web servers which are persistent.
    TODO: Check that maybe a supervisord process is already there. """
    # global _xmlrpc_server_proxy

    _log_supervisor_access("supervisor_startup", "entry")

    # Do not start the supervisor if:
    # - Testing and a specific environment variable is not set.
    # - The Python package supervisor is not available.
    if not _must_start_factory():
        error_message = "supervisor_startup: Do not start. "
        sys.stderr.write(error_message + "\n")
        return None


    # Maybe this is a supervisor service, or a local process.

    # TODO: The process should not be started if a service is already runing supervisor
    sys.stderr.write("supervisor_startup about to start _supervisor_process\n")
    _local_supervisor_start()

    sys.stderr.write("supervisor_startup _supervisor_process.pid=%d\n" % _supervisor_process.pid)
    # Extra test to be sure that supervisor is running.
    if not psutil.pid_exists(_supervisor_process.pid):
        error_message = "supervisor_startup not running _supervisor_process.pid=%d\n" % _supervisor_process.pid
        sys.stderr.write(error_message + "\n")
        raise Exception("supervisor_startup did not start _supervisor_process.pid=%d\n" % _supervisor_process.pid)

    _log_supervisor_access("supervisor_startup", "entry", pid=_supervisor_process.pid)
    return _supervisor_process.pid



def supervisor_stop():
    global _supervisor_process
    #global _xmlrpc_server_proxy

    _log_supervisor_access("supervisor_stop", "entry")
    sys.stderr.write("supervisor_stop\n")

    #if _xmlrpc_server_proxy is None:
    #    sys.stderr.write("supervisor_stop proxy already deleted\n")
    #else:
    #    # Stops the connection.
    #    del _xmlrpc_server_proxy
    #    _xmlrpc_server_proxy = None
    #    sys.stderr.write("supervisor_stop deleting proxy\n")

    # TODO: In the general case, detect a global supervisor started by somethign else.
    _local_supervisor_stop()
    _log_supervisor_access("supervisor_stop", "exit")
    return True


def is_supervisor_running():
   # global _xmlrpc_server_proxy
    _log_supervisor_access("is_supervisor_running", "entry")
    message_prefix = "is_supervisor_running pid=%d " % os.getpid()
    sys.stderr.write(message_prefix + " _supervisor_process.pid=%d\n" % _supervisor_process.pid)
    #sys.stderr.write(message_prefix + "entering _xmlrpc_error=%s\n" % _xmlrpc_error)
    #if _xmlrpc_server_proxy is None:
    #    raise Exception("_xmlrpc_server_proxy should be set: " + _xmlrpc_error)
    #sys.stderr.write(message_prefix + "_xmlrpc_server_proxy=%s\n" % str(_xmlrpc_server_proxy))


    xmlrpc_server_proxy = None
    try:
        xmlrpc_server_proxy = _create_server_proxy()
        api_version = xmlrpc_server_proxy.supervisor.getAPIVersion()
        sys.stderr.write(message_prefix + "api_version=%s\n" % api_version)
    except Exception as exc:
        sys.stderr.write(message_prefix + "exc=%s\n" % exc)
        api_version = None
    finally:
        del xmlrpc_server_proxy

    if _supervisor_process is None:
        sys.stderr.write(message_prefix + "SUPERVISOR NOT CREATED\n")
    else:
        if psutil.pid_exists(_supervisor_process.pid):
            sys.stderr.write(message_prefix + "OK _supervisor_process.pid=%d\n" % _supervisor_process.pid)
        else:
            sys.stderr.write(message_prefix + "NOT HERE _supervisor_process.pid=%d\n" % _supervisor_process.pid)

    sys.stderr.write(message_prefix + " api_version=%s\n" % api_version)
    _log_supervisor_access("is_supervisor_running", "exit", api_version=api_version)
    return api_version


_survol_group_name = "survol_group"


def _display_configuration_file(configuration_file_name):
    try:
        with open(configuration_file_name) as config_file:
            config_content = "".join(config_file.readlines())
        sys.stderr.write("_display_configuration_file: _survol_group_name=%s\n" % _survol_group_name)
        sys.stderr.write("_display_configuration_file: Configuration start ================================\n")
        sys.stderr.write("%s\n" % config_content)
        sys.stderr.write("_display_configuration_file: Configuration end   ================================\n")
    except Exception as exc:
        sys.stderr.write("_display_configuration_file: Cannot read configuration exc=%s\n" % str(exc))


def _add_and_start_program_to_group(process_name, user_command, environment_parameter, debug_stream=None):
    # Add the program and starts it immediately: This is faster
    program_options = {
        'command': user_command,
        'autostart': 'true',
        'autorestart': 'false',
        'environment': environment_parameter}

    #xmlrpc_server_proxy = None
    xmlrpc_server_proxy = _create_server_proxy()

    try:
        add_status = xmlrpc_server_proxy.twiddler.addProgramToGroup(
            _survol_group_name,
            process_name,
            program_options)
    except Exception as exc:
        # Possible exceptions:
        #
        # Fault: <Fault 10: 'BAD_NAME: http___any_machine_any_directory__survol_sources_types_events_generator_one_tick_per_second_py_parama_123_paramb_START'>
        #
        # <Fault 2: "INCORRECT_PARAMETERS: No closing quotation in section
        # 'program:ama_123_paramb_START' (file: 'survol/scripts/supervisord.conf')">
        #

        if exc.faultCode == SupervisorFaults.BAD_NAME:
            sys.stderr.write("POSSIBLY DOUBLE DEFINITION\n")
        else:
            _display_configuration_file("survol/scripts/supervisord.conf")
            raise
    finally:
        # Must explicitely test with None, otherwise it raises " Fault: <Fault 1: 'UNKNOWN_METHOD'>"
        if xmlrpc_server_proxy is not None:
            del xmlrpc_server_proxy
        #del xmlrpc_server_proxy


def _display_process_files(process_info):
    with open(process_info['stderr_logfile']) as stderr_logfile:
        sys.stderr.write("==== stderr_logfile ====\n%s" % "\n".join(stderr_logfile.readlines()))
    with open(process_info['stdout_logfile']) as stdout_logfile:
        sys.stderr.write("==== stdout_logfile ====\n%s" % "\n".join(stdout_logfile.readlines()))
    if process_info['logfile'] != process_info['stdout_logfile']:
        raise Exception("display_process_files Inconsistent log files:%s %s" % (
            process_info['logfile'], process_info['stdout_logfile']))


def start_user_process(process_name, user_command, environment_parameter="", debug_stream=None):
    """This returns the newly created process id."""
    _log_supervisor_access("start_user_process", "entry", proc_name=process_name, command=user_command)
    sys.stderr.write("start_user_process: python_command=%s\n" % user_command)
    #sys.stderr.write("start_user_process: _xmlrpc_error=%s\n" % _xmlrpc_error)
    #if _xmlrpc_server_proxy is None:
    #    sys.stderr.write("start_user_process: Server proxy not set: " + _xmlrpc_error)
    #    return None

    full_process_name = _survol_group_name + ":" + process_name

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
    _log_supervisor_access("start_user_process", "creation", full_proc_name=full_process_name)
    try:
        xmlrpc_server_proxy = _create_server_proxy()
        process_info = xmlrpc_server_proxy.supervisor.getProcessInfo(full_process_name)
    except Exception as exc:
        process_info = None

    if process_info is None:
        # Maybe this program is not defined in the config file,
        # so let's define it automatically.
        _add_and_start_program_to_group(process_name, user_command, environment_parameter, debug_stream)
        process_info = xmlrpc_server_proxy.supervisor.getProcessInfo(full_process_name)
        if process_info is None:
            raise Exception("Cannot get process_info after adding program:%" % full_process_name)
        created_process_id = process_info['pid']
        _log_supervisor_access("start_user_process", "created", created_pid=created_process_id)
        if not psutil.pid_exists(created_process_id):
            raise Exception("start_user_process: New process not successfully started.\n")
    else:
        created_process_id = process_info['pid']
        _log_supervisor_access("start_user_process", "exists", created_pid=created_process_id)
        if created_process_id > 0:
            if not psutil.pid_exists(created_process_id):
                raise Exception("start_user_process: Existing process not existing.\n")
        else:
            # Now, starts the process
            try:
                start_result = xmlrpc_server_proxy.supervisor.startProcess(full_process_name)
            except Exception as exc:
                sys.stderr.write("start_user_process: StartProcess raised:%s\n" % str(exc))
                raise
            
            if start_result:
                sys.stderr.write("start_user_process: StartProcess OK\n")
            else:
                raise Exception("Error restarting %s" % full_process_name)
            process_info = xmlrpc_server_proxy.supervisor.getProcessInfo(full_process_name)
            if process_info is None:
                raise Exception("Cannot get process_info after restarting program:%" % full_process_name)
            created_process_id = process_info['pid']
            if created_process_id > 0:
                if not psutil.pid_exists(created_process_id):
                    raise Exception("start_user_process: Existing process not existing.\n")

    # This expects the process to be continuously running.
    if not psutil.pid_exists(created_process_id):
        _display_process_files(process_info)
        raise Exception("created_process_id=%d not started" % created_process_id)

    del xmlrpc_server_proxy
    _log_supervisor_access("start_user_process", "leaving", created_pid=created_process_id)
    return created_process_id


def _get_user_process_info(process_name):
    message_prefix = "_get_user_process_info pid=%d " % os.getpid()
    #if _xmlrpc_server_proxy is None:
    #    sys.stderr.write(message_prefix + "Proxy not set\n")
    #    return None
    full_process_name = _survol_group_name + ":" + process_name
    _log_supervisor_access("_get_user_process_info", "entry", full_proc_name=full_process_name)
    try:
        xmlrpc_server_proxy = _create_server_proxy()

        process_info = xmlrpc_server_proxy.supervisor.getProcessInfo(full_process_name)
        del xmlrpc_server_proxy
    except xmlrpclib.Fault as exc:
        # xmlrpc.client.Fault: <Fault 10: 'BAD_NAME: survol_group:non_existent_url.py?arg=11132'>
        _log_supervisor_access("_get_user_process_info", "exit", exception=str(exc))
        if "BAD_NAME" in str(exc):
            sys.stderr.write(message_prefix + "BAD NAME:%s. Exc=%s\n" % (full_process_name, exc))
            return None
        # Otherwise it is an unexpected exception.
        raise
    except xmlrpclib.Fault as exc:
        raise
    #finally:
    #    del xmlrpc_server_proxy
    if process_info['logfile'] != process_info['stdout_logfile']:
        raise Exception(message_prefix + "Inconsistent log files:%s %s" % (
            process_info['logfile'], process_info['stdout_logfile']))
    return process_info


def is_user_process_running(process_name):
    _log_supervisor_access("is_user_process_running", "entry", proc_name=process_name)
    process_info = _get_user_process_info(process_name)
    if process_info is None:
        sys.stderr.write("is_user_process_running: No proxy")
        return False
    is_stopped = process_info['statename'] != 'STOPPED'

    # The logic should be the same: 'STOPPED' means that the process left.
    # This does not check the process id because it might have been reused (although extremely improbable).
    _log_supervisor_access("is_user_process_running", "exit", proc_name=process_name, is_stop=is_stopped)
    return is_stopped


def get_user_process_stdout(process_name):
    process_info = _get_user_process_info(process_name)
    if process_info is None:
        return "No stdout for process_name=" + process_name

    with open(process_info['stdout_logfile']) as file_stdout:
        return "".join(file_stdout.readlines())


def get_user_process_stderr(process_name):
    process_info = _get_user_process_info(process_name)
    if process_info is None:
        return "No stderr for process_name=" + process_name

    with open(process_info['stderr_logfile']) as file_stderr:
        return "".join(file_stderr.readlines())


def stop_user_process(process_name):
    _log_supervisor_access("stop_user_process", "entry", proc_name=process_name)
    """It stops a process, process group names are unique.
    It does not wait for the result.
    Consider killing the process if it does not stop after X seconds.
    It will protect against hanging. """
    full_process_name = _survol_group_name + ":" + process_name
    xmlrpc_server_proxy = None
    try:
        xmlrpc_server_proxy = _create_server_proxy()
        xmlrpc_server_proxy.supervisor.stopProcess(full_process_name, False)
    except:
        pass
    finally:
        del xmlrpc_server_proxy
    return True

