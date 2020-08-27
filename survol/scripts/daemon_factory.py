# This should avoid using lib_util, lib_common etc... because the intention of code
# in the "scripts/" directory is to be stand-alone, as much as possible.
import os
import sys
import subprocess
import configparser

# This is used to communicate with the supervisor.
if sys.version_info < (3,):
    import xmlrpclib
else:
    import xmlrpc.client as xmlrpclib

# This starts a supervisor process in interactive mode, except if a daemon is already started.
try:
    import supervisor
    # It is not started when run in pytest, except if explicitly asked.
    # Also, it must NOT be started
    # This is for performance reasons.
    _must_start_factory = "PYTEST_CURRENT_TEST" not in os.environ or "START_DAEMON_FACTORY" in os.environ
except ImportError:
    _must_start_factory = False



# This is not stored with credentials because the supervisor might be part of the machine setup,
# so Survol would use it instead of starting its own supervisord process.
# Also, code in "scripts/" directory must be as standalone as possible.
# C:\Users\rchateau\supervisord.conf
# config_file = r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\survol\scripts\supervisord.conf"
config_file = os.path.join(os.path.dirname(__file__), "..", "survol", "scripts", "supervisord.conf")


# This parses the supervisord configuration file to get the url, username and password.
def _get_supervisor_url():

    parsed_config = configparser.ConfigParser()
    parsed_config.read(config_file)
    print("Sections=", parsed_config.sections())

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

    print("supervisor_url=", supervisor_url)
    return supervisor_url


# This is done once only.
_supervisor_url = _get_supervisor_url()

# First, a ServerProxy object must be configured.
# If supervisord is listening on an inet socket, ServerProxy configuration is simple:

# Typical call: srv_prox = xmlrpclib.ServerProxy('http://chris:123@127.0.0.1:9001')
_server_proxy = None


# This starts the supervisor process as a subprocess.
# This can be done only by web servers which are persistent.
# TODO: Check that maybe a supervisord process is already there,
def supervisor_startup():
    # Do not start the supervisor if:
    # - Testing and a specific environment variable is not set.
    # - The Python package supervisor is not available.
    if not _must_start_factory:
        return

    supervisor_command = r'"%s" -m supervisor.supervisord -c "%s"' % (sys.executable, config_file)

    proc = subprocess.Popen(supervisor_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    if False:
        try:
            proc_outs, proc_errs = proc.communicate(timeout=15)
            print("proc_outs=", proc_outs)
            print("proc_errs=", proc_errs)
        except subprocess.TimeoutExpired:
            proc.kill()

    # py -3.6 -m supervisor.supervisord -c C:\Users\rchateau\supervisord


def supervisor_startup():
    global _server_proxy
    if _must_start_factory:
        # First, a ServerProxy object must be configured.
        # If supervisord is listening on an inet socket, ServerProxy configuration is simple:
        import xmlrpclib
        _server_proxy = xmlrpclib.ServerProxy(_supervisor_url)

        # Once ServerProxy has been configured appropriately, we can now exercise supervisor_twiddler:

        # _server_proxy.twiddler.getAPIVersion()
        return True
    else:
        return False


_survol_group_name = "survol_group"


def start_user_process(process_name, python_command):
    if not _server_proxy:
        return False
    full_process_name = _survol_group_name + ":" + process_name

    _server_proxy.twiddler.addProgramToGroup(_survol_group_name, process_name,
                                        {'command': python_command, 'autostart': 'false', 'autorestart': 'false'})
    # process_log = _server_proxy.supervisor.readProcessLog(full_process_name, 0, 50)

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
    process_info = _server_proxy.supervisor.getProcessInfo(full_process_name)

    assert process_info['logfile'] == process_info['stdout_logfile']

    # xmlrpc.client.Fault: <Fault 50: 'SPAWN_ERROR: thegroupname:dir4'>
    # xmlrpc.client.Fault: <Fault 10: 'BAD_NAME: dir4'>
    _server_proxy.supervisor.startProcess(full_process_name)

    return True

def is_user_process_running(process_name):
    full_process_name = _survol_group_name + ":" + process_name
    process_info = _server_proxy.supervisor.getProcessInfo(full_process_name)
    assert process_info['logfile'] == process_info['stdout_logfile']
    return process_info['statename'] != 'STOPPED'
