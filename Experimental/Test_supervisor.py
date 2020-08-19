# On Windows and Linux, the intentino is to test the Python module supervisor
# and ensure some basic functionalities which are needed by Survol.

# Import supervisor and supervisor-win and supervisor_twiddler which is the interface.

# Start a process.
# Gets its pid.
# Kills it and see if it is restarted.
# Check the role of username/passwords: They will be stored iun credentials file with the supervisor process url.

# Starts the supervisor process in non-deamon role: This is done by the Web servers.
import os
import sys
import time
import configparser

# https://github.com/mnaberez/supervisor_twiddler
# On Windows, supervisor_twiddler installs the Linux version of supervisor.
# Therefore, supervisor-win must be installed AFTER supervisor_twiddler.
# Another possibility, which is done here, is to have a local version of supervisor_twiddler
#import survol.scripts.supervisor_twiddler


# On Windows, the supervisor service is handled like:
# python -m supervisor.services install  -c C:\Users\rchateau\supervisord.conf
# python -m supervisor.services start
# python -m supervisor.services stop

# Starting the service as a plain subprocess, which is easier to test
# and does not require administrator rights.
# supervisord.exe -c C:\Users\rchateau\supervisord.conf
# supervisorctl.exe

# https://pypi.org/project/supervisor-win/
# To install supervisor as a windows service run the command:
# python -m supervisor.services install -c supervisord.conf
# python -m supervisor.services help

# C:\Users\rchateau\supervisord.conf
# config_file = r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\survol\scripts\supervisord.conf"
config_file = os.path.join(os.path.dirname(__file__), "..", "survol", "scripts", "supervisord.conf")

def get_supervisor_url():

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

supervisor_url = get_supervisor_url()

# First, a ServerProxy object must be configured.
# If supervisord is listening on an inet socket, ServerProxy configuration is simple:
if sys.version_info < (3,):
    import xmlrpclib
else:
    import xmlrpc.client as xmlrpclib

# srv_prox = xmlrpclib.ServerProxy('http://chris:123@127.0.0.1:9001')
srv_prox = xmlrpclib.ServerProxy(supervisor_url)

print("type(srv_prox)=", type(srv_prox))
print("srv_prox=", srv_prox)
#print("dir(srv_prox)=", dir(srv_prox))

# The subprocess running supervisor might as well be started as a Python process.
# This function starts the service as a plain subprocess, which is easier to test
# and does not require administrator rights.
# supervisor_command = "supervisord.exe -c C:\Users\rchateau\supervisord.conf"
#
# NOTE: The supervisor process stays running after the main process has left.
# This implies that s server might not need to restart a supervisord process
# that it has already started in a previous session. This, without a serice or a daemon.
#
# Beware that the behaviour might be different on Linux.
def _start_supervisor():
    supervisor_command = r'"%s" -m supervisor.supervisord -c "%s"' % (sys.executable, config_file)

    import subprocess
    print("No proxy. Starting supervisor. Command=", supervisor_command)
    proc = subprocess.Popen(supervisor_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    print("Started supervisor. Pid=", proc.pid)

    if False:
        try:
            proc_outs, proc_errs = proc.communicate(timeout=15)
            print("proc_outs=", proc_outs)
            print("proc_errs=", proc_errs)
        except subprocess.TimeoutExpired:
            proc.kill()

    # py -3.6 -m supervisor.supervisord -c C:\Users\rchateau\supervisord


def start_one_process(srv_prox, the_group_name):
    random_integer = int(time.time())
    process_name = "survol_url_%d" % int(random_integer)
    full_process_name = the_group_name + ":" + process_name
    python_command = 'python.exe -c "print(%d)"' % random_integer

    srv_prox.twiddler.addProgramToGroup(the_group_name, process_name,
                                        {'command': python_command, 'autostart': 'false', 'autorestart': 'false'})
    process_log = srv_prox.supervisor.readProcessLog(full_process_name, 0, 50)
    print("readProcessLog=", process_log)

    process_info = srv_prox.supervisor.getProcessInfo(full_process_name)
    process_info_pprint = pprint.pformat(process_info)
    print("srv_prox.supervisor.getProcessInfo()=", process_info_pprint)

    try:
        print("Starting process")
        srv_prox.supervisor.startProcess(full_process_name)
        print("Process started")
    except xmlrpclib.Fault:
        # xmlrpc.client.Fault: <Fault 50: 'SPAWN_ERROR: thegroupname:dir4'>
        # xmlrpc.client.Fault: <Fault 10: 'BAD_NAME: dir4'>
        print("Stopping process")
        srv_prox.supervisor.stopProcess(full_process_name)
        print("Process stopped")


try:
    api_version = srv_prox.supervisor.getAPIVersion()
except ConnectionRefusedError:
    _start_supervisor()
    time.sleep(10)
    try:
        api_version = srv_prox.supervisor.getAPIVersion()
    except ConnectionRefusedError:
        raise

import pprint

#print("srv_prox.twiddler.getAPIVersion()=", srv_prox.twiddler.getAPIVersion())
print("srv_prox.supervisor.getAPIVersion()=", srv_prox.supervisor.getAPIVersion())
print("srv_prox.supervisor.getIdentification()=", srv_prox.supervisor.getIdentification())
print("srv_prox.supervisor.getState()=", srv_prox.supervisor.getState())
all_config_info = srv_prox.supervisor.getAllConfigInfo()
all_config_info_pprint = pprint.pformat(all_config_info)
print("srv_prox.supervisor.getAllConfigInfo()=", all_config_info_pprint)
print("srv_prox.supervisor.getPID()=", srv_prox.supervisor.getPID())

srv_prox.system_listMethods = [
    'supervisor.addProcessGroup', 'supervisor.clearAllProcessLogs', 'supervisor.clearLog', 'supervisor.clearProcessLog',
    'supervisor.clearProcessLogs', 'supervisor.getAPIVersion', 'supervisor.getAllConfigInfo',
    'supervisor.getAllProcessInfo', 'supervisor.getIdentification', 'supervisor.getPID', 'supervisor.getProcessInfo',
    'supervisor.getState', 'supervisor.getSupervisorVersion', 'supervisor.getVersion', 'supervisor.readLog',
    'supervisor.readMainLog', 'supervisor.readProcessLog', 'supervisor.readProcessStderrLog',
    'supervisor.readProcessStdoutLog', 'supervisor.reloadConfig', 'supervisor.removeProcessGroup',
    'supervisor.restart', 'supervisor.restartProcess', 'supervisor.sendProcessStdin', 'supervisor.sendRemoteCommEvent',
    'supervisor.shutdown', 'supervisor.signalAllProcesses', 'supervisor.signalProcess', 'supervisor.signalProcessGroup',
    'supervisor.startAllProcesses', 'supervisor.startProcess', 'supervisor.startProcessGroup',
    'supervisor.stopAllProcesses', 'supervisor.stopProcess', 'supervisor.stopProcessGroup',
    'supervisor.tailProcessLog', 'supervisor.tailProcessStderrLog', 'supervisor.tailProcessStdoutLog',
    'system.listMethods', 'system.methodHelp', 'system.methodSignature', 'system.multicall',
    'twiddler.addProgramToGroup', 'twiddler.getAPIVersion', 'twiddler.getGroupNames', 'twiddler.getProcessGroup',
    'twiddler.log', 'twiddler.removeProcessFromGroup']
# print("srv_prox.system.listMethods()=", srv_prox.system.listMethods())

grpnam = srv_prox.twiddler.getGroupNames()
print("GroupNames=", grpnam)

the_group_name = grpnam[0]

for counter in range(10):
    start_one_process(srv_prox, the_group_name)
    print("=======================================================================")

procs_info = srv_prox.supervisor.getAllProcessInfo()
procs_info_pprint = pprint.pformat(procs_info)
print("Processes info:", procs_info_pprint)
print("Processes number:", len(procs_info))
for one_proc_info in procs_info:
    print(one_proc_info['name'])
# print("procs_info=", procs_info)

