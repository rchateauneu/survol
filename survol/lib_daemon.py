
# This expects that the daemon factory, i.e. the supervisor, is running.

import os
import sys
from scripts import daemon_factory

# BEWARE: This CANNOT import lib_common, otherwise circular reference.
import lib_util

# Test if a CGI script is running.

# Get the events created by the daemon process running the Deamon() function of a CGI script.


def _url_to_process_name(script_url):
    assert "mode=" not in script_url
    # Some characters are not accepted by process names by supervisor, which throws for example:
    # <Fault 2: "INCORRECT_PARAMETERS: Invalid name: 'http://vps516494.ovh.net/x/y/z/script.py?param=24880'
    # because of character: ':' in section 'http://vps516494.ovh.net/x/y/z/script.py?param=24880'>
    # Also, the process name is used to create stdout and stderr log file names,
    # so the process name must contain only chars allowed in filenames.
    for forbidden_char in ":/\\?=&+*()[]{}%.":
        script_url = script_url.replace(forbidden_char, "_")

    # start_user_process: start_user_process exc=<Fault 2:
    # "INCORRECT_PARAMETERS: No closing quotation in section 'program:ama_123_paramb_START'
    # (file: 'survol/scripts/supervisord.conf')">
    return script_url


def start_events_generator_daemon(script_url):
    """

    :param script_url: Something like http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.
    :return: True if it worked.
    """

    # Parse the URL, finds the script, fails if script not there.
    # The host is not important but check that this is the current machine.
    # Look for the string "sources_types" starting from the end.

    # http://vps516494.ovh.net/Survol/survol/print_environment_variables.py?toto=1&tutu=2
    # QUERY_STRING	toto=1&tutu=2
    # SCRIPT_FILENAME	/home/rchateau/survol/survol/print_environment_variables.py
    # HTTP_HOST	vps516494.ovh.net
    # SCRIPT_NAME	/Survol/survol/print_environment_variables.py
    # REQUEST_URI	/Survol/survol/print_environment_variables.py?toto=1&tutu=2
    #
    # ParseResult(scheme='http', netloc='vps516494.ovh.net', path='/Survol/survol/print_environment_variables.py',
    # params='', query='toto=1&tutu=2', fragment='')

    parsed_url = lib_util.survol_urlparse(script_url)

    split_path = parsed_url.path.split("/")
    sys.stderr.write("split_path=%s\n" % str(split_path))
    # All scripts returning data are in this directory or subdirs. It should not fail.
    index_sources = split_path.index("sources_types")
    sys.stderr.write("__file__=%s\n" % str(__file__))
    script_dir = os.path.dirname(__file__)
    script_relative_path = os.path.join(script_dir, *split_path[index_sources:])
    sys.stderr.write("script_relative_path=%s\n" % str(script_relative_path))
    assert script_relative_path.endswith(".py")
    assert os.path.isfile(script_relative_path)

    # The process name must contain the CGI parameters: Object class and attributes etc...
    process_name = _url_to_process_name(script_url)

    # This string is processed by several layers of software, and escaping might be mis-processed.
    script_relative_path = script_relative_path.replace("\\", "/")

    # Remove the script parameters and pass them as CGI environment variables: QUERY_STRING etc...
    python_command = '"%s" %s' % (sys.executable, script_relative_path)

    # Adding the mode is necessary for the function is_snapshot_behaviour()
    # which checks that environ["QUERY_STRING"] contains "mode=daemon".
    query_mode_delimiter = "&" if parsed_url.query else "?"
    query_string_with_daemon_mode = parsed_url.query + query_mode_delimiter + "mode=" + "daemon"

    # KEY1="value1",KEY2="value2"
    environment_parameter = 'HTTP_HOST="%s",QUERY_STRING="%s",SCRIPT_NAME="%s",REQUEST_URI="%s",PYTHONPATH="survol"' % (
        parsed_url.hostname,
        query_string_with_daemon_mode,
        parsed_url.path,
        "%s?%s" % (parsed_url.path, query_string_with_daemon_mode))

    # The script might be a test script which needs its execution context.
    # Sometimes, the library behaviour is slightly different in test mode.
    if "PYTEST_CURRENT_TEST" in os.environ:
        environment_parameter += ',PYTEST_CURRENT_TEST="%s"' % os.environ["PYTEST_CURRENT_TEST"]

    sys.stderr.write("python_command=%s\n" % python_command)
    sys.stderr.write("environment_parameter=%s\n" % environment_parameter)

    created_process_id = daemon_factory.start_user_process(process_name, python_command, environment_parameter)
    return created_process_id


def is_events_generator_daemon_running(script_url):
    process_name = _url_to_process_name(script_url)
    sys.stderr.write("is_events_generator_daemon_running process_name=%s\n" % process_name)
    supervisor_pid = daemon_factory.is_user_process_running(process_name)
    return supervisor_pid


def get_events_generator_stdout(script_url):
    process_name = _url_to_process_name(script_url)
    sys.stderr.write("get_events_generator_stdout process_name=%s\n" % process_name)
    return daemon_factory.get_user_process_stdout(process_name)


def get_events_generator_stderr(script_url):
    process_name = _url_to_process_name(script_url)
    sys.stderr.write("get_events_generator_stderr process_name=%s\n" % process_name)
    return daemon_factory.get_user_process_stderr(process_name)




def stop_events_generator_daemon(script_url):
    process_name = _url_to_process_name(script_url)
    sys.stderr.write("stop_events_generator_daemon process_name=%s\n" % process_name)
    return daemon_factory.stop_user_process(process_name)

