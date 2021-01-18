
"""
This expects that the daemon factory, i.e. the supervisor, is running.
"""

import os
import sys
import logging
from scripts import daemon_factory

# BEWARE: This CANNOT import lib_common, otherwise circular reference.
import lib_util


def _char_to_hex(one_char):
    """ 'a' => '61' """
    return format(ord(one_char), "x")


def _hex_to_char(chr_pair):
    """ '61' => 'a' """
    return bytearray.fromhex(chr_pair).decode()


# Underscore "_" is not forbidden but is used to encode forbidden chars,
# therefore it must be encoded too.
_forbidden_chars = ":/\\?=&+*()[]{}%." + "_"


def _url_to_process_name(script_url):
    """
    This is one of the isolation layer between Survol daemons and urls one one side,
    and supervisor processes on the other side.

    Survol needs to run a daemon for some scripts plus their CGI arguments: These CGI arguments
    define an unique object: Its class and the attributes defined in the ontology.
    On the other hand, the supervisor library has no idea of what urls does, it just knowns process names.

    Some characters are not accepted by process names by supervisor, which throws for example:
    <Fault 2: "INCORRECT_PARAMETERS: Invalid name: 'http://vps516494.ovh.net/x/y/z/script.py?param=24880'
    because of character: ':' in section 'http://vps516494.ovh.net/x/y/z/script.py?param=24880'>

    Also, the process name is used to create stdout and stderr log file names,
    so the process name must contain only chars allowed in filenames.
    """

    process_name = ""
    # The encoding scheme uses an undersocre to prefix the hexadecimal value.
    # Therefore, underscores must also be encoded although they are acceptable by supervisor library.
    for one_char in script_url:
        if one_char in _forbidden_chars:
            process_name += "_" + _char_to_hex(one_char)
        else:
            process_name += one_char

    # start_user_process: start_user_process exc=<Fault 2:
    # "INCORRECT_PARAMETERS: No closing quotation in section 'program:ama_123_paramb_START'
    # (file: 'survol/scripts/supervisord.conf')">
    return process_name


def _process_name_to_url(process_name):
    """
    This transforms a process name created for supervisor, into the original URL.
    There might be alimitiation if the process name cannot be long enough,
    """
    script_url = ""
    index = 0
    # This is not extremely fast but it does not matter because it is rarely called and the string is not very long.
    while index < len(process_name):
        if process_name[index] == "_":
            # Prefix of an encoded char,
            script_url += _hex_to_char(process_name[index+1:index+3])
            index += 3
        else:
            # This char is not encoded.
            script_url += process_name[index]
            index += 1
    return script_url


def start_events_generator_daemon(script_url):
    """
    This starts a daemon running the url, but in daemon mode instaed of snapshot mode.
    This url is a CGI script plus CGI arguments defining an object: The class and the attributes values.

    :param script_url: Something like http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.
    :return: True if it worked.
    """

    # http://vps516494.ovh.net/Survol/survol/print_environment_variables.py?toto=1&tutu=2
    # QUERY_STRING	toto=1&tutu=2
    # SCRIPT_FILENAME	/home/rchateau/survol/survol/print_environment_variables.py
    # HTTP_HOST	vps516494.ovh.net
    # SCRIPT_NAME	/Survol/survol/print_environment_variables.py
    # REQUEST_URI	/Survol/survol/print_environment_variables.py?toto=1&tutu=2
    #
    # ParseResult(scheme='http', netloc='vps516494.ovh.net', path='/Survol/survol/print_environment_variables.py',
    # params='', query='toto=1&tutu=2', fragment='')

    # Parse the URL, finds the script, fails if script not there.
    # The host is not important but check that this is the current machine.
    # Look for the string "sources_types" starting from the end.
    parsed_url = lib_util.survol_urlparse(script_url)

    split_path = parsed_url.path.split("/")
    logging.debug("split_path=%s" % str(split_path))
    # All scripts returning data are in this directory or subdirs. It should not fail.
    index_sources = split_path.index("sources_types")
    script_dir = os.path.dirname(__file__)
    script_relative_path = os.path.join(script_dir, *split_path[index_sources:])
    logging.debug("script_relative_path=%s" % str(script_relative_path))
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
    query_string_with_daemon_mode = parsed_url.query
    if parsed_url.query:
        query_string_with_daemon_mode += "&"
    query_string_with_daemon_mode += "mode=daemon"
    # QUERY_STRING must not start with "?" and certainly not with "&"
    assert query_string_with_daemon_mode[0] not in "?&"

    # This is needed by the CGI scripts.
    request_uri = "%s?%s" % (parsed_url.path, query_string_with_daemon_mode)

    # This is needed by the CGI scripts, with a default value, easy to see if not explicitly set.
    server_port = os.environ.get("SERVER_PORT", 54321)

    # KEY1="value1",KEY2="value2"
    actual_host = "" if parsed_url.hostname is None else parsed_url.hostname

    # Percent character "%%" must be escaped, because if the strings contain "%", thenit throws an error like:
    # 'HTTP_HOST="None",QUERY_STRING="xid=CIM_Directory.Name%3DC%3A%2FUsers%2Frchateau%2FAp ...
    # faultString = 'INCORRECT_PARAMETERS: Format string \'HTTP_HOST="...\\survol\\\\scripts\\\\supervisord.conf\')'
    environment_parameter = \
        'HTTP_HOST="%s",QUERY_STRING="%s",SCRIPT_NAME="%s",SERVER_PORT="%s",REQUEST_URI="%s",PYTHONPATH="survol"' % (
        actual_host,
        query_string_with_daemon_mode.replace("%", "%%"),
        parsed_url.path,
        server_port,
        request_uri.replace("%", "%%"))

    # The script might be a test script which needs its execution context.
    # Sometimes, the library behaviour is slightly different in test mode.
    if "PYTEST_CURRENT_TEST" in os.environ:
        environment_parameter += ',PYTEST_CURRENT_TEST="%s"' % os.environ["PYTEST_CURRENT_TEST"]

    logging.debug("python_command=%s" % python_command)
    logging.debug("environment_parameter=%s" % environment_parameter)

    created_process_id = daemon_factory.start_user_process(process_name, python_command, environment_parameter)
    return created_process_id


def is_events_generator_daemon_running(script_url):
    process_name = _url_to_process_name(script_url)
    logging.debug("is_events_generator_daemon_running process_name=%s" % process_name)
    supervisor_pid = daemon_factory.is_user_process_running(process_name)
    return supervisor_pid


def get_events_generator_stdout(script_url):
    process_name = _url_to_process_name(script_url)
    logging.debug("get_events_generator_stdout process_name=%s" % process_name)
    return daemon_factory.get_user_process_stdout(process_name)


def get_events_generator_stderr(script_url):
    process_name = _url_to_process_name(script_url)
    logging.debug("get_events_generator_stderr process_name=%s" % process_name)
    return daemon_factory.get_user_process_stderr(process_name)


def stop_events_generator_daemon(script_url):
    process_name = _url_to_process_name(script_url)
    logging.debug("stop_events_generator_daemon process_name=%s" % process_name)
    return daemon_factory.stop_user_process(process_name)


def get_running_daemons():
    """
    The key of the dict is the plain input URL.
    """
    user_processes_dict = daemon_factory.get_all_user_processes()
    urls_dict = {}
    for process_name, process_object in user_processes_dict.items():
        script_url = _process_name_to_url(process_name)
        urls_dict[script_url] = process_object
    return urls_dict

