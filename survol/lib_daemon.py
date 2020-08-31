
# This expects that the daemon factory, i.e. the supervisor, is running.

import os
import sys
from scripts import daemon_factory

# BEWARE: This CANNOT import lib_common, otherwise circular reference.

# Test if a CGI script is running.

# Get the events created by the daemon process running the Deamon() function of a CGI script.


def _url_to_process_name(script_url):
    assert "mode=" not in script_url
    return str(script_url)


def start_events_generator_daemon(script_url):
    # See lib_util.is_snapshot_behaviour

    process_name = _url_to_process_name(script_url)

    # Remove the script parameters and pass them as CGI environment variables: QUERY_STRING etc...
    python_command = "%s %s" % (sys.executable, script_url)

    daemon_factory.start_user_process(process_name, python_command)


def is_events_generator_daemon_running(script_url):
    process_name = _url_to_process_name(script_url)
    supervisor_pid = daemon_factory.is_user_process_running(process_name)
    return supervisor_pid


