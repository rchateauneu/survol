#!/usr/bin/env python

from __future__ import print_function

# This is a minimal HTTP server intended to replace Apache or IIS.
# The benefit is that it uses only builtins class: No package installation
# is necessary. Also, because it it very simple and started as a command-line program,
# debugging is easier.
#
# Also, this script can be run under any privileged account giving much more exploration
# possibilities than the safe apache IISUSR user accounts.

# This script is used in different cases:
# * In development mode, one process serves the HTML files of the UI and the Python files of the Agent,
#   all of them stored in the same directory. No cross-site scripting needed.
# * When deployed, acts as an Agent by running CGI scripts from lib-packages Python installed modules.
# * When deployed, acts as an Agent by running the single Python CGI script which imports installed modules.
# * When deployed, acts as a UI by running the HTML pages from the installation directory,
#   or from the directory defined by distutils or pkg_resources.

# The directory "survol" must be in PYTHONPATH to access lib_common.py etc...

import sys
import platform
import getopt
import os
import socket
import datetime
import atexit
import webbrowser
import logging

if __package__:
    from . import daemon_factory
else:
    import daemon_factory

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


def __run_server_forever(server):
    logging.info("__run_server_forever.")
    server.serve_forever()


_port_number_default = 8000


# So it can be restored.
original_dir = os.getcwd()


def __print_cgi_server_usage():
    prog_nam = sys.argv[0]
    print("Survol CGI server: %s"%prog_nam)
    print("    -a,--address=<IP address> TCP/IP address.")
    print("    -p,--port=<number>        TCP/IP port number. Default is %d." % _port_number_default)
    # Ex: -b "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
    print("    -b,--browser              Starts a browser.")
    print("    -l,--log                  Log level.")
    print("")


def _exit_handler():
    daemon_factory.supervisor_stop()
    os.chdir(original_dir)


def cgiserver_entry_point():
    """Note: It is also possible to call the script from command line."""

    logging.debug("cgiserver_entry_point")

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:p:bl:", ["help", "address=", "port=", "browser", "log"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        __print_cgi_server_usage()
        sys.exit(2)

    # It must be the same address whether it is local or guessed from another machine.
    # Equivalent to os.environ['SERVER_NAME']
    # server_name = "mymachine"
    # server_name = "DESKTOP-NI99V8E"
    # It is possible to force this address to "localhost" or "127.0.0.1" for example.
    # Consider also: socket.gethostbyname(socket.getfqdn())

    server_name = socket.gethostname()

    try:
        server_addr = socket.gethostbyname(server_name)
    except socket.gaierror as exc:
        # socket.gaierror: [Errno 8] nodename nor servname provided, or not known
        print("Caught", exc, ". Attempting to append '.local'")
        try:
            server_name += ".local"
            server_addr = socket.gethostbyname(server_name)
        except Exception as exc:
            print("Caught", exc, ". Server name must be entered with option '-a'")

    port_number = _port_number_default
    start_browser = False

    for an_opt, a_val in opts:
        if an_opt in ("-l", "--log"):
            logging.getLogger().setLevel(a_val.upper())
            os.environ["SURVOL_LOGGING_LEVEL"] = a_val.upper()
        elif an_opt in ("-a", "--address"):
            server_name = a_val
        elif an_opt in ("-p", "--port"):
            port_number = int(a_val)
        elif an_opt in ("-b", "--browser"):
            start_browser = True
        elif an_opt in ("-h", "--help"):
            __print_cgi_server_usage()
            sys.exit()
        else:
            assert False, "Unhandled option"

    # Here, the server starts for good.
    daemon_factory.supervisor_startup()

    atexit.register(_exit_handler)

    # The script must be started from a specific directory for URLs of CGI scripts.
    good_dir = os.path.join(os.path.dirname(__file__), "..", "..")
    os.chdir(good_dir)

    the_url = "http://" + server_name
    if port_number:
        if port_number != 80:
            the_url += ":%d" % port_number
    the_url += "/survol/www/index.htm"
    print("Url:" + the_url)

    if start_browser:
        webbrowser.open(the_url, new=0, autoraise=True)
        print("Browser started to:"+the_url)

    # Apache sets these environment variables.
    # SERVER_SOFTWARE=Apache/2.4.12 (Win64) OpenSSL/1.0.1m mod_wsgi/4.4.12 Python/2.7.10
    # SERVER_NAME=mymachine
    # SERVER_ADDR=fe80::3c7a:339:64f0:2161
    # HTTP_HOST=mymachine

    # print("os.environ['SERVER_NAME']='%s'" % (os.environ['SERVER_NAME']) )
    print("Platform=%s" % sys.platform)
    print("Version:%s" % str(sys.version_info))
    if sys.platform.startswith("win32"):
        print("os.sys.getwindowsversion()=", os.sys.getwindowsversion())
        print("platform.win32_ver()=", platform.win32_ver())
    print("platform.release()=", platform.release())
    print("Server address:%s" % server_addr)
    print("Opening %s:%d" % (server_name, port_number))

    logging.debug("server_name=%s port_number=%d" % (server_name, port_number))
    logging.debug("sys.executable=%s" % sys.executable)
    logging.debug("sys.exec_prefix=%s" % sys.exec_prefix)
    logging.debug("getpid=%d" % os.getpid())

    start_server_forever(server_name, port_number)


def cgi_server_logfile_name(port_number):
    """
    This is used when testing on Travis, when output cannot be read.
    This is a last-chance solution, when the logging module is not enough.
    """
    return "cgiserver.execution.%d.log" % port_number


def start_server_forever(server_name, port_number, current_dir=""):
    """
    Setup (setup.py) creates a binary script which directly calls this function.
    The current directory can be set, this is used when this is called from multiprocessing.
    """

    import logging

    logfil = open(cgi_server_logfile_name(port_number), "w")
    logfil.write(__file__ + " " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
    logfil.write(__file__ + " startup server_name=%s port_number=%d\n" % (server_name, port_number))
    logfil.flush()

    os.environ["SERVER_SOFTWARE"] = "CGIServerPython"

    # Maybe this function is started by tests/init.py.
    if "SERVER_PORT" not in os.environ:
        os.environ["SERVER_PORT"] = str(port_number)


    # This sets PYTHONPATH for the CGI scripts.
    envPYTHONPATH = "PYTHONPATH"
    if sys.platform.startswith("win32"):
        # This is necessary for lib_util which is otherwise not found.
        extra_path = "survol"
        try:
            os.environ[envPYTHONPATH] = os.environ[envPYTHONPATH] + os.pathsep + extra_path
        except KeyError:
            os.environ[envPYTHONPATH] = extra_path
        os.environ.copy()

    # This also works on Windows and Python 3.
    elif sys.platform.startswith("linux"):
        extra_path = "survol"
        try:
            os.environ[envPYTHONPATH] = os.environ[envPYTHONPATH] + os.pathsep + extra_path
        except KeyError:
            os.environ[envPYTHONPATH] = extra_path
    elif sys.platform.startswith("darwin"):
        extra_path = "survol"
        try:
            os.environ[envPYTHONPATH] = os.environ[envPYTHONPATH] + os.pathsep + extra_path
        except KeyError:
            os.environ[envPYTHONPATH] = extra_path
    else:
        print("Unsupported platform:%s" % sys.platform)

    try:
        logging.debug("os.environ['%s']=%s" % (envPYTHONPATH, os.environ[envPYTHONPATH]))
    except KeyError:
        logging.debug("os.environ['%s']=%s" % (envPYTHONPATH, "Not defined"))

    if current_dir:
        os.chdir(current_dir)
        logging.debug("getcwd=%s" % os.getcwd())
    if sys.version_info[0] < 3:
        import CGIHTTPServer
        from BaseHTTPServer import HTTPServer
        from CGIHTTPServer import _url_collapse_path

        class MyCGIHTTPServer(CGIHTTPServer.CGIHTTPRequestHandler):
            def is_cgi(self):
                collapsed_path = _url_collapse_path(self.path)
                logging.debug("is_cgi getpid=%d" % os.getpid())
                logging.debug("is_cgi collapsed_path=%s getcwd=%s" % (collapsed_path, os.getcwd()))

                uprs = urlparse(collapsed_path)
                path_only = uprs.path

                file_name, file_extension = os.path.splitext(path_only)

                url_prefix = "/survol/"
                if file_extension == ".py" and path_only.startswith(url_prefix):
                    dir_sep_index = len(url_prefix)-1
                    head, tail = collapsed_path[:dir_sep_index], collapsed_path[dir_sep_index + 1:]
                    self.cgi_info = head, tail
                    return True
                else:
                    return False

            # Not strictly necessary, but useful hook for debugging.
            def run_cgi(self):
                # This starts a Python subprocess.
                CGIHTTPServer.CGIHTTPRequestHandler.run_cgi(self)

        handler = MyCGIHTTPServer

        server = HTTPServer((server_name, port_number), handler)

        # server.server_name is later stored to os.environ["SERVER_NAME"].
        # Here, this environment variable must have the same value
        # as the server address, because it is used to build URLs.
        # It is not properly set on Linux.
        # Same for Windows Py2 and an Internet provider ("hostname.broadband")
        server.server_name = server_name

        logging.info("server.server_name=%s" % server.server_name)

        __run_server_forever(server)

    else:
        # For an obscure reason, the module logging must be imported again.
        import logging
        from http.server import CGIHTTPRequestHandler, HTTPServer

        class MyCGIHTTPServer(CGIHTTPRequestHandler):
            def is_cgi(self):
                logging.debug("is_cgi self.path=%s" % self.path)

                # https://stackoverflow.com/questions/17618084/python-cgihttpserver-default-directories
                self.cgi_info = '', self.path[1:]
                # So it always works.
                uprs = urlparse(self.path)
                path_only = uprs.path

                file_name, file_extension = os.path.splitext(path_only)
                return file_extension == ".py"

            def run_cgi(self):
                """
                Not strictly necessary, because it just calls the base class method, but useful hook for debugging.
                """
                super(MyCGIHTTPServer, self).run_cgi()

            def log_error(self, format, *args):
                """
                This method overrides BaseHTTPRequestHandler.log_error

                Needed because \r\n are escaped on Python 3.
                This is true for stderr output and also logging.
                """

                if sys.platform.startswith("win32"):
                    message_string = format % args
                    message_split = message_string.split(r"\r\n")
                    for one_message in message_split:
                        sys.stderr.write(one_message + "\n")
                else:
                    # TODO: Check what is the behaviour on Linux.
                    super(MyCGIHTTPServer, self).log_error(format, *args)


        handler = MyCGIHTTPServer
        server = HTTPServer((server_name, port_number), handler)

        # Testing Win10 and Python 3
        logging.info(__file__ + " sys.platform=%s" % sys.platform)

        server.server_name = server_name

        server.serve_forever()
    logfil.close()


if __name__ == '__main__':
    # If this is called from the command line, we are in test mode and must use the local Python code,
    # and not use the installed packages.
    # Here are the directories:
    # www/index.htm
    # www/js/base64.js
    #
    # In this mode, we assume that the Python scripts are here, on the same server.
    cgiserver_entry_point()

    # TODO: Once started, it could register itself to Service Location Protocol (SLP),
    # for example with the Python 3 module pyslp. This is what WBEM uses for services discovery.
