#!/usr/bin/env python

# This is a minimal HTTP server intended to replace Apache or IIS.
# The benefit is that it uses only builtins class: No package installation
# is necessary. Also, because it it very simple and started as a command-line program,
# debugging is easier.
#
# Also, this script can be run under any privileged account giving much more exploration
# possibilities than the safe apache IISUSR user accounts.

# The directory "survol" must be in PYTHONPATH to access lib_common.py etc...

import sys
import platform
import getopt
import os
import socket
import datetime

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

# Apache setup:
# In Apache httpd.conf, we have the directive:

def __run_server_forever(server):
    sys.stderr.write("__run_server_forever\n")
    if YappiProfile:
        try:
            yappi.start()
            server.serve_forever()
        except KeyboardInterrupt:
            print("Leaving")
            yappi.get_func_stats().print_all()
            yappi.get_thread_stats().print_all()
    else:
        server.serve_forever()

# Different specific cases:
# * In development mode, one process serves the HTML files of the UI and the Python files of the Agent,
#   all of them stored in the same directory. No cross-site scripting needed.
# * When deployed, acts as an Agent by running CGI scripts from lib-packages Python installed modules.
# * When deployed, acts as an Agent by running the single Python CGI script which imports installed modules.
# * When deployed, acts as a UI by running the HTML pages from the installation directory,
#   or from the directory defined by distutils or pkg_resources.

port_number_default = 8000

def __print_cgi_server_usage():
    progNam = sys.argv[0]
    print("Survol CGI server: %s"%progNam)
    print("    -a,--address=<IP address> TCP/IP address")
    print("    -p,--port=<number>        TCP/IP port number. Default is %d." %(port_number_default) )
    # Ex: -b "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
    print("    -b,--browser=<program>    Starts a browser")
    print("    -v,--verbose              Verbose mode")
    print("")
    print("Script must be started with command: survol/scripts/cgiserver.py")


# https://docs.python.org/2/library/webbrowser.html
def __open_url_with_webbrowser(browser_name, the_url):
    """This starts a browser with the specific module to do it"""

    import webbrowser

    # TODO: Parses the argument from the parameter
    webbrowser.open(the_url, new=0, autoraise=True)

def __open_url_with_new_browser_process(browser_name, the_url):
    """This starts a browser whose executable is given on the command line"""
    # Import only if needed.
    import threading
    import time
    import subprocess

    def __starts_browser_process():

        print("About to start browser: %s %s"%(browser_name,the_url))

        # Leaves a bit of time so the HTTP server can start.
        time.sleep(5)

        subprocess.check_call([browser_name, the_url])

    threading.Thread(target=__starts_browser_process).start()
    print("Browser thread started")

# It is also possible to call the script from command line.
def __run_cgi_server_internal():

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:p:b:v", ["help","address=","port=","browser=","verbose"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        __print_cgi_server_usage()
        sys.exit(2)

    # It must be the same address whether it is local or guessed from another machine.
    # Equivalent to os.environ['SERVER_NAME']
    # server_name = "rchateau-HP"
    # server_name = "DESKTOP-NI99V8E"
    # It is possible to force this address to "localhost" or "127.0.0.1" for example.
    # Consider also: socket.gethostbyname(socket.getfqdn())

    server_name = socket.gethostname()

    server_addr = socket.gethostbyname(server_name)

    verbose = False
    port_number = port_number_default
    browser_name = None

    for anOpt, aVal in opts:
        if anOpt in ("-v", "--verbose"):
            verbose = True
        elif anOpt in ("-a", "--address"):
            server_name = aVal
        elif anOpt in ("-p", "--port"):
            port_number = int(aVal)
        elif anOpt in ("-b", "--browser"):
            browser_name = aVal
        elif anOpt in ("-h", "--help"):
            __print_cgi_server_usage()
            sys.exit()
        else:
            assert False, "Unhandled option"

    currDir = os.getcwd()
    if verbose:
        print("cwd=%s path=%s"% (currDir, str(sys.path)))


    # The script must be started from a specific directory to ensure the URL.
    # See AddUrlPrefix() and TopScriptsFunc() to simplify things.
    filMyself = open("survol/scripts/cgiserver.py")
    if not filMyself:
        print("Script started from wrong directory")
        __print_cgi_server_usage()
        sys.exit()
    

    theUrl = "http://" + server_name
    if port_number:
        if port_number != 80:
            theUrl += ":%d" % port_number
    theUrl += "/survol/www/index.htm"
    print("Url:"+theUrl)

    # Starts a thread which will starts the browser.
    if browser_name:

        if browser_name.startswith("webbrowser"):
            __open_url_with_webbrowser(browser_name,theUrl)
        else:
            __open_url_with_new_browser_process(browser_name,theUrl)
        print("Browser thread started to:"+theUrl)

    # Apache sets these environment variables.
    # SERVER_SOFTWARE=Apache/2.4.12 (Win64) OpenSSL/1.0.1m mod_wsgi/4.4.12 Python/2.7.10
    # SERVER_NAME=rchateau-hp
    # SERVER_ADDR=fe80::3c7a:339:64f0:2161
    # HTTP_HOST=rchateau-hp

    # print("os.environ['SERVER_NAME']='%s'" % (os.environ['SERVER_NAME']) )
    print("Platform=%s"%sys.platform)
    print("Version:%s"% str(sys.version_info))
    if 'win' in sys.platform:
        print("os.sys.getwindowsversion()=", os.sys.getwindowsversion())
        print("platform.win32_ver()=", platform.win32_ver())
    print("platform.release()=", platform.release())
    print("Server address:%s" % server_addr)
    print("Opening %s:%d" % (server_name,port_number))

    start_server_forever(verbose, server_name, port_number)

# This is used when testing on Travis, when output cannot be read.
def cgi_server_logfile_name(port_number):
    return "cgiserver.execution.%d.log" % port_number

# Setup (setup.py) creates a binary script which directly calls this function.
# The current directory can be set, this is used when this is called from multiprocessing.
def start_server_forever(verbose, server_name, port_number, current_dir = ""):
    logfil = open(cgi_server_logfile_name(port_number), "w")
    logfil.write(__file__ + " "+ datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
    logfil.write(__file__ + " startup server_name=%s port_number=%d\n" % (server_name, port_number))
    logfil.flush()

    os.environ["SERVER_SOFTWARE"] = "CGIServerPython"

    if verbose:
        sys.stderr.write("server_name=%s port_number=%d\n" % (server_name, port_number) )
        sys.stderr.write("sys.executable=%s\n" % sys.executable)
        sys.stderr.write("sys.exec_prefix=%s\n" % sys.exec_prefix)
        sys.stderr.write("getpid=%d\n" % os.getpid())
    envPYTHONPATH = "PYTHONPATH"
    if 'win' in sys.platform:
        # This is necessary for lib_util which is otherwise not found.
        extraPath = "survol"
        try:
            os.environ[envPYTHONPATH] = os.environ[envPYTHONPATH] + os.pathsep + extraPath
        except KeyError:
            os.environ[envPYTHONPATH] = extraPath
        os.environ.copy()

    # This also works on Windows and Python 3.
    elif 'linux' in sys.platform:
        extraPath = "survol"
        try:
            os.environ[envPYTHONPATH] = os.environ[envPYTHONPATH] + os.pathsep + extraPath
        except KeyError:
            os.environ[envPYTHONPATH] = extraPath
    else:
        print("Unsupported platform:%s"%sys.platform)

    # print("sys.path=%s"% str(sys.path))
    try:
        sys.stderr.write("os.environ['%s']=%s\n"% (envPYTHONPATH,os.environ[envPYTHONPATH]))
    except KeyError:
        print("os.environ['%s']=%s"% (envPYTHONPATH,"Not defined"))

    if current_dir:
        os.chdir(current_dir)
        sys.stderr.write("getcwd=%s\n" % os.getcwd() )
    if sys.version_info[0] < 3:
        import CGIHTTPServer
        import BaseHTTPServer
        from BaseHTTPServer import HTTPServer
        from CGIHTTPServer import _url_collapse_path
        class MyCGIHTTPServer(CGIHTTPServer.CGIHTTPRequestHandler):
            def is_cgi(self):
                # self.path = "/survol/entity.py?xid=odbc/table.Dsn=DSN~MyNativeSqlServerDataSrc,Table=VIEWS"
                collapsed_path = _url_collapse_path(self.path)
                if verbose:
                    sys.stderr.write("is_cgi getpid=%d\n" % os.getpid())
                    sys.stderr.write("is_cgi collapsed_path=%s getcwd=%s\n" % (collapsed_path, os.getcwd()))

                uprs = urlparse(collapsed_path)
                pathOnly = uprs.path

                fileName, fileExtension = os.path.splitext(pathOnly)

                urlPrefix = "/survol/"
                if fileExtension == ".py" and pathOnly.startswith(urlPrefix):
                    dir_sep_index = len(urlPrefix)-1
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

        sys.stderr.write("server.server_name=%s\n" % server.server_name)

        __run_server_forever(server)

    else:
        from http.server import CGIHTTPRequestHandler, HTTPServer
        class MyCGIHTTPServer(CGIHTTPRequestHandler):
            def is_cgi(self):
                if verbose:
                    sys.stderr.write("is_cgi self.path=%s\n" % self.path)

                # https://stackoverflow.com/questions/17618084/python-cgihttpserver-default-directories
                self.cgi_info = '', self.path[1:]
                # So it always works.
                uprs = urlparse(self.path)
                pathOnly = uprs.path

                # This interprets cr-nl.
                logging.info('\n')

                fileName, fileExtension = os.path.splitext(pathOnly)
                return fileExtension == ".py"

            # Not strictly necessary, but useful hook for debugging.
            def run_cgi(self):
                super(MyCGIHTTPServer, self).run_cgi()

        # Purpose is to understand why it does not interpret cr-nl.
        import logging
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S')
        logging.info(__file__ + ' test logging.')
        logging.info('\n')
        # logging.warning('new hello')

        handler = MyCGIHTTPServer
        server = HTTPServer((server_name, port_number), handler)

        # Testing Win10 and Python 3
        logfil.write(__file__ + " sys.platform=%s\n" % sys.platform)
        server.server_name = server_name

        # FIXME: Win3 and carriage return, in Pycharm..
        if 'win' in sys.platform:
            import msvcrt
            # msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            # It does not work either. Problem is that it receives binary strings.
            msvcrt.setmode(sys.stdout.fileno(), os.O_TEXT)

            # With this, still it does not interpret carriage-returns.
            # Maybe it is open as binary and should be reopen as text ?
            # sys.stderr = sys.stdout

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
    # survol/entity.py
    __run_cgi_server_internal()

    # TODO: Once started, it could register itself to Service Location Protocol (SLP),
    # for example with the Python 3 module pyslp.
    # this is what WBEM uses for services discovery.
