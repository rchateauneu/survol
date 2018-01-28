#!/usr/bin/python

# This is a minimal HTTP server intended to replace Apache or IIS.
# First reason is that, on a small machine, no HTTP server might be available.
# 
# Also, this script can be run under any privileged account giving much more exploration
# possibilities than the safe apache IISUSR user accounts.


# This can be used for profiling.
# Unfortunately, it does not work yet with threads and subprocesses.
YappiProfile = False
try:
    import yappi
except ImportError:
    YappiProfile = False

import sys
import getopt
import os
import socket

try:
	from urlparse import urlparse
except ImportError:
	from urllib.parse import urlparse

# Apache setup:
# In Apache httpd.conf, we have the directive:
# SetEnv PYTHONPATH C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\htbin\revlib
# It is also possible to set it globally in the .profile
# if not we get the error, for example:  import lib_pefile.
# sys.path.append('survol/revlib')

def ServerForever(server):
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

def Usage():
    progNam = sys.argv[0]
    print("Survol HTTP server: %s"%progNam)
    print("    -a,--address=<IP address> TCP/IP address")
    print("    -p,--port=<number>        TCP/IP port number. Default is %d." %(port_number_default) )
    # Ex: -b "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
    print("    -b,--browser=<program>    Starts a browser")
    print("    -v,--verbose              Verbose mode")
    print("")
    print("Script must be started with command: survol/scripts/cgiserver.py"

# Setup creates a binary script which directly calls this function.
# This changes the current directory, so that URLs can point to plain Python scripts.
# This can be avoided if we have an unique CGI script loading Python scripts as modules.
def RunCgiServer():
    curPth = None
    print("Searching internal packages")
    for pth in sys.path:
        if pth.endswith("site-packages"):
            curPth = pth
            break

    if curPth:
        print("Setting current path to %s"%curPth)
        os.chdir(curPth)
        RunCgiServerInternal()
    else:
        print("No python path to set")

# https://docs.python.org/2/library/webbrowser.html
def StartsWebrowser(browser_name,theUrl):
    """This starts a browser with the specific module to do it"""

    import webbrowser

    # TODO: Parses the argument from the parameter
    webbrowser.open(theUrl, new=0, autoraise=True)

def StartsBrowser(browser_name,theUrl):
    """This starts a browser whose executable is given on the command line"""
    # Import only if needed.
    import threading
    import time
    import subprocess

    def StartBrowserProcess():

        print("About to start browser: %s %s"%(browser_name,theUrl))

        # Leaves a bit of time so the HTTP server can start.
        time.sleep(5)

        subprocess.check_call([browser_name, theUrl])

    threading.Thread(target=StartBrowserProcess).start()
    print("Browser thread started")

# It is also possible to call the script from command line.
def RunCgiServerInternal():

    envPYTHONPATH = "PYTHONPATH"
    if 'win' in sys.platform:
        # This is necessary for revlib which is otherwise not found.
        extraPath = "survol"
        try:
            os.environ[envPYTHONPATH] = os.environ[envPYTHONPATH] + ";" + extraPath
        except KeyError:
            os.environ[envPYTHONPATH] =extraPath
        os.environ.copy()

    # This also works on Windows and Python 3.
    elif 'linux' in sys.platform:
        # It seems that the cgi script is executed in another process
        # therefore chaning sys.argv does not do anything.
        try:
            os.environ["PYTHONPATH"]
        except KeyError:
            os.environ["PYTHONPATH"] = "/home/rchateau/rdfmon-code/survol"

    else:
        print("Unsupported platform:%s"%sys.platform)

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ha:p:b:v", ["help","address=","port=","browser=","verbose"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        Usage()
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
            Usage()
            sys.exit()
        else:
            assert False, "Unhandled option"

    currDir = os.getcwd()
    if verbose:
        print("cwd=%s path=%s"% (currDir, str(sys.path)))


    # The script must be started from a specific directory to ensure the URL.
    filMyself = open("survol/scripts/cgiserver.py")
    if not filMyself:
        print("Script started from wrong directory")
        Usage()
        sys.exit()
    

    # print("os.environ['SERVER_NAME']='%s'" % (os.environ['SERVER_NAME']) )
    print("Platform=%s\n"%sys.platform)
    print("Version:%s\n"% str(sys.version_info))
    print("Server address:%s" % server_addr)
    print("Opening %s:%d" % (server_name,port_number))
    # print("sys.path=%s"% str(sys.path))
    try:
        print("os.environ['%s']=%s"% (envPYTHONPATH,os.environ[envPYTHONPATH]))
    except KeyError:
        print("os.environ['%s']=%s"% (envPYTHONPATH,"Not defined"))

    theUrl = "http://" + server_name
    if port_number:
        if port_number != 80:
            theUrl += ":%d" % port_number
    theUrl += "/survol/www/index.htm"
    print("Url:"+theUrl)

    # Starts a thread which will starts the browser.
    if browser_name:

        if browser_name.startswith("webbrowser"):
            StartsWebrowser(browser_name,theUrl)
        else:
            StartsBrowser(browser_name,theUrl)
        print("Browser thread started to:"+theUrl)

    # https://stackoverflow.com/questions/32241082/python-access-control-allow-origin
    # CORS Cross-site scripting must be activated.

    # Apache sets these environment variables.
    # SERVER_SOFTWARE=Apache/2.4.12 (Win64) OpenSSL/1.0.1m mod_wsgi/4.4.12 Python/2.7.10
    # SERVER_NAME=rchateau-hp
    # SERVER_ADDR=fe80::3c7a:339:64f0:2161
    # HTTP_HOST=rchateau-hp

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
                    print("is_cgi collapsed_path=%s"%collapsed_path)

                uprs = urlparse(collapsed_path)
                pathOnly = uprs.path
                # print("is_cgi pathOnly=%s"%pathOnly)

                fileName, fileExtension = os.path.splitext(pathOnly)

                # print("is_cgi pathOnly=%s fileExtension=%s"%(pathOnly,fileExtension))

                urlPrefix = "/survol/"
                if fileExtension == ".py" and pathOnly.startswith(urlPrefix):
                    dir_sep_index = len(urlPrefix)-1
                    head, tail = collapsed_path[:dir_sep_index], collapsed_path[dir_sep_index + 1:]
                    # print("is_cgi YES head=%s tail=%s"%(head, tail))
                    self.cgi_info = head, tail
                    return True
                else:
                    # print("is_cgi NOT")
                    return False

        server = BaseHTTPServer.HTTPServer
        handler = MyCGIHTTPServer

        server = HTTPServer((server_name, port_number), handler)

        if 'linux' in sys.platform:
            # Normally, this value receives socket.gethostname(),
            # which later gives its value to os.environ["SERVER_NAME"].
            # But, for this application, this environment variable must have the same value
            # as the server address, because it is used to build URLs.
            # Therefore, we are indirectly setting the value of the environment variable "SERVER_NAME".
            # This is not necessary for Windows (Which apparently copies its env vars).
            # This must be tested on Python 3.
            server.server_name = server_name
            print("server=%s"%(server.server_name))

        ServerForever(server)

    else:
        from http.server import CGIHTTPRequestHandler, HTTPServer
        class MyCGIHTTPServer(CGIHTTPRequestHandler):
            def is_cgi(self):
                if verbose:
                    sys.stdout.write("is_cgi self.path=%s\n" % self.path)

                # By defaut, self.cgi_directories=['/cgi-bin', '/htbin']
                sys.stdout.write("self.cgi_directories=%s\n" % self.cgi_directories)

                # https://stackoverflow.com/questions/17618084/python-cgihttpserver-default-directories
                self.cgi_info = '', self.path[1:]
                # So it always work.
                uprs = urlparse(self.path)
                pathOnly = uprs.path
                # print("is_cgi pathOnly=%s"%pathOnly)

                # This interprets cr-nl.

                logging.info('\n')

                fileName, fileExtension = os.path.splitext(pathOnly)
                return fileExtension == ".py"

        # Purpose is to understand why it does not interpret cr-nl.
        import logging
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s', datefmt='%H:%M:%S')
        logging.info('hello')
        logging.info('\n')
        # logging.warning('new hello')

        handler = MyCGIHTTPServer
        server = HTTPServer((server_name, port_number), handler)

        # Testing Win10 and Python 3
        if 'win' in sys.platform:
            # Normally, this value receives socket.gethostname(),
            # which later gives its value to os.environ["SERVER_NAME"].
            # But, for this application, this environment variable must have the same value
            # as the server address, because it is used to build URLs.
            # Therefore, we are indirectly setting the value of the environment variable "SERVER_NAME".
            # This is not necessary for Windows (Which apparently copies its env vars).
            # This must be tested on Python 3.
            server.server_name = server_name
            print("server=%s"%(server.server_name))
            # os.environ["SERVER_NAME"] = server_name


        if 'win' in sys.platform:
            import msvcrt
            # msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
            # It does not work either. Problem is that it receives binary strings.
            msvcrt.setmode(sys.stdout.fileno(), os.O_TEXT)

            # With this, still it does not interpret carriage-returns.
            # Maybe it is open as binary and should be reopen as text ?
            # sys.stderr = sys.stdout

        server.serve_forever()

if __name__ == '__main__':
    # If this is called from the command line, we are in test mode and must use the local Python code,
    # and not use the installed packages.
    # Here are the directories:
    # www/index.htm
    # www/js/base64.js
    #
    # In this mode, we assume that the Python scripts are here, on the same server.
    # survol/entity.py
    RunCgiServerInternal()

    # TODO: Once started, it could register itself to Service Location Protocol (SLP),
    # for example with the Python 3 module pyslp.
    # this is what WBEM uses for services discovery.
