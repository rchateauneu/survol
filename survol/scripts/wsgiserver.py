#!/usr/bin/env python

# http://www.bortzmeyer.org/wsgi.html

import os
import sys
import getopt
import socket
import importlib
import wsgiref.simple_server as server

# See lib_client.py with similar code which cannot be imported here.
# This expects bytes (Py3) or str (Py2).
def CreateStringStream():
    from io import BytesIO
    return BytesIO()

# This models the output of the header and the content.
# See the class lib_util.OutputMachineCgi
class OutputMachineWsgi:
    def __init__(self, start_response):
        # FIXME: This is not efficient because Survol creates a string stored in the stream,
        # FIXME: then converted to a string, then written to the socket.
        # FIXME: Ideally, this should be written in one go from for example lib_common.CopyToOut,
        # FIXME: to the output socket.
        self.m_output = CreateStringStream()
        self.m_start_response = start_response
        self.m_header_called = False

    def __del__(self):
        # Close object and discard memory buffer --
        # .getvalue() will now raise an exception.
        self.m_output.close()

    def Content(self):
        if not self.m_header_called:
            sys.stderr.write("OutputMachineWsgi.Content HeaderWriter not called.\n")
        self.m_header_called = False
        str_value = self.m_output.getvalue()
        if sys.version_info >= (3,):
            if type(str_value) == str:
                str_value = str_value.encode()
        else:
            if type(str_value) == unicode:
                str_value = str_value.encode()
        return str_value

    # extraArgs is an array of key-value tuples.
    def HeaderWriter(self, mimeType, extraArgs= None):
        if self.m_header_called:
            sys.stderr.write("OutputMachineWsgi.HeaderWriter already called: mimeType=%s. RETURNING.\n"%mimeType)
            return
        self.m_header_called = True
        status = '200 OK'
        response_headers = [('Content-type', mimeType)]
        self.m_start_response(status, response_headers)

    def OutStream(self):
        return self.m_output

def app_serve_file(path_info, start_response):
    file_name = path_info[1:]
    sys.stderr.write("app_serve_file file_name:%s cwd=%s\n" % (file_name, os.getcwd()))
    # Just serve a plain HTML or CSS file.
    response_headers = [('Content-type', 'text/html')]

    try:
        of = open(file_name, "rb")
        file_content = of.read()
        of.close()
        sys.stderr.write("app_serve_file file read OK\n")
        sys.stderr.write("Writing type=%s\n" % type(file_content))

        start_response('200 OK', response_headers)

        sys.stderr.write("Writing %d bytes\n" % len(file_content))

        return [ file_content ]
    except Exception as exc:
        start_response('200 OK', response_headers)
        sys.stderr.write("app_serve_file caught %s\n" % str(exc))
        return [ "<html><head></head><body>app_serve_file file_name=%s: Caught:%s</body></html>" % (file_name, exc)]

global_module = None

verbose_debug_mode = False


# environ[SERVER_SOFTWARE]=WSGIServer/0.1 Python/2.7.10
# Maybe some non-string and undocumented values:
# environ[wsgi.errors         ]=<open file '<stderr>', mode 'w' at 0x0000000001CEA150>
# environ[wsgi.file_wrapper   ]=wsgiref.util.FileWrapper
# environ[wsgi.input          ]=<socket._fileobject object at 0x0000000002990A98>
# environ[wsgi.multiprocess   ]=False
# environ[wsgi.multithread    ]=True
# environ[wsgi.run_once       ]=False
# environ[wsgi.url_scheme     ]=http
# environ[wsgi.version        ]=(1, 0)
def application_ok(environ, start_response):
    global global_module

    if verbose_debug_mode:
        sys.stderr.write("application_ok: environ\n")
        for key in sorted(environ.keys()):
            sys.stderr.write("application_ok:environ[%-20s]=%-20s\n"%(key,environ[key]))

        sys.stderr.write("application_ok: os.environ\n")
        for key in sorted(os.environ.keys()):
            sys.stderr.write("application_ok:os.environ[%-20s]=%-20s\n"%(key,os.environ[key]))

    # Must be done BEFORE IMPORTING, so the modules can have the good environment at init time.
    for key in ["QUERY_STRING","SERVER_PORT"]:
        os.environ[key] = environ[key]

    # This is necessary for security reasons.
    os.environ["REMOTE_ADDR"] = environ["REMOTE_ADDR"]

    # This is necessary for error processing, if the header must be sent once only,
    # and before the content.
    # environ["SERVER_PROTOCOL"] = "HTTP/1.1"
    # environ["SERVER_SOFTWARE"] = "WSGIServer/0.2"
    os.environ["SERVER_SOFTWARE"] = environ["SERVER_SOFTWARE"]

    # The wsgi Python module sets a value for SERVER_NAME that we do not want.
    os.environ["SERVER_NAME"] = os.environ["SURVOL_SERVER_NAME"]

    ### sys.stderr.write("os.environ['SCRIPT_NAME']=%s\n"%os.environ['SCRIPT_NAME'])
    os.environ["PYTHONPATH"] = "survol" # Not needed if installed ??

    # Not sure this is needed on all platforms.
    os.environ.copy()

    # Example: "/survol/entity_dirmenu_only.py"
    pathInfo = environ['PATH_INFO']

    # This environment variable is parsed in UriRootHelper
    # os.environ["SCRIPT_NAME"] = "/survol/see_wsgiserver"
    # SCRIPT_NAME=/survol/print_environment_variables.py
    # REQUEST_URI=/survol/print_environment_variables.py?d=s
    # QUERY_STRING=d=s
    os.environ["SCRIPT_NAME"] = pathInfo

    # All modules must be explicitly loaded, because importing is not recursive:
    # The path is imported but if it tries to import another module, the initialisation code
    # of this module will be run only when leaving the first imported module; which is too late.
    # This must be done only when environment variables are properly set.
    if not global_module:
        global_module = importlib.import_module("entity")
        sys.stderr.write("application_ok: Loaded global module")

    # If "http://127.0.0.1:8000/survol/sources_top/enumerate_CIM_LogicalDisk.py?xid=."
    # then "/survol/sources_top/enumerate_CIM_LogicalDisk.py"
    sys.stderr.write("application_ok: pathInfo=%s\n" % pathInfo)

    # Example: pathInfo=/survol/www/index.htm
    if pathInfo.find("/survol/www/") >= 0 or pathInfo.find("/ui/css") >= 0 :
        return app_serve_file(pathInfo, start_response)

    pathInfo = pathInfo.replace("/",".")

    modulePrefix = "survol."
    htbinIndex = pathInfo.find(modulePrefix)

    assert pathInfo.endswith(".py")
    pathInfo = pathInfo[htbinIndex + len(modulePrefix):-3] # "Strips ".py" at the end.

    # ["sources_types","enumerate_CIM_LogicalDisk"]
    splitPathInfo = pathInfo.split(".")

    import lib_util

    # This is the needed interface so all our Python machinery can write to the WSGI server.
    theOutMach = OutputMachineWsgi(start_response)

    if len(splitPathInfo) > 1:
        modulesPrefix = ".".join( splitPathInfo[:-1] )

        # Tested with Python2 on Windows.
        # Example: entity_type = "Azure.location"
        # entity_module = importlib.import_module( ".subscription", "sources_types.Azure")
        moduleName = "." + splitPathInfo[-1]
        sys.stderr.write("application_ok: moduleName=%s modulesPrefix=%s\n" % (moduleName,modulesPrefix))
        the_module = importlib.import_module( moduleName, modulesPrefix )

        # TODO: Apparently, if lib_util is imported again, it seems its globals are initialised again. NOT SURE...
        lib_util.globalOutMach = theOutMach

    else:
        # Tested with Python2 on Windows.

        # TODO: Strange: Here, this load lib_util a second time.
        sys.stderr.write("application_ok: pathInfo=%s\n" % pathInfo)
        the_module = importlib.import_module(pathInfo)

        # TODO: Apparently, if lib_util is imported again, it seems its globals are initialised again. NOT SURE...
        lib_util.globalOutMach = theOutMach

    script_name = os.environ['SCRIPT_NAME']
    sys.stderr.write("application_ok: scriptNam=%s\n" % script_name)

    try:
        the_module.Main()
    except Exception as exc:
        sys.stderr.write("application_ok caught %s in Main()\n" % exc)
        raise

    try:
        # TODO: Use yield for better performance.
        module_content = lib_util.globalOutMach.Content()
    except Exception as exc:
        sys.stderr.write("application_ok: caught from Content():%s\n" % exc)
        # The HTTP header is not written because of the exception. This calls start_response.
        lib_util.globalOutMach.HeaderWriter('text/html')
        module_content = "Message: application_ok caught:%s\n" % exc

    return [ module_content ]

def application(environ, start_response):
    try:
        return application_ok(environ, start_response)
    except Exception as exc:

        import lib_util

        lib_util.globalOutMach.HeaderWriter('text/html')
        module_content = "Message: application caught:%s\n" % exc
        return ["<html><head></head><body>Error:%s</body></html>" % module_content]


port_number_default = 9000

def Usage():
    progNam = sys.argv[0]
    print("Survol WSGI server: %s"%progNam)
    print("    -a,--address=<IP address> TCP/IP address")
    print("    -p,--port=<number>        TCP/IP port number. Default is %d." %(port_number_default) )
    # Ex: -b "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
    print("    -b,--browser=<program>    Starts a browser")
    print("    -v,--verbose              Verbose mode")
    print("")
    print("Script must be started with command: survol/scripts/cgiserver.py")

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

def RunWsgiServer():

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

    StartWsgiServer(server_name, port_number, current_dir="")

def StartWsgiServer(server_name, port_number, current_dir=""):

    server_addr = socket.gethostbyname(server_name)

    print("Platform=%s\n"%sys.platform)
    print("Version:%s\n"% str(sys.version_info))
    print("Server address:%s" % server_addr)
    print("Opening %s:%d" % (server_name,port_number))

    # The script must be started from a specific directory because of the URLs.
    if current_dir:
        os.chdir(current_dir)
        sys.stderr.write("StartWsgiServer getcwd=%s\n" % os.getcwd() )
    try:
        filMyself = open("survol/scripts/wsgiserver.py")
    except Exception as exc:
        print("Script started from wrong directory %s: exc=%s" % (os.getcwd(), exc))
        Usage()
        sys.exit()

    sys.path.append("survol")
    sys.stderr.write("path=%s\n" % str(sys.path))

    # This expects that environment variables are propagated to subprocesses.
    os.environ["SURVOL_SERVER_NAME"] = server_name
    sys.stderr.write("server_name=%s\n"% server_name)

    httpd = server.make_server('', port_number, application)
    print("WSGI server running on port %i..." % port_number)
    # Respond to requests until process is killed
    httpd.serve_forever()

if __name__ == '__main__':
    # If this is called from the command line, we are in test mode and must use the local Python code,
    # and not use the installed packages.
    RunWsgiServer()
