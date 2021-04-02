#!/usr/bin/env python

# http://www.bortzmeyer.org/wsgi.html

import os
import sys
import getopt
import socket
import traceback
import importlib
import wsgiref.simple_server as server
import webbrowser
import logging
import io

if __package__:
    from . import daemon_factory
else:
    import daemon_factory


# This models the output of the header and the content.
# See the class lib_util.OutputMachineCgi
# TODO: We could have a much simpler implementation by changing the value of sys.stdout.
# TODO: We would detect the end of the header on the fly.
# TODO: The advantage is that it would work with plain CGI scripts.
class OutputMachineWsgi:
    def __init__(self, start_response):
        # FIXME: This is not efficient because Survol creates a string stored in the stream,
        # FIXME: then converted to a string, then written to the socket.
        # FIXME: Ideally, this should be written in one go from for example lib_common.copy_to_output_destination,
        # FIXME: to the output socket.
        self.m_output = io.BytesIO()
        self.m_start_response = start_response
        self.m_header_called = False

    def __del__(self):
        # Close object and discard memory buffer --
        # .getvalue() will now raise an exception.
        self.m_output.close()

    def Content(self):
        if not self.m_header_called:
            logging.error("Warning OutputMachineWsgi.Content HeaderWriter not called.")
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
    def HeaderWriter(self, mime_type, extraArgs= None):
        if self.m_header_called:
            logging.error("OutputMachineWsgi.HeaderWriter already called: mimeType=%s. RETURNING." % mime_type)
            return
        self.m_header_called = True
        status = '200 OK'
        response_headers = [('Content-type', mime_type)]
        self.m_start_response(status, response_headers)

    def OutStream(self):
        return self.m_output


def app_serve_file(path_info, start_response):
    file_name = path_info[1:]
    logging.debug("app_serve_file file_name:%s cwd=%s", file_name, os.getcwd())
    # Just serve a plain HTML or CSS file.
    response_headers = [('Content-type', 'text/html')]

    try:
        of = open(file_name, "rb")
        file_content = of.read()
        of.close()
        logging.debug("app_serve_file file read OK")
        logging.debug("Writing type=%s" % type(file_content))

        start_response('200 OK', response_headers)

        logging.debug("Writing %d bytes" % len(file_content))

        return [file_content]
    except Exception as exc:
        start_response('200 OK', response_headers)
        logging.error("app_serve_file caught %s" % exc)
        return ["<html><head></head><body>app_serve_file file_name=%s: Caught:%s</body></html>" % (file_name, exc)]


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
        logging.debug("environ")
        for key in sorted(environ.keys()):
            logging.debug("environ[%-20s]=%-20s", key, environ[key])

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

    os.environ["PYTHONPATH"] = "survol" # Not needed if installed ??

    # FIXME: Is this needed on all platforms.
    os.environ.copy()

    # Example: "/survol/entity_dirmenu_only.py"
    path_info = environ['PATH_INFO']

    # This environment variable is parsed in UriRootHelper
    # os.environ["SCRIPT_NAME"] = "/survol/see_wsgiserver"
    # SCRIPT_NAME=/survol/print_environment_variables.py
    # REQUEST_URI=/survol/print_environment_variables.py?d=s
    # QUERY_STRING=d=s
    os.environ["SCRIPT_NAME"] = path_info

    # All modules must be explicitly loaded, because importing is not recursive:
    # The path is imported but if it tries to import another module, the initialisation code
    # of this module will be run only when leaving the first imported module; which is too late.
    # This must be done only when environment variables are properly set.
    if not global_module:
        global_module = importlib.import_module("entity")
        logging.debug("Loaded global module")

    # If "http://127.0.0.1:8000/survol/sources_top/enumerate_CIM_LogicalDisk.py?xid=."
    # then "/survol/sources_top/enumerate_CIM_LogicalDisk.py"
    logging.debug("path_info=%s" % path_info)

    # Example: path_info=/survol/www/index.htm
    if path_info.find("/survol/www/") >= 0 \
            or path_info.find("/ui/css") >= 0 \
            or path_info == '/favicon.ico':
        return app_serve_file(path_info, start_response)

    path_info = path_info.replace("/", ".")

    module_prefix = "survol."
    htbin_index = path_info.find(module_prefix)

    if not path_info.endswith(".py"):
        logging.error("path_info=%s should be a Python script" % path_info)
        raise Exception("application_ok: path_info=%s is not a Python script" % path_info)

    path_info = path_info[htbin_index + len(module_prefix):-3] # "Strips ".py" at the end.

    # ["sources_types","enumerate_CIM_LogicalDisk"]
    split_path_info = path_info.split(".")

    import lib_util

    # This is the needed interface so all our Python machinery can write to the WSGI server.
    the_out_mach = OutputMachineWsgi(start_response)

    if len(split_path_info) > 1:
        modules_prefix = ".".join(split_path_info[:-1])

        # Tested with Python2 on Windows and Linux.
        # Example: entity_type = "Azure.location"
        # entity_module = importlib.import_module( ".subscription", "sources_types.Azure")
        module_name = "." + split_path_info[-1]
        logging.error("module_name=%s modules_prefix=%s", module_name, modules_prefix)
        try:
            the_module = importlib.import_module(module_name, modules_prefix)
        except Exception as exc:
            logging.error("Caught=%s" % exc)
            raise

        # TODO: Apparently, if lib_util is imported again, it seems its globals are initialised again. NOT SURE...
        lib_util.globalOutMach = the_out_mach

    else:
        logging.error("Not dot in path_info=%s" % path_info)
        the_module = importlib.import_module(path_info)

        lib_util.globalOutMach = the_out_mach

    script_name = os.environ['SCRIPT_NAME']
    logging.debug("script_name=%s" % script_name)

    try:
        # TODO: Rename this to a more visible name like MainEntryPoint.
        the_module.Main()
    except RuntimeError as exc:
        # Minor error thrown by ErrorMessageHtml
        logging.error("Caught %s in Main()" % exc)
        logging.error("Exception=%s" % traceback.format_exc())
    except Exception as exc:
        logging.error("Caught %s in Main()" % exc)
        logging.error("Exception=%s" % traceback.format_exc() )
        raise

    try:
        # TODO: Use yield for better performance.
        module_content = lib_util.globalOutMach.Content()
    except Exception as exc:
        logging.error("Caught from Content():%s" % exc)
        # The HTTP header is not written because of the exception. This calls start_response.
        lib_util.globalOutMach.HeaderWriter('text/html')
        module_content = "Message: application_ok caught:%s\n" % exc

    return [module_content]


def application(environ, start_response):
    """This is required by WSGI"""
    try:
        return application_ok(environ, start_response)
    except Exception as exc:

        import lib_util

        lib_util.globalOutMach.HeaderWriter('text/html')
        module_content = "Message: application caught:%s\n" % exc
        return ["<html><head></head><body>Error:%s</body></html>" % module_content]


_port_number_default = 9000


def __print_wsgi_server_usage():
    progNam = sys.argv[0]
    print("Survol WSGI server: %s"%progNam)
    print("    -a,--address=<IP address> TCP/IP address.")
    print("    -p,--port=<number>        TCP/IP port number. Default is %d." % _port_number_default)
    print("    -b,--browser              Starts a browser.")
    print("    -l,--log                  Log level.")
    print("")
    print("Script must be started with command: survol/scripts/wsgiserver.py")


def wsgiserver_entry_point():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "ha:p:bl:",
            ["help", "address=", "port=", "browser=", "log"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        __print_wsgi_server_usage()
        sys.exit(2)

    # It must be the same address whether it is local or guessed from another machine.
    # Equivalent to os.environ['SERVER_NAME']
    # server_name = "mymachine"
    # server_name = "DESKTOP-NI99V8E"
    # It is possible to force this address to "localhost" or "127.0.0.1" for example.
    # Consider also: socket.gethostbyname(socket.getfqdn())

    server_name = socket.gethostname()

    port_number = _port_number_default
    start_browser = False

    for an_opt, a_val in opts:
        if an_opt in ("-l", "--log"):
            logging.basicConfig(level=a_val.upper())
            os.environ["SURVOL_LOGGING_LEVEL"] = a_val.upper()
        elif an_opt in ("-a", "--address"):
            server_name = a_val
        elif an_opt in ("-p", "--port"):
            port_number = int(a_val)
        elif an_opt in ("-b", "--browser"):
            start_browser = True
        elif an_opt in ("-h", "--help"):
            __print_wsgi_server_usage()
            sys.exit()
        else:
            assert False, "Unhandled option"

    # Here, the server starts for good.
    daemon_factory.supervisor_startup()

    curr_dir = os.getcwd()
    logging.debug("cwd=%s path=%s", curr_dir, str(sys.path))

    the_url = "http://" + server_name
    if port_number:
        if port_number != 80:
            the_url += ":%d" % port_number
    the_url += "/survol/www/index.htm"
    print("Url:"+the_url)

    if start_browser:
        webbrowser.open(the_url, new=0, autoraise=True)
        print("Browser started to:" + the_url)

    start_server_forever(server_name, port_number, current_dir="")

WsgiServerLogFileName = "wsgiserver.execution.log"


def start_server_forever(server_name, port_number, current_dir=""):
    logfil = open(WsgiServerLogFileName, "w")
    logfil.write(__file__ + " startup\n")
    logfil.flush()

    logging.debug(__file__ + " redirection stderr")

    server_addr = socket.gethostbyname(server_name)

    logging.debug("Platform=%s" % sys.platform)
    logging.debug("Version:%s" % str(sys.version_info))
    logging.debug("Server address:%s" % server_addr)
    logging.debug("sys.path:%s" % str(sys.path))
    logging.debug("Opening %s:%d", server_name, port_number)

    # The script must be started from a specific directory because of the URLs.
    good_dir = os.path.join(os.path.dirname(__file__), "..", "..")
    os.chdir(good_dir)

    sys.path.append("survol")
    logging.info("path=%s" % str(sys.path))

    # This expects that environment variables are propagated to subprocesses.
    os.environ["SURVOL_SERVER_NAME"] = server_name
    logging.info("server_name=%s" % server_name)

    logfil.flush()

    httpd = server.make_server('', port_number, application)
    print("WSGI server running on port %i..." % port_number)
    # Respond to requests until process is killed
    httpd.serve_forever()

    logfil.write(__file__ + " leaving\n")
    logfil.close()


if __name__ == '__main__':
    # If this is called from the command line, we are in test mode and must use the local Python code,
    # and not use the installed packages.
    wsgiserver_entry_point()
