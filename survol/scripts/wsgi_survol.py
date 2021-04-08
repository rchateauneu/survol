

import os
import sys
import traceback
import importlib
import logging
import io

if __package__:
    from . import daemon_factory
else:
    import daemon_factory


class OutputMachineWsgi:
    """
    This models the output of the header and the content.
    See the class lib_util.OutputMachineCgi
    """
    def __init__(self, start_response):
        # FIXME: This is not efficient because Survol creates a string stored in the stream,
        # FIXME: then converted to a string, then written to the socket.
        # FIXME: Ideally, this should be written in one go from for example lib_common.copy_to_output_destination,
        # FIXME: to the output socket.
        self.m_output = io.BytesIO()
        self.m_start_response = start_response
        self.m_header_called = False

    def __del__(self):
        """
        Close object and discard memory buffer.
        """
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

    def HeaderWriter(self, mime_type, extraArgs= None):
        """
        extraArgs is an array of key-value tuples.
        """
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


_global_module = None


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
    global _global_module

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

    os.environ["PYTHONPATH"] = "survol" # Not needed if the package is installed.

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
    if not _global_module:
        _global_module = importlib.import_module("entity")
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

        # Example: entity_type = "Azure.location"
        module_name = "." + split_path_info[-1]
        logging.debug("module_name=%s modules_prefix=%s", module_name, modules_prefix)
        try:
            the_module = importlib.import_module(module_name, modules_prefix)
        except Exception as exc:
            logging.error("Caught=%s" % exc)
            raise

        lib_util.globalOutMach = the_out_mach
    else:
        logging.debug("Not dot in path_info=%s" % path_info)
        the_module = importlib.import_module(path_info)

        lib_util.globalOutMach = the_out_mach

    script_name = os.environ['SCRIPT_NAME']
    logging.debug("script_name=%s" % script_name)

    try:
        # TODO: Rename this to a more visible name like MainEntryPoint.
        the_module.Main()
    except SystemExit as exc:
        if exc.code == 0:
            logging.info("Normal exit, possibly at the end of the script:%s" % exc)
        else:
            logging.info("Exit with error:%s. Reraising." % exc)
            raise
    except RuntimeError as exc:
        # Minor error thrown by ErrorMessageHtml
        logging.error("Caught %s in Main()" % exc)
        logging.error("Exception=%s" % traceback.format_exc())
    except Exception as exc:
        logging.error("Caught %s in Main()" % exc)
        logging.error("Exception=%s" % traceback.format_exc())
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


_is_supervisor_started = False


def application(environ, start_response):
    """This is required by WSGI interface"""

    global _is_supervisor_started
    if not _is_supervisor_started:
        # The daemon runs processes writing events to a database, which are later read by CGI or WSGI scripts.
        daemon_factory.supervisor_startup()
        _is_supervisor_started = True

    try:
        return application_ok(environ, start_response)
    except Exception as exc:

        import lib_util

        lib_util.globalOutMach.HeaderWriter('text/html')
        module_content = "Message: application caught:%s\n" % exc
        return ["<html><head></head><body>Error:%s</body></html>" % module_content]


