#!/usr/bin/env python

# http://www.bortzmeyer.org/wsgi.html

import os
import sys
import getopt
import socket
import wsgiref.validate
import wsgiref.simple_server
import webbrowser
import logging

if __package__:
    from . import wsgi_survol
else:
    import wsgi_survol



_port_number_default = 9000


def __print_wsgi_server_usage():
    prog_nam = sys.argv[0]
    print("Survol WSGI server: %s" % prog_nam)
    print("    -a,--address=<IP address> TCP/IP address.")
    print("    -p,--port=<number>        TCP/IP port number. Default is %d." % _port_number_default)
    print("    -b,--browser              Starts a browser.")
    print("    -v,--validate             Validate application.")
    print("    -l,--log=<level>          Log level.")
    print("")
    print("Script must be started with command: survol/scripts/wsgiserver.py")


def wsgiserver_entry_point():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "a:p:b:l:vh",
            ["address=", "port=", "browser=", "log=", "validate", "help"])
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
    validate_application = False

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
        elif an_opt in ("-v", "--validate"):
            validate_application = True
        elif an_opt in ("-h", "--help"):
            __print_wsgi_server_usage()
            sys.exit()
        else:
            assert False, "Unhandled option"

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

    start_server_forever(server_name, port_number, validate_application)

WsgiServerLogFileName = "wsgiserver.execution.log"


def start_server_forever(server_name, port_number, validate_application):
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

    if validate_application:
        validator_app = wsgiref.validate.validator(wsgi_survol.application)
        httpd = wsgiref.simple_server.make_server('', port_number, validator_app)
    else:
        httpd = wsgiref.simple_server.make_server('', port_number, wsgi_survol.application)
    print("WSGI server running on port %i..." % port_number)
    # Respond to requests until process is killed
    httpd.serve_forever()

    logfil.write(__file__ + " leaving\n")
    logfil.close()


if __name__ == '__main__':
    # If this is called from the command line, we are in test mode and must use the local Python code,
    # and not use the installed packages.
    wsgiserver_entry_point()
