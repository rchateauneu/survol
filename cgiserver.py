#!/usr/bin/python

YappiProfile = False
try:
    import yappi
except ImportError:
    YappiProfile = False

import sys
import getopt
import os

# If Apache is not available or if we want to run the website
# with a specific user account.

# In Apache httpd.conf, we have the directive:
# SetEnv PYTHONPATH C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\htbin\revlib
# It is also possible to set it globally in the .profile
# if not we get the error, for example:  import lib_pefile.
# sys.path.append('survol/revlib')

# Several problems with this script.
# * It fails if a page is called survol.htm
# * It collapses repeated slashes "///" into one "/".

# extraPath = "survol/revlib"
#extraPath = "survol;survol/revlib"
#try:
#    os.environ[pyKey] = os.environ[pyKey] + ";" + extraPath
#except KeyError:
#     os.environ[pyKey] =extraPath
#os.environ.copy()

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


def Usage():
    print("Survol HTTP server")

def RunCgiServer():

    if 'win' in sys.platform:
        # This is necessary for revlib which is otherwise not found.
        pyKey = "PYTHONPATH"
        # extraPath = "survol/revlib"
        # extraPath = "survol;survol/revlib"
        extraPath = "survol"
        try:
            os.environ[pyKey] = os.environ[pyKey] + ";" + extraPath
        except KeyError:
            os.environ[pyKey] =extraPath
        os.environ.copy()

    # This also works on Windows and Python 3.
    if 'linux' in sys.platform:
        sys.path.append("survol")
        # sys.path.append("survol/revlib")
        sys.stderr.write("path=%s\n"% str(sys.path))

    #sys.path.append("survol")
    #sys.path.append("tralala")
    #sys.path.append("survol/revlib")
    #sys.stderr.write("Sys.PathA=%s\n"%str(sys.path))


    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:b:v", ["help", "port=","browser=","verbose"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)  # will print something like "option -a not recognized"
        Usage()
        sys.exit(2)

    verbose = False
    port_number = 8000
    browser_name = None

    for anOpt, aVal in opts:
        if anOpt == ("-v", "--verbose"):
            verbose = True
        elif anOpt in ("-p", "--port"):
            port_number = int(aVal)
        elif anOpt in ("-b", "--browser"):
            browser_name = aVal
        elif anOpt in ("-h", "--help"):
            usage()
            sys.exit()
        else:
            assert False, "Unhandled option"

    print("Opening port %d" % port_number)

    if sys.version_info[0] < 3:
        # Not finished.
        import CGIHTTPServer
        import BaseHTTPServer
        from BaseHTTPServer import HTTPServer
        from CGIHTTPServer import _url_collapse_path
        class MyCGIHTTPServer(CGIHTTPServer.CGIHTTPRequestHandler):
        # class MyCGIHTTPServer(CGIHTTPRequestHandler):
          def is_cgi(self):
            collapsed_path = _url_collapse_path(self.path)
            for path in self.cgi_directories:
                if path in collapsed_path:
                    dir_sep_index = collapsed_path.rfind(path) + len(path)
                    head, tail = collapsed_path[:dir_sep_index], collapsed_path[dir_sep_index + 1:]
                    self.cgi_info = head, tail
                    return True
            return False

        server = BaseHTTPServer.HTTPServer
        handler = MyCGIHTTPServer

        handler.cgi_directories = [ "survol" ]
        print("Cgi directories=%s" % handler.cgi_directories)
        server = HTTPServer(('localhost', port_number), handler)

        ServerForever(server)

    else:
        from http.server import CGIHTTPRequestHandler, HTTPServer
        class MyCGIHTTPServer(CGIHTTPRequestHandler):
            def is_cgi(self):
                sys.stdout.write("is_cgi self.path=%s\n" % self.path)

                # By defaut, self.cgi_directories=['/cgi-bin', '/htbin']
                sys.stdout.write("self.cgi_directories=%s\n" % self.cgi_directories)

                # https://stackoverflow.com/questions/17618084/python-cgihttpserver-default-directories
                self.cgi_info = '', self.path[1:]
                # So it always work.
                return True

                # HOW CAN IT WORK ALTHOUGH THE PATH SHOULD NOT CONTAIN "cgi-bin" PR "/htin"
                # TODO: What is the equivalent of _url_collapse_path ?
                if True:
                    collapsed_path = self.path
                else:
                    collapsed_path = _url_collapse_path(self.path)

                for path in self.cgi_directories:
                    if path in collapsed_path:
                        dir_sep_index = collapsed_path.rfind(path) + len(path)
                        head, tail = collapsed_path[:dir_sep_index], collapsed_path[dir_sep_index + 1:]
                        self.cgi_info = head, tail
                        return True
                return False

        handler = MyCGIHTTPServer
        server = HTTPServer(('localhost', port_number), handler)
        server.serve_forever()

if __name__ == '__main__':
    # os.chdir("..")
    currDir = os.getcwd()
    #sys.path.append(os.path.join(currDir,"survol"))
    #sys.path.append(os.path.join(currDir,"survol","revlib"))
#    sys.path.append("survol")
#    sys.path.append("survol/revlib")
    sys.stderr.write("cwd=%s path=%s\n"% (currDir, str(sys.path)))
    RunCgiServer()
