#!/usr/bin/env python
#
# THIS IS A WORK IN PROGRESS.
#
# The intention is to implement another server using the Python module twisted.
# The benefit is that it is probably faster and more powerful that the builtins class.
# This uses CGI scripts as they are, just like Apache or cgiserver.py
#
# WSGI needs an intermediary bytes strings retuened by a function called application().
# The intention is to avoid this temporary variable which can be big,
# but instead directly wroites to the output network socket.
#
# https://jcalderone.livejournal.com/tag/sixty%20seconds

import sys

if __package__:
    from . import daemon_factory
else:
    import daemon_factory

#raise Exception("Not implemented yet")

# Possible implementation: Iterate on all CGI scripts:
if False:
    from twisted.web.twcgi import CGIScript
    resource = CGIScript("/survol/entity.py")

    def start_server():
        daemon_factory.supervisor_startup()

# There is a standard way to start a defined twisted server, from the command line.
if False:
    from twisted.web.resource import Resource
    from twisted.web import server
    class MySite(Resource):
        def render_GET(self, request):
            request.write("<!DOCTYPE html>")
            request.write("<html><head>")
            request.write("<title>Twisted Driven Site</title>")
            request.write("</head><body>")
            request.write("<h1>Twisted Driven Website</h1>")
            request.write("<p>Prepath: <pre>{0}</pre></p>".format(request.prepath))
            request.write("</body></html>")
            request.finish()
            return server.NOT_DONE_YET

    resource = mysite.MySite()

# This is started with the command: python cgitwisted.py
if False:
    from twisted.internet import reactor
    from twisted.web import static, server, twcgi
    from twisted.python import log

    log.startLogging(sys.stdout)
    log.msg("Starting server")

    # This works with favicon.ico
    root = static.File("")
    # root = static.File("/survol")
    # root.putChild("cgi-bin", twcgi.CGIDirectory("/survol/www/cgi-bin"))
    the_dir = r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\survol"
    root.putChild("survol", twcgi.CGIDirectory(the_dir))

    reactor.listenTCP(10000, server.Site(root))
    reactor.run()



