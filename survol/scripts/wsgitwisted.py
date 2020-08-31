#!/usr/bin/env python

# https://jcalderone.livejournal.com/51888.html

# Just like cgitwisted, the intention is to use the Python package twisted
# to implement a WSGI server.
# See how the function application() is implemented in wsgiserver.py
# wsgiserver could be imported as a package.

raise Exception("Not implemented yet")

from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor

if __package__:
    from . import daemon_factory
else:
    import daemon_factory
daemon_factory.supervisor_startup()

def application(environ, start_response):
    start_response('200 OK', [('Content-type', 'text/plain')])
    return ['Hello, world!']


resource = WSGIResource(reactor, reactor.getThreadPool(), application)