#!/usr/bin/env python

# The intention is to implement another server using the Python module twisted.
# The benefit is that it is probably faster and more powerful that the builtins class.
# This uses CGI scripts as they are, just like Apache or cgiserver.py
#
# https://jcalderone.livejournal.com/tag/sixty%20seconds

if __package__:
    from . import daemon_factory
else:
    import daemon_factory
daemon_factory.supervisor_startup()

raise Exception("Not implemented yet")

# Possible implementation: Iterate on all CGI scripts:
from twisted.web.twcgi import CGIScript
resource = CGIScript("/survol/entity.py")
