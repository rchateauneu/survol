# The intention is to implement another server using the Python module twisted.
# The benefit is that it is probably faster and more powerful that the builtins class.
# This uses CGI scripts as they are, just like Apache or cgiserver.py
#
# https://jcalderone.livejournal.com/tag/sixty%20seconds

# Possible implementation: Iterate on all CGI scripts:
from twisted.web.twcgi import CGIScript
resource = CGIScript("/survol/entity.py")
