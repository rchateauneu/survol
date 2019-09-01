#!/usr/bin/env python

# Original Yawn URL example:
# http://192.168.1.88/yawn/EnumInstanceNames/LMI_ServiceAffectsIdentity?url=https%3A%2F%2FUnknown-30-b5-c2-02-0c-b5-2.home&verify=1&ns=root%2Fcimv2


import sys
import os

# Might be pywbem or python3-pywbem.
import pywbem
import wbem_utils

try:
	from urlparse import urlparse
except ImportError:
	from urllib.parse import urlparse

try:
	import Cookie as cookies
except ImportError:
    # Python 3
    import http
    from http import cookies


#C = cookies.SimpleCookie()
#C["fig"] = "newton"
#C.load("chips=ahoy; vienna=finger") # load from a string (HTTP header)

# Ca va etre un parametre CGI qui servira de clef dans les cookies,
# pour se reconnecter a chaque fois.
cgi_url = "http://192.168.1.83:5988"
url_parsed = urlparse(cgi_url)

wbem_host=url_parsed.hostname

# If port is empty, sets a default value.
wbem_port=url_parsed.port in [ None, "" ]


try:
    cookie_string=os.environ.get('HTTP_COOKIE')
    cook=cookies.SimpleCookie()
    cook.load(cookie_string)

    cookieCounter = int(cook["cookie_counter"].value)
except Exception:
    cookieCounter = 0



C = cookies.SimpleCookie()
C["fig"] = "newton"
C["sugar"] = "wafer"
C["Gling"] = "Glong"
C["rocky"] = "road"
C["rocky"]["path"] = "/cookie"
C['raspberrypi']='ValRasp'
C['raspberrypi']['expires']='Thu, 01 Jan 1970 00:00:00 GMT'
C["cookie_counter"] = str(cookieCounter+1)

# wbem_utils.Headers()

print("Content-Type: text/html")
print(C)
print("")

print("""<html>
<head></head>
<body>
""")


print("""
  <form action="/Login" method="post">
    <table>
      <tr>
        <td>URI Scheme:</td>
        <td><select id="select-scheme" name="scheme">
            <option value="https" >https</option>
            <option value="http" selected>http</option></select>
        </td>
      </tr><tr>
        <td>Host:</td><td><input id="host" type="text" name="host" value="192.168.1.83"/></td>
      </tr><tr>
        <td>Port:</td><td><input id="port" type="text" name="port" value="5988" /></td>
      </tr><tr>
        <td>Namespace:</td><td><input type="text" name="ns" /></td>
      </tr>
      <tr>
        <td></td><td><input type="submit" value="Login" /></td>
      </tr>
    </table>
  </form>
""")

print("<br>Cookies<br>")

if 'HTTP_COOKIE' in os.environ:
    cookie_string=os.environ.get('HTTP_COOKIE')
    cook=cookies.SimpleCookie()
    cook.load(cookie_string)

    for ck in cook:
        print(ck + " = " + str(cook[ck].value) + "<br>" )
else:
    print("Pas de cookie<br>")

print("FINI<br>")


print("""
</body>
</html>
""")

