#!/usr/bin/python

import sys
import cgi

# Might be pywbem or python3-pywbem.
import pywbem
import wbem_utils


arguments = cgi.FieldStorage()
cgiUrl = arguments["url"].value

conn = wbem_utils.WbemConnection(cgiUrl)

wbem_utils.Headers()

print("""<html>
<head></head>
<body>
""")

nsd = wbem_utils.EnumNamespacesCapabilities(conn)

print("<table border=1>")
for nskey in nsd:
    sys.stdout.write("<tr>")
    sys.stdout.write("<td>" + wbem_utils.HrefNamespace(nskey, cgiUrl) + "</td>")
    cnt = nsd[nskey]
    if cnt == 0:
        sys.stdout.write("<td>" + str(cnt) + "</td>")
    else:
        sys.stdout.write("<td>" + "<a href='" + wbem_utils.UrlNamespace(nskey, cgiUrl, True) + "'>" + str(cnt) + "</a>" + "</td>")
    sys.stdout.write("</tr>")
print("</table>")
print("<br>")

print("""
<br><a href="../index.htm">Return home</a>
</body>
</html>
""")