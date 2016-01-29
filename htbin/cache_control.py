#!/usr/bin/python

import os
import re
import urllib

import cgi
import lib_common
import lib_infocache

print ("""Content-Type: text/html

<html>
<head>
<title>URLs information cache control and management</title>
</head>
<body>
""")

g_infoCache = lib_infocache.InfoCache()

arguments = cgi.FieldStorage()
try:
	valAct = arguments['submit_cleanup'].value
except KeyError:
	valAct = ""

if valAct == "Cleanup":
	print("Cleanup<br>")
	g_infoCache.Clean()
else:
	print("Display only<br>")

# If not a cleanup, then normal display.

print('<table border=1 width="100%">')
print("<tr><td colspan=3>Info cache content:" + g_infoCache.m_cacheFileName + "</td></tr>")
print("<tr><td>Url</td><td>Information</td><td>Status</td></tr>")

for key in g_infoCache.m_cacheDict:
	print("<tr>")
	print('<td><a href="' + key + '">' + key + "</a></td>")
	val = g_infoCache.m_cacheDict[key]
	try:
		print("<td>" + str(val['info']) + "</td>")
	except KeyError:
		print("<td>No info</td>")

	try:
		print("<td>" + str(val['Status']) + "</td>")
	except KeyError:
		print("<td>No Status</td>")
	print("</tr>")

print("</table>")


print("""
<br>
<br>
<form action="cache_control.py" method="post">
<input type="submit" name="submit_cleanup" value="Cleanup">
<input type="submit" name="submit_refresh" value="Refresh">
</form>
""")



print("""
<br>
<a href="../index.htm">Home</a>
</body>
</html>
""")
