#!/usr/bin/python

# Ce script CGI affiche la liste des sources RDF
# pour visualiser un process.
import os
import re
import cgi
import lib_common
import psutil

# arguments = cgi.FieldStorage()

print("""Content-type: text/html

<head>
 <title>RDF sources per process</title>
<script language="javascript">
function OnClickProcess(url)
{
	pid = document.getElementById("selected_pid").value;

	if( pid == null )
	{
		alert("It is necessary to select a process");
		return;
	}

	complete_url = url + "?entity_id=" + pid

	document.location.href = complete_url;
	return;
}
</script>
</head>
<body>
""")

print("""
<form>
<table border="1">
""")

start = '..'
sources = '/sources_types/process'
rootdir = start + sources
print("getcwd=" + os.getcwd() + "<br>")
print("Dir=" + rootdir + "<br>")
print("UriRoot=" + lib_util.uriRoot + "<br>")

rgx = re.compile ('^cgi_.*.py$')

for subdir, dirs, files in os.walk(rootdir):
	for file in files:
		if rgx.match( file ):
			filnam = subdir+'/'+file
			url = lib_util.uriRoot + '/sources/' + filnam

			print('<tr>')
			print('<td>')
			# print('<a href="' + url + '">' + filnam + '</href>')
			print('<a onClick="OnClickProcess(' + "'" + url + "')" + '" href="#">' + filnam + '</a>')
			print('</td>')
			print('</tr>')
print("""
</table>
""")

print("""
<select name="processes" id ="selected_pid">
""")

for proc in psutil.process_iter():
	procName = proc.name
	pid = proc.pid
	print('<option value="' + str(pid) + '">' + procName + '</option>')

print("""
</select>
""")

print("""
</form>
""")

print("""
<br><a href="directory.py">Top-level RDF sources</a>
""")

print("""
</body></html>
""")

