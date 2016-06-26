#!/usr/bin/python

import os
import re
import cgi

# HTTP_HOST and SERVER_NAME and SERVER_PORT

arguments = cgi.FieldStorage()

print("""Content-type: text/html

<head>
 <title>Environment variables</title>
</head>
<body>
<table border="1">""")

start = '..'
sources = '/sources'
rootdir = start + sources
print("getcwd=" + os.getcwd() + "<br>")
print("Dir=" + rootdir + "<br>")

print("Cgi vars<br>")
for key, value in os.environ.items():
	print( key + "=" + value + "<br>")
print("Cgi vars end<br><br>")

print("""
<br>And for the sake of development convenience, here is a list of 
our dev-only URLs:
	<table border=1>
""")

try:
	print('<tr><td><a href="' + os.environ['SCRIPT_NAME'] + '">This page</a></td></tr>')
except KeyError:
	print('<tr><td>SCRIPT_NAME environment variable is not defined</td></tr>')


print("""
	<tr><td><a href="file:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/merge_rdf_inputs_graphviz_only.htm#">Display and merge URLs sources displayed with SLP</a></td></tr>
	<tr><td><a href="file:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/merge_rdf_inputs.htm#">Same, but more sophisticated</a></td></tr>
	<tr><td><a href="file:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/display_rdf_to_json.htm?rdf_url=merge_result.rdf">In progress: Display RDF in Javascript</a></td></tr>
	<tr><td><a href="ile:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/metacgiview.htm#">Edits and builds URLs made of merged sources</a></td></tr>
""")

print("""
	<tr><td><a href="file:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/build_merge.htm#">Nice display of SLP sources,</a></td></tr>
	<tr><td><a href="file:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/build_merge.htm#">Build merges, with Javascript drag-and-drop</a></td></tr>
	</table>
""")

print("""
</body></html>
""")



