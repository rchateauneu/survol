#!/usr/bin/python

# Ce script CGI affiche la liste des sources RDF.
# Ca supplee au serveur SLP. Rien d'indispensable,
# mais plus complet.
import os
import re
import cgi
import lib_common

# CA NE DEVRAIT PAS ALLER DANS LE MEME DIRECTORY QUE LE MERGE.

# HTTP_HOST and SERVER_NAME and SERVER_PORT

arguments = cgi.FieldStorage()

print("""Content-type: text/html

<head>
 <title>Directory and various useful links</title>
</head>
<body>
List of RDF sources, displayed with HTTP.
It would be possible to generate a json variable.
The point of this script is that it is faster than SLP.
Onthe other hand it works only with local scripts.<br>
<table border="1">""")

rootdir = '../sources'
print("getcwd=" + os.getcwd() + "<br>")
print("Dir=" + rootdir + "<br>")

rgx = re.compile ('^cgi_.*.py$')

for subdir, dirs, files in os.walk(rootdir):
	for file in files:
		if rgx.match( file ):
			filnam = subdir+'/'+file
			url = lib_common.UriRoot() + '/sources/' + filnam

			print '<tr>'
			print '<td>'
			print '<a href="' + url + '">' + file + '</href>'
			print '</td>'
			print '</tr>'
		# else:
			# print "KO:" + file

print("""</table>

<br>And for the sake of development convenience, here is a list of 
our dev-only URLs:
	<table border=1>
""")

print('<tr><td><a href="' + os.environ['SCRIPT_NAME'] + '">This page</a></td></tr>')

print("""
	<tr><td><a href="file:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/merge_rdf_inputs_graphviz_only.htm#">Display and merge URLs sources displayed with SLP</a></td></tr>
	<tr><td><a href="file:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/merge_rdf_inputs.htm#">Same, but more sophisticated</a></td></tr>
	<tr><td><a href="file:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/display_rdf_to_json.htm?rdf_url=merge_result.rdf">In progress: Display RDF in Javascript</a></td></tr>
	<tr><td>f<a href="ile:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/metacgiview.htm#">Edits and builds URLs made of merged sources</a></td></tr>
""")

print('<tr><td><a href="' + lib_common.DynCgi() + '">Internal list of bookmarks, displayed in Json</a></td></tr>')
print('<tr><td><a href="' + lib_common.SlpMenu() + '">Internal list of SLP sources, displayed in Json</a></td></tr>')

print("""
	<tr><td><a href="file:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/build_merge.htm#">Nice display of SLP sources,</a></td></tr>
	<tr><td><a href="file:///home/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/build_merge.htm#">Build merges, with Javascript drag-and-drop</a></td></tr>
	</table>
</body></html>
""")

