#!/usr/bin/python
#!C:\Program Files (x86)\Python32\pythonw.exe

# Ce script CGI affiche la liste des sources RDF.
# Ca supplee au serveur SLP. Rien d'indispensable,
# mais plus complet.
import os
import re
import lib_common
import lib_util

print("""Content-type: text/html

<head>
 <title>Directory and various useful links</title>
</head>
<body>
List of RDF sources, displayed with HTTP.
The point of this script is that it is faster than SLP.
On the other hand it works only with local scripts.<br>
<table border="1">""")

start = '..'
sources = '/sources'
rootdir = start + sources
print("getcwd=" + os.getcwd() + "<br>")
print("Dir=" + rootdir + "<br>")
print("UriRoot=" + lib_util.uriRoot + "<br>")

print("""
<tr><td>RDF</td><td>HTML</td></tr>
""")


for subdir, dirs, files in os.walk(rootdir):
	for file in files:
		tstCgi = re.match( '^cgi_.*.py$', file )
		# NOTE: Did not manage to merge the two regular expressions into one.
		# Slash and backslash for Unix and Windows.
		tstBY = re.match( r'.*sources_types/.*', subdir ) or re.match( r'.*sources_types\BY_.*', subdir ) 
		if tstCgi and not tstBY:
			filnam = subdir+'/'+file
			# Forces the output as "rdf" because the default value is "svg".
			url_rdf = lib_util.uriRoot + sources + '/' + filnam + "?mode=rdf"
			url_html = "rdf2html.py?url=" + lib_util.EncodeUri(url_rdf)

			print('<tr>')
			print('<td><a href="' + url_rdf + '">' + filnam + '</href></td>')
			print('<td><a href="' + url_html + '">' + filnam + '</href></td>')

			url_merge_remote = lib_common.Url2Svg( url_rdf )
			print( "<td>" )
			print( "<a href='" + url_merge_remote + "'>SVG remote url</a>" )
			print( "</td>" )

			print('</tr>')
		# else:
			# print "KO:" + file

print("""</table>
""")

print("""
<br><a href="rdfroot.py">Same data sources, but in RDF format</a><br>
""")

print("""
<br><a href="directory_BY_process.py">Data sources per process</a><br>
""")

print("""
<br><a href="directory_BY_file.py">data sources per file</a><br>
""")

print("""
<br><a href="directory_BY_smbshr.py">Data sources per samba share</a><br>
""")

print("Cgi vars<br>")
for key, value in os.environ.items():
	print( key + "=" + value + "<br>")
print("Cgi vars end<br><br>")


print("""
<br>And for the sake of development convenience, here is a list of 
our dev-only URLs:
	<table border=1>
""")

print('<tr><td><a href="' + os.environ['SCRIPT_NAME'] + '">This page</a></td></tr>')


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
<br>Finished
</body></html>
""")



