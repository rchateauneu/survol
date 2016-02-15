#!/usr/bin/python

# Ce script CGI affiche la liste des sources RDF
# pour visualiser un fichier.
import os
import sys
import re
import cgi
import lib_common
import lib_util
import urllib

# On recoit un directory en argument et par defaut "/"
# On liste les fichier: Si sous-dir, le lien est notre script avec ce sous-dir comme argument.
# Sinon entity_dir avec le fichier.
# Pour les DLL et les SO evidemment on va chercher le bon fochier
# Idem pour les liens symboliques.

arguments = cgi.FieldStorage()

if lib_util.isPlatformWindows:
	import string
	from ctypes import windll

	def get_drives():
		drives_vect = []
		# LOCALDISK = 3
		bitmask = windll.kernel32.GetLogicalDrives()
		for i in range(26):
			if (bitmask >> i) & 0x01:
				drive = chr(i+65) + ':/'
				#if windll.kernel32.GetDriveTypeA(drive) == LOCALDISK:
				drives_vect.append(drive)

		return drives_vect
		

print("""Content-type: text/html

<head>
 <title>RDF sources per files</title>
</head>
<body>
""")

print("Cwd="+os.getcwd()+"<br>")

if lib_util.isPlatformWindows:
	drvs = get_drives()
	for dev in drvs:
		url = os.environ['SCRIPT_NAME'] + "?rootdir=" + dev
		print('<a href="' + url + '">' + dev + '</a>  ')
	print('<br>')
		
try:
	rootdir = arguments["rootdir"].value
except KeyError:
	if lib_util.isPlatformWindows:
		rootdir = "C:"
	else:
		rootdir = "/"
		
print("Dir=" + rootdir + "<br>")
print("UriRoot=" + lib_util.uriRoot + "<br>")

for subdir, dirs, files in os.walk(rootdir):
	break

print("""
<table border=1>
""")

ScriptName = os.environ['SCRIPT_NAME']

if rootdir != '/':
	splitdir = rootdir.split('/')
	topdir = '/'.join( splitdir[:-1] )
	encoded_file=lib_util.EncodeUri(topdir)
	url = ScriptName + "?rootdir=" + encoded_file
	file = '..'
	print('<tr><td span=2>')
	print('<a href="')
	print(url)
	print('">' + file + '</a></td></tr>')

rootdir_slash = rootdir + "/"
for dir in dirs:
	rootfile=rootdir_slash+dir
	encoded_file=lib_util.EncodeUri(rootfile)
	url1 = ScriptName + "?rootdir=" + encoded_file
	print('<tr>')
	print('<td>')
	print('<a href="')
	print(url1)
	print('">' + dir + '</a></td>')
	# url2 = lib_util.EntityUri('file', encoded_file )
	url2 = lib_common.gUriGen.FileUri( rootfile )
	print('<td>')
	print('<a href="')
	print(url2)
	print('">' + dir + '</a> as RDF</td>')
	print('</tr>')

for file in files:
	rootfile=rootdir_slash+dir
	encoded_file=lib_util.EncodeUri(rootfile)
	# url = lib_util.EntityUri('file', encoded_file )
	url = lib_common.gUriGen.FileUri( rootfile )
	print('<tr><td colspan=2>')
	print('<a href="')
	print(url)
	print('">' + file + '</a></td></tr>')

print("""
</table>
""")

print("""
<br><a href="directory.py">Top-level RDF sources</a>
""")

print("""
</body></html>
""")

