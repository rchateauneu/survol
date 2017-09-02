#!/usr/bin/python

# http://www.bortzmeyer.org/wsgi.html

import os
import re
import sys
import importlib
import wsgiref.simple_server as server
import cStringIO

# TODO: Verifier quon peut lancer en cliquant sur wsgiserver.py ou cgiserver.py
# TODO: Permettre a wsgiserver.py d afficher les messages d erreurs.
# TODO: Maintenant que wsgi fonctionne, y adapter les scripts asyncyhrones.

def the_dflt(environ, start_response):
	status = '200 OK'
	global cnt
	output = "<h1>XXX Ga Bu Zo Meu %d</h1>\n" % cnt
	output += "<table>"
	for e in environ:
		v = str(environ[e])
		v = v.replace("<","LT").replace(">","GT")
		output += "<tr><td>%s</td><td>%s</td></tr>" % (e,v)
	output += "</table>"
	cnt += 1
	response_headers = [('Content-type', 'text/html'),
						('Content-Length', str(len(output)))]
	start_response(status, response_headers)
	return [output]

class OutputMachineWsgi:

	def __init__(self,start_response):
		sys.stderr.write("OutputMachineWsgi creation\n")
		self.m_output = cStringIO.StringIO()
		self.m_start_response = start_response

	def __del__(self):
		# Close object and discard memory buffer --
		# .getvalue() will now raise an exception.
		self.m_output.close()

	def Content(self):
		str = self.m_output.getvalue()
		sys.stderr.write("OutputMachineWsgi.Content %d\n" % len(str))
		return str

	def HeaderWriter(self,mimeType):
		sys.stderr.write("OutputMachineWsgi.HeaderWriter: %s\n"%mimeType)
		status = '200 OK'
		response_headers = [('Content-type', mimeType)]
		self.m_start_response(status, response_headers)

	def OutStream(self):
		return self.m_output

def app_serve_file(pathInfo, start_response):
	filNam = pathInfo[1:]
	sys.stderr.write("Plain file:%s\n"%filNam)
	# Just serve a plain HTML file.
	response_headers = [('Content-type', 'text/html')]

	try:
		of = open(filNam)
		fContent = of.read()
		of.close()

		start_response('200 OK',response_headers)

		sys.stderr.write("Writing %d bytes\n" % len(fContent))

		return [ fContent ]
	except:
		start_response('200 OK',response_headers)
		return [ "<html><head></head><body>Broken</body></html>" ]

def application_ok(environ, start_response):
	# Must be done BEFORE IMPORTING, so the modules can have the good environment at init time.
	for key in ["QUERY_STRING","SERVER_PORT"]:
		os.environ[key] = environ[key]
	# This environment variable is parsed in UriRootHelper
	os.environ["SCRIPT_NAME"] = "/survol/"
	os.environ["PYTHONPATH"] = "survol" # Not needed if installed ??
	os.environ.copy()

	pathInfo = environ['PATH_INFO']

	# If "http://127.0.0.1:8000/survol/sources_top/enumerate_CIM_LogicalDisk.py?xid=."
	# then "/survol/sources_top/enumerate_CIM_LogicalDisk.py"
	sys.stderr.write("pathInfo=%s\n"%pathInfo)

	pathInfo = pathInfo.replace("/",".")

	modulePrefix = "survol."
	htbinIndex = pathInfo.find(modulePrefix)

	# This is not a Python file. Most probably a html file.
	if htbinIndex < 0:
		return app_serve_file(pathInfo, start_response)

	pathInfo = pathInfo[htbinIndex + len(modulePrefix):-3] # "Strips ".py" at the end.

	# ["sources_top","enumerate_CIM_LogicalDisk"]
	splitPathInfo = pathInfo.split(".")

	# TODO: THIS WORKS BUT WHYYYYYYYYYYYYYYYYYYYYYYYYYYY  ?????
	if splitPathInfo[-1] == "entity":
		from revlib import lib_util
	else:
		import lib_util

	# This is the needed interface so all our Python machinery can write to the WSGI server.
	theOutMach = OutputMachineWsgi(start_response)

	if len(splitPathInfo) > 1:
		modulesPrefix = ".".join( splitPathInfo[:-1] )

		# Tested with Python2 on Windows.
		# Example: entity_type = "Azure.location"
		# entity_module = importlib.import_module( ".subscription", "sources_types.Azure")
		moduleName = "." + splitPathInfo[-1]
		sys.stderr.write("LOADING moduleName=%s modulesPrefix=%s\n" % (moduleName,modulesPrefix))
		the_module = importlib.import_module( moduleName, modulesPrefix )

		# TODO: Apparently, if lib_util is imported again, it seems its globals are initialised again. NOT SURE...
		lib_util.globalOutMach = theOutMach

	else:
		# Tested with Python2 on Windows.

		# TODO: Strange: Here, this load lib_util a second time.
		sys.stderr.write("LOADING pathInfo=%s\n" % pathInfo)
		the_module = importlib.import_module( pathInfo )

		# TODO: Apparently, if lib_util is imported again, it seems its globals are initialised again. NOT SURE...
		lib_util.globalOutMach = theOutMach

	#for k in sys.modules:
	#	v = sys.modules[k]
	#	if re.match( ".*lib_util.*", k):
	#		sys.stderr.write("MODULES %s %s\n"%(k,str(v)))

	scriptNam=os.environ['SCRIPT_NAME']
	sys.stderr.write("scriptNam1=%s\n"%scriptNam)

	the_module.Main()
	sys.stderr.write("After Main\n")
	return [ lib_util.globalOutMach.Content() ]

def application(environ, start_response):
	# return application_ok(environ, start_response)
	try:
		return application_ok(environ, start_response)
	except:
		exc = sys.exc_info()
		sys.stderr.write("CAUGHT:%s\n"%str(exc))
		return the_dflt(environ, start_response)

def RunWsgi():
	cnt=0

	port = 9000

	httpd = server.make_server('', port, application)
	print "Serving HTTP on port %i..." % port
	# Respond to requests until process is killed
	httpd.serve_forever()

if __name__ == '__main__':
    sys.path.append("survol")
    sys.path.append("survol/revlib")
    sys.stderr.write("path=%s\n"% str(sys.path))
	RunWsgiServer()
