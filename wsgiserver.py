#!/usr/bin/python

# http://www.bortzmeyer.org/wsgi.html

import sys
import importlib
import wsgiref.simple_server as server
import os

# pyKey = "PYTHONPATH"
# # extraPath = "htbin/revlib"
# extraPath = "htbin;htbin/revlib"
#
# def SetPathOS():
# 	try:
# 		os.environ[pyKey] = os.environ[pyKey] + ";" + extraPath
# 	except KeyError:
# 		os.environ[pyKey] = extraPath
# 	os.environ.copy()
#
# def SetPathEnv(environ):
# 	try:
# 		environ[pyKey] = environ[pyKey] + ";" + extraPath
# 	except KeyError:
# 		environ[pyKey] = extraPath
# 	environ.copy()



def the_dflt(environ, start_response):
	status = '200 OK'
	global cnt
	output = "<h1>Ga Bu Zo Meu %d</h1>\n" % cnt
	output += "<table>"
	for e in environ:
		v = environ[e]
		output += "<tr><td>%s</td><td>%s</td></tr>" % (e,v)
	output += "</table>"
	cnt += 1
	response_headers = [('Content-type', 'text/html'),
						('Content-Length', str(len(output)))]
	start_response(status, response_headers)
	return [output]

def application(environ, start_response):

	pathInfo = environ['PATH_INFO']

	sys.stderr.write("pathInfo=%s\n"%pathInfo)

	if pathInfo == "/enumerate_CIM_LogicalDisk":

		# sys.stderr.write("PYTHONPATH=%s\n"%os.environ["PYTHONPATH"])

		the_module = importlib.import_module( ".enumerate_CIM_LogicalDisk", "sources_top")

		for key in ["QUERY_STRING","SCRIPT_NAME"]:
			os.environ[key] = environ[key]
		os.environ.copy()


		the_module.Main()
		status = '200 OK'
		global cnt
		output = "<h1>Ga Bu Zo Meu %d</h1>\n" % cnt
		output += "<table>"
		for e in environ:
			v = environ[e]
			output += "<tr><td>%s</td><td>%s</td></tr>" % (e,v)
		output += "</table>"
		cnt += 1
		response_headers = [('Content-type', 'text/html'),
							('Content-Length', str(len(output)))]
		start_response(status, response_headers)
		return [output]
	else:
		return the_dflt(environ, start_response)


cnt=0

# SetPathOS()
# SetPath(os.environ)

port = 9000

sys.path.append("htbin")
sys.path.append("htbin/revlib")
sys.stderr.write("path=%s\n"% str(sys.path))


httpd = server.make_server('', port, application)
print "Serving HTTP on port %i..." % port
# Respond to requests until process is killed
httpd.serve_forever()