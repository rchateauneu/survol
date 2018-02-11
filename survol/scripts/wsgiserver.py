#!/usr/bin/python

# http://www.bortzmeyer.org/wsgi.html

import os
import sys
import getopt
import socket
import importlib
import wsgiref.simple_server as server
import cStringIO

# See the class lib_util.OutputMachineCgi
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

	# extraArgs is an array of key-value tuples.
	def HeaderWriter(self,mimeType,extraArgs= None):
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
	#for key in sorted(environ.keys()):
	#	sys.stderr.write("application_ok:environ[%-20s]=%-20s\n"%(key,environ[key]))

	#for key in sorted(os.environ.keys()):
	#	sys.stderr.write("application_ok:os.environ[%-20s]=%-20s\n"%(key,os.environ[key]))

	# Must be done BEFORE IMPORTING, so the modules can have the good environment at init time.
	for key in ["QUERY_STRING","SERVER_PORT"]:
		os.environ[key] = environ[key]

	# The wsgi Python module sets a value for SERVER_NAME that we do not want.
	os.environ["SERVER_NAME"] = os.environ["SURVOL_SERVER_NAME"]

	### sys.stderr.write("os.environ['SCRIPT_NAME']=%s\n"%os.environ['SCRIPT_NAME'])
	os.environ["PYTHONPATH"] = "survol" # Not needed if installed ??

	# Not sure this is needed on all platforms.
	os.environ.copy()

	pathInfo = environ['PATH_INFO']

	# This environment variable is parsed in UriRootHelper
	# os.environ["SCRIPT_NAME"] = "/survol/see_wsgiserver"
	# SCRIPT_NAME=/survol/print_environment_variables.py
	# REQUEST_URI=/survol/print_environment_variables.py?d=s
	# QUERY_STRING=d=s
	os.environ["SCRIPT_NAME"] = pathInfo

	# If "http://127.0.0.1:8000/survol/sources_top/enumerate_CIM_LogicalDisk.py?xid=."
	# then "/survol/sources_top/enumerate_CIM_LogicalDisk.py"
	sys.stderr.write("pathInfo=%s\n"%pathInfo)

	# Example: pathInfo=/survol/www/index.htm
	if pathInfo.find("/survol/www/") >= 0:
		return app_serve_file(pathInfo, start_response)
		

	pathInfo = pathInfo.replace("/",".")

	modulePrefix = "survol."
	htbinIndex = pathInfo.find(modulePrefix)

	pathInfo = pathInfo[htbinIndex + len(modulePrefix):-3] # "Strips ".py" at the end.

	# ["sources_types","enumerate_CIM_LogicalDisk"]
	splitPathInfo = pathInfo.split(".")

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

	scriptNam=os.environ['SCRIPT_NAME']
	sys.stderr.write("scriptNam1=%s\n"%scriptNam)

	the_module.Main()
	sys.stderr.write("After Main\n")
	return [ lib_util.globalOutMach.Content() ]

def application(environ, start_response):
	try:
		return application_ok(environ, start_response)
	except:
		# Uncomment this for easier debugging.
		# raise
		sys.stderr.write("application CAUGHT:\n")

		import lib_util

		exc = sys.exc_info()
		sys.stderr.write("application CAUGHT:%s\n"%str(exc))
		return [ lib_util.globalOutMach.Content() ]

port_number_default = 9000

def Usage():
	progNam = sys.argv[0]
	print("Survol WSGI server: %s"%progNam)
	print("	-a,--address=<IP address> TCP/IP address")
	print("	-p,--port=<number>		TCP/IP port number. Default is %d." %(port_number_default) )
	# Ex: -b "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
	print("	-b,--browser=<program>	Starts a browser")
	print("	-v,--verbose			  Verbose mode")
	print("")
	print("Script must be started with command: survol/scripts/cgiserver.py")

# https://docs.python.org/2/library/webbrowser.html
def StartsWebrowser(browser_name,theUrl):
	"""This starts a browser with the specific module to do it"""

	import webbrowser

	# TODO: Parses the argument from the parameter
	webbrowser.open(theUrl, new=0, autoraise=True)

def StartsBrowser(browser_name,theUrl):
	"""This starts a browser whose executable is given on the command line"""
	# Import only if needed.
	import threading
	import time
	import subprocess

	def StartBrowserProcess():

		print("About to start browser: %s %s"%(browser_name,theUrl))

		# Leaves a bit of time so the HTTP server can start.
		time.sleep(5)

		subprocess.check_call([browser_name, theUrl])

	threading.Thread(target=StartBrowserProcess).start()
	print("Browser thread started")

def RunWsgiServer():

	try:
		opts, args = getopt.getopt(sys.argv[1:], "ha:p:b:v", ["help","address=","port=","browser=","verbose"])
	except getopt.GetoptError as err:
		# print help information and exit:
		print(err)  # will print something like "option -a not recognized"
		Usage()
		sys.exit(2)

	# It must be the same address whether it is local or guessed from another machine.
	# Equivalent to os.environ['SERVER_NAME']
	# server_name = "rchateau-HP"
	# server_name = "DESKTOP-NI99V8E"
	# It is possible to force this address to "localhost" or "127.0.0.1" for example.
	# Consider also: socket.gethostbyname(socket.getfqdn())

	server_name = socket.gethostname()

	server_addr = socket.gethostbyname(server_name)

	verbose = False
	port_number = port_number_default
	browser_name = None

	for anOpt, aVal in opts:
		if anOpt in ("-v", "--verbose"):
			verbose = True
		elif anOpt in ("-a", "--address"):
			server_name = aVal
		elif anOpt in ("-p", "--port"):
			port_number = int(aVal)
		elif anOpt in ("-b", "--browser"):
			browser_name = aVal
		elif anOpt in ("-h", "--help"):
			Usage()
			sys.exit()
		else:
			assert False, "Unhandled option"

	currDir = os.getcwd()
	if verbose:
		print("cwd=%s path=%s"% (currDir, str(sys.path)))


	# The script must be started from a specific directory to ensure the URL.
	filMyself = open("survol/scripts/wsgiserver.py")
	if not filMyself:
		print("Script started from wrong directory")
		Usage()
		sys.exit()

	print("Platform=%s\n"%sys.platform)
	print("Version:%s\n"% str(sys.version_info))
	print("Server address:%s" % server_addr)
	print("Opening %s:%d" % (server_name,port_number))

	theUrl = "http://" + server_name
	if port_number:
		if port_number != 80:
			theUrl += ":%d" % port_number
	theUrl += "/survol/www/index.htm"
	print("Url:"+theUrl)

	# Starts a thread which will starts the browser.
	if browser_name:

		if browser_name.startswith("webbrowser"):
			StartsWebrowser(browser_name,theUrl)
		else:
			StartsBrowser(browser_name,theUrl)
		print("Browser thread started to:"+theUrl)

	sys.path.append("survol")
	# sys.path.append("survol/revlib")
	sys.stderr.write("path=%s\n"% str(sys.path))

	# This expects that environment variables are propagated to subprocesses.
	os.environ["SURVOL_SERVER_NAME"] = server_name
	sys.stderr.write("server_name=%s\n"% server_name)

	httpd = server.make_server('', port_number, application)
	print "WSGI server running on port %i..." % port_number
	# Respond to requests until process is killed
	httpd.serve_forever()

if __name__ == '__main__':
	# If this is called from the command line, we are in test mode and must use the local Python code,
	# and not use the installed packages.
	RunWsgiServer()
