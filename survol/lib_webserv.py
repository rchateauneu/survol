import lib_util
import lib_common

import os
import cgi
import sys
import psutil
import socket
import errno

# http://python3porting.com/noconv.html
import urllib
try:
	from urllib.request import urlopen
except ImportError:
	from urllib import urlopen

#try:
#	from urllib.parse import urlparse
#except ImportError:
#	from urlparse import urlparse
	
import time
import datetime
import lib_util
import lib_tabular

# http://rhodesmill.org/brandon/2010/python-multiprocessing-linux-windows/
# Python multiprocessing is different under Linux and Windows
import multiprocessing
import threading
if sys.version_info >= (3,):
	import _thread as thread
else:
	import thread

if sys.version_info >= (3,):
	# import http.server
	from http.server import BaseHTTPRequestHandler, HTTPServer
else:
	from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

################################################################################

def Task():
	timeStamp = time.time()
	dtStr = datetime.datetime.fromtimestamp(timeStamp).strftime('%Y-%m-%d %H:%M:%S')
	return "%s p=%d" % ( dtStr, os.getpid() )

# Generic class for all sources of RDF streaming data.
class RdfQueue_HTTPRequestHandler(BaseHTTPRequestHandler):

	def LogMsg(self,msg):
		### SUSPICION D UNE RACE CONDITION SUR STDERR !!!!!
		### OUI, CA SEMBLE CLAIR !!!!
		### self.log_message("(log)ReqHnd:" + Task() + " " + msg )
		self.server.m_logFd.write( "(srv)ReqHnd:" + Task() + " " + msg + "\n")
		self.server.m_logFd.flush()

	# Not sure it works, but we have tried several methods to stop the server.
	def StopServer(self,entityId):
		self.LogMsg("About to stop server and feeders")
		pidServer = self.server.m_pid
		pidFeeder = self.server.m_feeder[entityId].pid

		self.LogMsg("Stopping entityId="+entityId+" pidServer="+str(pidServer)+" pidFeeder="+str(pidFeeder))
		# Ideally it would be cleaner to signal to the subprocess that it is time to stop.

		# Apparently this is the only safe way to stop the HTTP server,
		# working from Python 2.5.
		# But it does not seem to do much.
		self.server.socket.close()

		# Kills all feeders.
		for ent in self.server.m_feeder:
			self.LogMsg("Stopping feeder ent="+ent )
			oneFeed = self.server.m_feeder[ent]
			self.LogMsg("Terminating feeder ent="+ent+" pid="+str(oneFeed.pid) )
			oneFeed.terminate()
			self.LogMsg("Joining feeder ent="+ent+" pid="+str(oneFeed.pid) )
			oneFeed.join()
			lib_common.KillProc( oneFeed.pid )

		# This mean killing our own process, the http subserver.
		msg = "Stopping entityId="+entityId+" pidServer="+str(pidServer)+" self.server.m_pid=" + str(self.server.m_pid)
		self.LogMsg(msg)
		lib_util.InfoMessageHtml(msg)

		# TODO: METTRE UN BOUTON ET QUAND ON LE CLIQUE CA REDIRIGE
		# VERS L URL DE DEPART, COMME CA ON PEUT REDEMARRER QUAND ON VEUT.

		lib_common.KillProc( self.server.m_pid )
		self.LogMsg("SHOULD NEVER BE HERE")
		sys.exit(0)

	def ParseQuery(self):
		# "GET /?mode=stop HTTP/1.0" 200
		# http://192.168.1.68/~rchateau/RevPython/survol/entity.py?xid=process:7775
		self.LogMsg("ParseQuery path="+self.path)

		parsed_url = lib_util.survol_urlparse( self.path )

		query_as_dict = cgi.parse_qs(parsed_url.query)

		try:
			( entity_type, entity_id, entity_host ) = lib_util.ParseXid( query_as_dict["xid"][0] )
		except KeyError:
			entity_type="Undefined_entity_type"
			entity_id="Undefined_entity_id"
			entity_host="Undefined_entity_host"

		self.LogMsg("ParseQuery entity_id="+entity_id)

		self.server.FeederCreateOrGet(entity_id)

		try:
			arg_mode = query_as_dict["mode"][0]
			if arg_mode == "stop":
				self.StopServer(entity_id)
		except KeyError:
			# If no stop, proceed as usual.
			pass

		return ( entity_type, entity_id )

	# This avoids: "'str' does not support the buffer interface"
	def SelfWrite(self,str):
		# Python 3.2.3
		self.wfile.write( str.encode() )


	# [Mon Mar 02 18:26:25 2015] [error] [client 127.0.0.1]
	# (70007)The timeout specified has expired: ap_content_length_filter:
	# apr_bucket_read() failed, referer: http://127.0.0.1/PythonStyle/survol/entity.py


	def WriteQueueInformation(self):
		self.send_response(200)
			
		self.LogMsg("WriteQueueInformation start path="+self.path)
		try:
			# Content
			lib_util.HttpHeaderClassic( self.wfile, "text/html")


#patt = """Content-type: text/html
#
#<!DOCTYPE html><html></html>"""
#	resu = patt % ( url, url, url )
#	out_dest.write( resu )




			self.LogMsg("WriteQueueInformation header done")

			self.SelfWrite("<html>")
			self.SelfWrite("<head></head>")
			self.SelfWrite("<title>Sub-server activity: pid=%d</title>" % os.getpid() )

			self.SelfWrite("<body>")
			self.SelfWrite("<table border='1'>")
			self.SelfWrite("<tr><td>Entity</td><td>Queue size</td><td>feeder pid</td></tr>")
			self.LogMsg("WriteQueueInformation before loop")
			for entityId in self.server.m_queues:
				self.SelfWrite("<tr>")
				self.LogMsg("WriteQueueInformation entityId=%s" % entityId)
				theQ = self.server.m_queues[ entityId ]

				self.SelfWrite("<td>%s</td>" % entityId)
				self.SelfWrite("<td>%d</td>" % theQ.qsize() )

				try:
					theFeed = self.server.m_feeder[ entityId ]
					self.SelfWrite("<td>%d</td>" % theFeed.pid )
				except KeyError:
					self.SelfWrite("<td>N/A</td>" )

				self.SelfWrite("</tr>")
			self.SelfWrite("</table>")
			self.SelfWrite("</body>")
			self.SelfWrite("</html>")

			self.LogMsg("WriteQueueInformation content sent")
		except Exception:
			exc = sys.exc_info()[1]

			# TODO: Send more appropriate error messages !!
			self.send_error(404, "WriteQueueInformation caught:" + str(exc) + " pid=" + str(os.getpid()))

		self.LogMsg("WriteQueueInformation end")
		return

	def do_GET(self):
		self.LogMsg("RdfQueue_HTTPRequestHandler do_GET path="+self.path)

		# Some browsers ask for this.
		if self.path == "/favicon.ico":
			return

		if lib_tabular.ServeFile( self.path ):
			self.LogMsg("Tabular file: " + self.path )
			return

		# TODO: Use CGI arguments to return the size.
		if self.path == "/infoqueues":
			self.WriteQueueInformation()
			return

		# ET AUSSI: ON VA SERVIR LES FICHIERS CSV QU'ON CREE.
		# ON LES RECONNAIT CAR YA "Tabular" AU DEBUT.




		try:
			# Maybe some ancillary tasks.
			( entityType, entityId ) = self.ParseQuery()

			self.LogMsg("Getting queue entityId=" + entityId)
			try:
				theQ = self.server.m_queues[ entityId ]
				theFeed = self.server.m_feeder[ entityId ]
			except KeyError:
				self.LogMsg("Caught when getting queue entityId=" + entityId )
				lib_common.ErrorMessageHtml("No queue for entityId=" + entityId )

			# TODO: This test is already done in ParseQuery, so it could be simplified.
			self.LogMsg("Getting pid")
			pidFeeder = theFeed.pid
			if not psutil.pid_exists( pidFeeder ):
				self.LogMsg("pidFeeder " + str(pidFeeder) + " not there.")
				lib_common.ErrorMessageHtml("pidFeeder " + str(pidFeeder) + " not there.")
				# TODO: Restart the feeder if it crashed.
				# TODO: Restart the feeder if it crashed.
				# TODO: Restart the feeder if it crashed.
				# OUI MAIS IL Y A DEJA EU UNE TENTATIVE AVEC ParseQuery()

			self.send_response(200)
			
			grph = cgiEnv.GetGraph()

			self.LogMsg("do_GET Before insertion pidFeeder=%d nbtriples=%d" % ( pidFeeder, len(grph) ) )
			# Add all the triples stored in the shared queue.
			errMsg = None
			while not theQ.empty():
				self.LogMsg("Deserializing pidFeeder=%d szQ=%d" % ( pidFeeder, theQ.qsize() ) )
				triple = theQ.get()
				self.LogMsg("After get pidFeeder=%d szQ=%d" % ( pidFeeder, theQ.qsize() ) )

				# If the object is NOT a triplet (In fact, a tuple) but a string,
				# it can only be an error message, by convention.
				if isinstance( triple, str ):
					errMsg = triple
					self.LogMsg("Instead of tuple, str=" + errMsg )
					break

				try:
					self.server.m_deserial( self.server.m_logFd, grph, triple )
				except Exception:
					exc = sys.exc_info()[1]
					self.LogMsg("do_GET deserial:" + str(exc) )

			if errMsg != None:
				self.LogMsg("do_GET Found error when reading queue=" + errMsg )
				# TODO: Do we restart the feeder ? How to display this error message ?
			else:
				self.LogMsg("do_GET No error when reading queue" )

			self.LogMsg("After insertion pidFeeder=%d nbtriples=%d" % ( pidFeeder, len(grph) ) )

			mode = lib_util.GetModeFromUrl(self.path)

			self.LogMsg("GetModeFromUrl=" + mode )

			topUrl = lib_util.TopUrl( entityType, entityId )


			lib_util.SetDefaultOutput(self.wfile)

			# TODO: How can we pass the edition parameters ? How to change them ?
			# How to store them ? For the moment, the subservers cannot have any parameter.
			# Maybe having parameters will imply restarting the feeder and maybe the subserver.
			lib_common.OutCgiMode( grph, topUrl, mode, self.server.m_page_title,
					self.server.m_dot_layout,errorMsg=errMsg,isSubServer=True)

			self.LogMsg("End of transmission pidFeeder=" + str(pidFeeder) )
		except Exception:
			exc = sys.exc_info()[1]

			# TODO: Send more appropriate error messages !!
			self.send_error(404, "go_GET caught:" + str(exc) + " pid=" + str(os.getpid()))

		self.LogMsg("do_GET: Leaving")

	# Not implemented yet.
	def do_POST(self):
		self.LogMsg("do_POST not implemented yet")

# TODO: Simplify: Only one such function is needed. But it appears in other files.
def GblLog(msg):
	sys.stderr.write("%s:%s\n" % ( Task(), msg ) )
	sys.stderr.flush()

# We wish to wrap the user function so that exception are caught.
class Feeder( multiprocessing.Process ):
	def __init__(self, theEngine, theEntity, theQueue ):
		GblLog("Feeder.__init__ entity="+theEntity)
		super(Feeder, self).__init__()

		self.m_engine = theEngine
		self.m_entity = theEntity
		self.m_queue = theQueue
		GblLog("Feeder.__init__ created")

	def run( self ):
		GblLog( "Feeder.run entityId="+self.m_entity )
		try:
			msg = self.m_engine( self.m_queue, self.m_entity )
		except Exception:
			exc = sys.exc_info()[1]
			msg = "Caught in Feeder:" + str(exc)

		GblLog(msg)
		# Exit reason is stored as a string in the queue.
		# Normally the queue must store only tuples,
		# so a string can only be an error message.
		self.m_queue.put( msg )
		return

# Question: How can we have two servers with the same port number,
# one running with apache as user, the other with rchateau ?
# Not easy to reproduce.

# This is started in a separate process which do not terminate
# when its creator leaves. Some privileges might be necessary
# because it is created by a CGI script started by the main HTTP server.
# Also, we use multiple inheritance because of the mix of old-style and new-style classes,
# it avoids the error message "caught:super() argument 1 must be type, not classobj"
class RdfStreamServer (HTTPServer,object) :

	def LogMsg(self,msg):
		nam = thread.get_ident()
		### SUSPICION OF RACE CONDITIONS, ON WINDOWS.
		### sys.stderr.write( "(s)Server %s:%s\n" % ( Task() , msg ) )
		self.m_logFd.write( "(l)Server %s:%s\n" % ( Task() , msg ) )
		self.m_logFd.flush()

	# This ensures that the feeder process is created. If not, creates it.
	def FeederCreateOrGet(self,entityId):
		self.LogMsg("Checking to create feeder entity=" + entityId)

		try:
			pidFeeder = self.m_feeder[ entityId ].pid
			if psutil.pid_exists(pidFeeder):
				self.LogMsg("Feeder is running as expected: entity=" + entityId + " pid=" + str(pidFeeder) )
			else:
				msg = "Feeder should be running: entity=" + entityId + " pid=" + str(pidFeeder)
				self.LogMsg(msg)
				lib_common.ErrorMessageHtml(msg)
				# TODO: WE COULD ATTEMPT TO RESTART THE FEEDER PROCESS.
		except KeyError:
			self.LogMsg("Actually creating feeder entity=" + entityId)
			theQ = multiprocessing.Queue()
			# BEWARE: Should put a lock here, because dict() is not thread safe !!
			self.m_queues[ entityId ] = theQ

			the_feeder = Feeder( self.m_engine, entityId, theQ )
			self.m_feeder[entityId] = the_feeder
			self.LogMsg("About to start feeder entity=" + entityId)
			the_feeder.start()

			# Give it a bit of time to start properly, but this is not essential.
			# TODO: Maybe remove this in the future.
			# Rather, for example should wait until the port number is used.
			time.sleep(1)

			self.LogMsg("Created feeder entity=" + entityId + " pid=" + str(the_feeder.pid) )

	# Called at startup
	def __init__(self,PortNum,DataEngine,Deserializer,Title,layoutParams,logFileName):
		try:
			self.m_logFileName = logFileName
			self.m_logFd = open( self.m_logFileName, "a" )
			self.LogMsg("RdfStreamServer ctor:PortNum="+str(PortNum)+" log="+logFileName)
			self.m_pid = os.getpid()
			self.m_feeder = dict()

			self.m_engine = DataEngine
			self.m_queues = dict()
			self.m_deserial = Deserializer

			self.m_page_title = Title
			self.m_dot_layout = layoutParams

			# Start HTTP server
			server_address = ('127.0.0.1', PortNum)
			super(RdfStreamServer,self).__init__(server_address, RdfQueue_HTTPRequestHandler)

			self.LogMsg("RdfStreamServer started")

			HTTPServer.serve_forever(self)
		except Exception:
			exc = sys.exc_info()[1]
			self.LogMsg("Caught when creating RdfStreamServer:" + str(exc) )
			lib_common.ErrorMessageHtml("From RDFStreamServer ctor, caught:" + str(exc) )

################################################################################

# Use both meta, and JavaScript code and would have a link just in case.
# Set the meta rate to 1 for occasional circumstances where the browser ignores 0 value meta refresh.
# Practically, out_dest is always sys.stdout.
def SendRedirection( out_dest, url ):
	GblLog("SendRedirection url=" + url )
	patt = """Content-type: text/html

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" />
<meta http-equiv="Refresh" content="1; url=%s" />
<script type="text/javascript">
window.location.href = "%s"
</script>
<title>Redirection</title>
<meta name="robots" content="noindex" />
</head>

<body>
<p><a href="%s">Redirection</a></p>
</body>
</html>
"""
	resu = patt % ( url, url, url )
	out_dest.write( resu )
	GblLog("Written bytes:" + str( len(resu) ) )
	out_dest.flush()

	# TODO: SHOULD WE FLUSH THIS ?????

################################################################################

def SubServerUrl(PortNum,cgiEnv):
	url = 'http://127.0.0.1:' + str(PortNum) + '/'
	try:
		entity = cgiEnv.GetId()
		GblLog("SubServerUr PortNum=%d entity:%s" % (PortNum, entity) )
	except KeyError:
		# Maybe we are testing from the command line.
		try:
			entity = os.environ["entity_id"]
		except KeyError:
			entity = "DfltEntity"
	# The type is not important
	cgi_args = lib_util.EncodeEntityId("",entity)
	resu = lib_util.ConcatenateCgi( url, cgi_args )
	GblLog("SubServerUr resu="+resu)
	return resu


# This checks if the stop command is sent.
# Maybe we are called from the command line or from a query.
def MustStop():
	GblLog("MustStop checking")

	# If the script is called from the command line, for testing purpose.
	if ( len(sys.argv) > 1 ) and ( sys.argv[1] == "stop" ):
		return True

	arguments = cgi.FieldStorage()

	# In normal behaviour, the command is sent in the url.
	try:
		mustStopCgi = arguments["mode"].value == "stop"
	except KeyError:
		return False

	return mustStopCgi

################################################################################

# Hard-coded for the moment.
portDict = {
	"tcpdump"                  : 1111,
	"psutil_processes_perf"    : 2222,
	"sockets_promiscuous_mode" : 3333,
	"win_directory_changes"    : 4444,
	"iostat_all_disks"         : 5555
	}

class SrvSingleton:

	# Checks if the file is there and correctly filled because this should be the most common case.
	def __init__(self,AppName):

		GblLog("SrvSingleton pid=%d AppName:%s" % ( os.getpid(), AppName ) )
		# There should not be any duplicate. Should be OK for the moment.
		# base name will be used for the log file, also.
		self.m_appBaseName = os.path.basename(AppName).split(".")[0]

		# The file name must be unique.
		self.m_logFilNam = lib_common.TmpDir() + "/SubSrv." + self.m_appBaseName + ".log"

		self.m_isSubSrv = False
		self.m_pidSubSrv = -1
		self.m_PortNumber = -1

		if not os.path.exists(self.m_logFilNam):
			GblLog("SrvSingleton m_logFilNam:%s does not exist" % self.m_logFilNam )
			return

		try:
			self.m_logFd = open( self.m_logFilNam, "r" )
			# File is there. Maybe not completely filled now.
			for nbTries in range(0,3):
				self.m_logFd.seek(0)
				try:
					linSplit = self.m_logFd.readline().split(" ")
					self.m_logFd.close()

					pidSubSrv = int( linSplit[0] )

					# TODO: Should check if the port is OK.
					self.m_PortNumber = int( linSplit[1] )

					# If the process is not there, this is an old file.
					if not psutil.pid_exists(pidSubSrv):
						os.remove(self.m_logFilNam)
						return

					self.m_pidSubSrv = pidSubSrv
					self.m_isSubSrv = True
					self.m_logFd.close()
					GblLog("SrvSingleton read getpid=%d m_pidSubSrv=%d m_PortNumber=%d" % ( os.getpid(), self.m_pidSubSrv, self.m_PortNumber ) )
					return
				except ValueError:
					# Maybe not ready yet.
					time.sleep(0.3)
					# Retry reading.
				GblLog("SrvSingleton Cannot open:" + self.m_logFilNam )
		except IOError:
			# If the file is not there, the server is not running.
			exc = sys.exc_info()[1]
			# File is there but could not read valid pid and port.
			GblLog("SrvSingleton Caught:%s" % str(exc) )
			# self.m_logFd.close()
	
	def GetRunning(self):
		return self.m_isSubSrv

	def SetRunning(self):
		GblLog("SetRunning getpid=%d pid=%d port=%d" % ( os.getpid(), self.m_pidSubSrv, self.m_PortNumber ) )
		if self.m_isSubSrv:
			lib_common.ErrorMessageHtml("Already running pid=%d port=%d\n" % ( self.m_pidSubSrv, self.m_PortNumber ) )
		# File is not there. Possible race condition.
		self.m_logFd = open( self.m_logFilNam, "w+" )
		# If we could open it, now write the port number so it can be read by the others.
		# Must immediately allocate a socket.
		self.m_PortNumber = portDict[self.m_appBaseName]
		self.m_pidSubSrv = os.getpid()

		# Atomic write.
		self.m_logFd.write( "%d %d\n" % ( self.m_pidSubSrv, self.m_PortNumber ) )

		# Checks that it is properly written.
		self.m_logFd.seek(0)
		linSplit = self.m_logFd.readline().split(" ")
		pidSubSrvAlt = int( linSplit[0] )
		PortNumberAlt = int( linSplit[1] )
		if ( self.m_pidSubSrv != pidSubSrvAlt ) or ( self.m_PortNumber != PortNumberAlt ) :
			# Race condition. Another process is faster than us.
			self.m_pidSubSrv = pidSubSrvAlt
			self.m_PortNumber = PortNumberAlt
			self.m_isSubSrv = False
			self.m_logFd.close()
			GblLog( "Race condition %d %d" % ( self.m_pidSubSrv, self.m_PortNumber ) )
			return False

		self.m_isSubSrv = True
		return True

	# If we could not start the subserver.
	def CancelRunning(self):
		if not self.m_isSubSrv:
			lib_common.ErrorMessageHtml("Not running pid=%d port=%d\n" % ( self.m_pidSubSrv, self.m_PortNumber ) )
		self.m_logFd.close()

		# NOT YET.
		### os.remove(self.m_logFilNam)

################################################################################

# AppName is __file__ for the calling program
# TODO: Allocates port number on the fly.
def DoTheJob(TheEngine,Deserializer,AppName,Title,dot_layout = "", collapsed_properties=[] ):
	srvSingle = SrvSingleton(AppName)

	PortNum = srvSingle.m_PortNumber

	run_word = "run"
	GblLog("DoTheJob:" + str(sys.argv) + " title="+Title+" dot_layout="+dot_layout)

	if srvSingle.m_PortNumber != None:
		GblLog("Title=%s PortNum=%d" % ( Title, PortNum ) )
	else:
		GblLog("Title=%s PortNum not defined yet" % ( Title ) )

	# So we can answer immediately to "info" requests, without creating the subserver.
	cgiEnv = lib_common.CgiEnv( Title, "", { "port_number":PortNum } )

	# This is the subprocess of the specialised http server.
	if ( len(sys.argv) > 1 ) and ( sys.argv[1] == run_word ):
		if srvSingle.GetRunning():
			GblLog("Subprocess: Race condition: Port " + str(PortNum) + " allocated. Leaving.")
			sys.exit(0)

		# Called before creating the subserver because we will be stuck into it.
		if not srvSingle.SetRunning():
			GblLog("CANNOT SET RUNNING STATE: Race condition ?")
			return

		# This time the port must be valid.
		PortNum = srvSingle.m_PortNumber
		GblLog("Subprocess: Port %d free. About to create subserver." % PortNum)
		try:
			# Normally we are stuck in this, answering HTTP requests and accumulating data.
			# TODO: It is probably not necessary to send Title and DotLayout.
			layoutParams = lib_common.MakeDotLayout( dot_layout, collapsed_properties )

			# Now, will append log at the end.
			srvSingle.m_logFd.close()
			gServer = RdfStreamServer(PortNum,TheEngine,Deserializer,Title,layoutParams,srvSingle.m_logFilNam)

			GblLog("Should never be here")
		except Exception:
			exc = sys.exc_info()[1]
			msg = Task() + " Caught when starting RdfStreamServer:" + str(exc)
			GblLog(msg)
			srvSingle.CancelRunning()
			lib_common.ErrorMessageHtml("From RDFStreamServer, caught:" + msg )

		sys.exit(0)

	# if the subserver is not running, we start it, then redirects the browser
	# to initiate a new connection. After that, we exit() but this will never really
	# exit until our subserver subprocess, exits first.

	if not srvSingle.GetRunning():
		GblLog("About to start:"+AppName)
		try:
			# Do not pipe the output otherwise it would not run in the background.

			# Si necessaire, on pourrait lancer un process avec l'user root ?
			# sub_proc = lib_common.SubProcPOpen( [ "python", AppName, run_word ] )
			# Share standard error.
			sub_proc = lib_common.SubProcPOpen( [ "python", AppName, run_word ], stderr=sys.stderr )

			GblLog("Started sub http server:" + AppName + " subpid=" + str(sub_proc.pid) )

			# We need the cgi arguments, especially the entity id.
			origUrl = os.environ["REQUEST_URI"]

			GblLog("About to redirect browser to:"+origUrl)

			# IMPORTANT: We leave time enough for the subprocess to start,
			# otherwise it will be started TWICE.
			time.sleep(0.1)

			GblLog("After pause")

			SendRedirection( sys.stdout, origUrl )

			# This blocks until the subprocess exists.
			GblLog("Waiting for end of subpid=" + str(sub_proc.pid) )
			sys.exit(0)

		except Exception:
			exc = sys.exc_info()[1]
			lib_common.ErrorMessageHtml("When starting server=" + AppName + ", caught:" + str(exc) )

	GblLog("Service exists. Port="+str(PortNum) )

	# Here, we know that the subserver is running.
	url = SubServerUrl(PortNum,cgiEnv)

	# Do we have to stop the subserver ?
	if MustStop():
		# Equivalent to 'ModedUrl("stop")'
		url_stop = lib_util.ConcatenateCgi( url, "mode=stop" )
		# TODO: We could also load this URL, this would be nicer.
		SendRedirection( sys.stdout, url_stop )
		sys.exit(0)

	mode = lib_util.GuessDisplayMode()
	GblLog("mode:"+mode)
	# Equivalent to 'ModedUrl(mode)'
	url_mode = lib_util.ConcatenateCgi( url, "mode=" + mode )

	GblLog("url_mode:"+url_mode)
	SendRedirection( sys.stdout, url_mode )

	GblLog("Finished:" + AppName )


################################################################################
