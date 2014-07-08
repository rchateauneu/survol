import lib_common

import os
import cgi
import urlparse
import sys
import signal
import time
import subprocess
import multiprocessing
import threading
import thread
import rdflib

if sys.version_info >= (3,):
	# import http.server
	from http.server import BaseHTTPRequestHandler, HTTPServer
else:
	from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

if sys.version_info >= (3,):
	from urllib.request import urlopen
	from urllib.error import HTTPError
else:
	from urllib import urlopen
	# from urllib.error import HTTPError

def Task():
	nam = thread.get_ident()
	return "p="+str(os.getpid()) + " t=" + str(nam)

# Generic class for all sources of RDF streaming data.
class RdfQueue_HTTPRequestHandler(BaseHTTPRequestHandler):

	def LogMsg(self,msg):
		self.log_message("ReqHnd: " + Task() + " " + msg )

	# Not sure it works, but we have tried several methods to stop the server.
	def StopServer(self):
		# Ideally it would be cleaner to signal to the subprocess
		# that it is time to stop.
		self.server.m_feeder.terminate()
		self.server.m_feeder.join()

		# Apparently this is the only safe way to stop the HTTP server,
		# working from Python 2.5.
		# But it does not seem to do much.
		self.server.socket.close()

		os.kill( self.server.m_pid, signal.SIGQUIT )
		lib_common.ErrorMessageHtml( "RdfQueue stop server pid="+str(self.server.m_pid) )

# access_log says:
# "GET /~rchateau/RevPython/sources/cgi_top.py?action=stop HTTP/1.1" 200
# ... but error_log says:
# RdfQueue_HTTPRequestHandler do_GET path=/
# "GET / HTTP/1.0" 200
# WHY? This is why we cannot stop the server from the browser !!!!!

# MAYBE THIS IS NOT path ???



	def ParseQuery(self):
		# "GET /?action=stop HTTP/1.0" 200
		self.LogMsg("Ancillary do_GET path="+self.path)

		parsed_url = urlparse.urlparse( self.path )
		# This is prior Python 2.6. Afterthat, use urlparse.parse_qs
		query_as_dict = cgi.parse_qs(parsed_url.query)

		try:
			entityId = query_as_dict["entity_id"][0]
		except KeyError:
			entityId="Tagada"

		# Si la creation de thread se fait la, le process principal qui execute
		# le script ne retourne pas le prompt.
		# Alors que dans le process HttpServer, c'est OK. Pourtant
		# c'est le meme process et la meme thread. POURQUOI ?
		# Si on kill le process interactif, le process du serveur a le ppid=1.
		# Mais pourquoi le comportement est different entre HTTPServer et HTTPRequestHandler
		# alors que c'est le meme process ?
		self.server.FeederCreation(entityId)

		try:
			arg_action = query_as_dict["action"][0]
			if arg_action == "stop":
				self.StopServer()

			lib_common.ErrorMessageHtml("RdfQueue Unknown action:"+arg_action)
		except KeyError:
			# If no action, proceed as usual.
			pass

		return entityId

	def do_GET(self):
		self.LogMsg("RdfQueue_HTTPRequestHandler do_GET path="+self.path)
		try:
			# Maybe some ancillary tasks.
			entityId = self.ParseQuery()

			# Maybe check if the feeder is still running, and if not, then restart it.
			self.LogMsg("Getting queue entityId=" + entityId)
			try:
				theQ = self.server.m_queues[ entityId ]
			except KeyError:
				self.LogMsg("Caught when getting queue entity:" + entityId )
				lib_common.ErrorMessageHtml("No queue for entity=" + entityId )
			# theQ = self.server.m_feeder.m_queue

			self.send_response(200)

			grph = rdflib.Graph()

			# Add all the triples stored in the shared queue.
			while not theQ.empty():
				triple = theQ.get()
				self.server.m_deserial( grph, triple )

			self.LogMsg("End of insertion")
			# TODO: See lib_common.OutCgiRdf(grph)
			# Or the MIME type should be 'text/rdf' (Note the slash instead of hyphen)
			self.send_header('Content-type','text-rdf')
			self.end_headers()

			self.LogMsg("After header")
			srl = grph.serialize(format='xml')
			self.LogMsg("Before write")
			unistr = unicode(srl)
			self.wfile.write( unistr )
			self.LogMsg("After write len="+str(len(unistr)))
            
		except Exception:
			exc = sys.exc_info()[1]

			# TODO: Send more appropriate error messages !!
			self.send_error(404, "go_GET caught:" + str(exc) )

	# Not implemented yet.
	def do_POST(self):
		self.LogMsg("do_POST not implemented yet")


def GblLog(msg):
	print("Global: " + Task() + " " + msg )

# We wish to wrap the user function so that exception are caught.
class Feeder( multiprocessing.Process ):
    def __init__(self, theEngine, theEntity, theQueue ):
        super(Feeder, self).__init__()

	self.m_engine = theEngine
	self.m_entity = theEntity
	self.m_queue = theQueue

    def run( self ):
	try:
		self.m_engine( self.m_queue, self.m_entity )
	except Exception:
		exc = sys.exc_info()[1]
		GblLog("Caught in Feeder:" + str(exc) )

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
		print("Server: " + Task() + " " + msg )

	def FeederCreation(self,entityId):
		self.LogMsg("Creating feeder entity=" + entityId)



MAINTENANT CREER LE FEEDER.
ACTUELLEMENT on ne voit pas bien l erreur si le feeder n existe pas
et toujours le probleme du process suspendu.
Et trouver d autres sources de donnees que strace.
Par exemple tcpdump sur une socket.
Ou lsof pour un process? Non, car c est du fixe.
A la limite "tail -f" pour un fichier, histoire de montrer que le concept est solide.

Peut etre mettre la queue dans le feeder, histoire de faire propre.

		if self.m_feeder == '':
			theQ = multiprocessing.Queue()
			self.m_queues[ entityId ] = theQ
			self.m_feeder = Feeder( self.m_engine, entityId, theQ )
			self.m_feeder.start()
			self.LogMsg("Created feeder entity=" + entityId)

	# Called at startup
	def __init__(self,PortNum,DataEngine,Deserializer):
		try:
			self.m_pid = os.getpid()
			self.m_feeder = ''

			self.m_engine = DataEngine
			# self.m_queues = multiprocessing.Queue()
			self.m_queues = dict()
			self.m_deserial = Deserializer

			# QUESTION: Quand on cree le process ici, le scritp retroubne avec le prompt.
			# self.FeederCreation("Default")

			# Start HTTP server
			server_address = ('127.0.0.1', PortNum)
			super(RdfStreamServer,self).__init__(server_address, RdfQueue_HTTPRequestHandler)

			self.LogMsg("RdfStreamServer started")

			HTTPServer.serve_forever(self)
		except Exception:
			exc = sys.exc_info()[1]
			self.LogMsg("Caught when creating RdfStreamServer:" + str(exc) )
			lib_common.ErrorMessageHtml("From RDFStreamServer ctor, caught:" + str(exc) )


# This fetches the content of the given url and prints it.
def RedirectHttpResult(PortNum,ExtraCgi=""):
	time.sleep(0.01)

	# This just forwards the URL and its arguments.
	url = 'http://127.0.0.1:' + str(PortNum) + '/' + ExtraCgi

	try:
		try:
			# If this throws an exception, nothing is yet sent back to the client.
			content = urlopen(url).read()

			# Without these two lines, the browser displays the error message:
			# "malformed header from script. Bad header=<?xml version="1.0" encoding=": cgi_tcpdump.py "
			print("Content-type: text/rdf")
			print("")
			# This sends the result to the browser.
			print( content )
			###   print("RedirectHttpResult OK")
			return ""
		# This used to work on Python 2.5.2
		#except urllib.HTTPError:
			# If here, it means that the server is not started.
		#	exc = sys.exc_info()[1]
		#	print('HTTPError = ' + str(exc.code))
		#	return "retry"
		#except urllib.URLError:
		#	exc = sys.exc_info()[1]
		#	lib_common.ErrorMessageHtml('URLError = ' + str(exc.reason))
		#except httplib.HTTPException:
		#	exc = sys.exc_info()[1]
		#	lib_common.ErrorMessageHtml('HTTPException = ' + str(exc))
		except Exception:
			# This works on Linux, and Python 2.5.
			try:
				exc = sys.exc_info()[1]
				if( exc[1][0] == 111):
					return "retry"
				msg = 'exc=' + str(exc)
			except IndexError:
				msg = 'Incomplete exception exc=' + str(exc)
			lib_common.ErrorMessageHtml('Exception unexpected :' + msg )

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml('Exception unexpected = ' + str(exc))
	except NameError:
		exc = sys.exc_info()[1]
		GblLog('Unexpected one = ' + str(exc))
		lib_common.ErrorMessageHtml('NameError unexpected = ' + str(exc))

# This checks if the stop command is sent.
# Maybe we are called from the command line or from a query.
# If does not stop, returns the cgi arguments for the local HTTP server.
def ProcessLocalCgis(PortNum):
	arguments = cgi.FieldStorage()

	cgi_args = "?x=y"

	try:
		entity = arguments["entity_id"].value
	except KeyError:
		entity = "DfltEntity"
	cgi_args += "&entity_id=" + entity

	# If the script is called from the command line, for testing purpose.
	mustStopCmd = ( len(sys.argv) > 1 ) and ( sys.argv[1] == "stop" )

	# In normal behaviour, the command is sent in the url.
	if not mustStopCmd:
		try:
			mustStopCgi = arguments["action"].value == "stop"
		except KeyError:
			mustStopCgi = False

	if mustStopCmd or mustStopCgi:
		GblLog("About to stop")
		ret = RedirectHttpResult(PortNum,"?action=stop")
		time.sleep(0.1)
		sys.exit(0)

	return cgi_args

# AppName comes is __file__ for the calling program
def DoTheJob(TheEngine,PortNum,Deserializer,AppName):
	run_word = "run"
	GblLog("MAIN PROCESS:" + str(sys.argv) )

	# Mystery : What is the command line when called as a CGI script ???
	if ( len(sys.argv) > 1 ) and ( sys.argv[1] == run_word ):
		# MULTIFEEDERS : On va creer une queue par entity_id
		GblLog("Magic word OK")
		try:
			GblLog("Creating Tuple Queue")
			# MULTIFEEDERS: On prend la valeur de entity_id dans le cgi, chaine vide
			# par defaut. Mais il faut creer cette queue au tout debut de DoTheJob, meme
			# si le process existe.

			# Normally we are stuck in this, answering HTTP requests and accumulating data.
			GblLog("Creating gServer")
			gServer = RdfStreamServer(PortNum,TheEngine,Deserializer)

			# If we remove serve_forever() in the constructor; this could be replaced by:
    			#while keep_running():
        		#	httpd.handle_request()

			GblLog("Should never be here")
		except Exception:
			exc = sys.exc_info()[1]
			msg = Task() + " Caught when starting RdfStreamServer:" + str(exc)
			GblLog(msg)
			lib_common.ErrorMessageHtml("From RDFStreamServer, caught:" + msg )
		sys.exit(0)


	cgi_args = ProcessLocalCgis(PortNum)

	# TODO: Edit runtime parameters for the process.

	# Contacts the real server with a HTTP query.
	# We know its port number.
	# If it is not running, starts it.
	try:
		ret = RedirectHttpResult(PortNum, cgi_args)
		# print("pid="+str(os.getpid()) + " " + "After RedirectHttpResult ret="+str(ret))

		if ret == "":
			# Worked fine, bye bye.
			sys.exit(0)

		if ret != "retry":
			lib_common.ErrorMessageHtml('Should not happen: ret='+retry)
			sys.exit(1)
		# print("Starting server after RedirectHttpResult failure ret="+retry)
	except Exception:
		exc = sys.exc_info()[1]
		# This is temporary, to avoid a fork bomb.
		time.sleep(0.01)

		pass

	# First we try to start the server.
	try:
		# Probably not all exceptions.
		# Do not pipe the output otherwise it would not run in the background.
		GblLog("About to start:"+AppName)

		# This work-ish but blocks at the creation of the feeder, if the feeder is
		# created by the HTTPRequestHandler.
		ret = subprocess.Popen( [ "python", AppName, run_word ] )

		# No real change with this.
		# cmd = "python " + AppName + " " + run_word + " > /dev/null 2>&1 &"
		# ret = os.system( cmd )
		GblLog("Started:" + AppName)
	except Exception:
		exc = sys.exc_info()[1]
		# print(exc)
		lib_common.ErrorMessageHtml("When starting server=" + AppName + ", caught:" + str(exc) )

	# Theoretically we have managed to start the server.
	try:
		GblLog("About to redirect results")
		# This is temporary, to avoid a fork bomb.
		# And also, the server has time enough to start properly.
		time.sleep(0.5)

		RedirectHttpResult(PortNum, cgi_args)
		# Worked fine, bye bye.
		sys.exit(0)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("After having started the server, caught:" + str(exc) )


#On va repartir a zero.

#Ensuite on creer une map de queue. Il faudrait que la map
#ne soit pas partagee, mais comment la passer au process HTTPRequest ?
#On va overrider  dans HTTPServer les methodes
#    - verify_request(request, client_address)
#    - process_request(request, client_address)
#Pour commencer, afficher la request et la parser nous-memes.
#Voir si c est possible.
#Dans ces methodes, on cree la queue et le feeder.
#Ou alors, on met la queue dans le serveur HTTP et la thread HTTPRequest 
#y accede immediatement car on la passe en parametre (Je crois que c est possible).
#On essaye de les mettre dans une map mais aucun autre process
#ne va acceder a la map, seulement a la queue.
#Si on peut creer le feeder quand on cree le process HTTPRequest,
#et lui passer la queue ainsi qu au process HTTPRequest, ca marche.
#Voir BaseHTTPServer.py
#    1. One line identifying the request type and path
#    2. An optional set of RFC-822-style headers
#    3. An optional data part
#    The headers and data are separated by a blank line.
#    The first line of the request has the form
#    <command> <path> <version>


