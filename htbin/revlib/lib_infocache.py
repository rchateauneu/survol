import os
import sys
import time
import lib_util
import lib_common

try:
    import simplejson as json
except ImportError:
    import json

# TODO: On pourrait y stocker les serveurs SLP.
# Aussi, si WSGI, tout garder en memoire.

################################################################################
def JsonLoads( content ):
	try:
		if sys.version_info >= (3,):
			# Windows + Python 3.2
			return json.loads( content )
		else:
			# Linux + Python 2.5
			return json.loads( content.decode() )
	except ValueError:
		# No JSON object could be decoded
		return {}


################################################################################

# General-purpose class. Later, can be moved to its own file.
class CacheFile():
	def __init__(self, name ):
		self.m_cacheFileName = "%s/%s.cache.txt" % ( lib_common.tmpDir, name )
		sys.stderr.write("InfoCacheFile=%s\n" % self.m_cacheFileName )

		# If the file is shared we have a problem. OK for the moment.
		try:
			timStampFil = os.path.getmtime(self.m_cacheFileName)
		except OSError:
			# If the file does not exist.
			timStampFil = 0
		timStampNow = time.time()


		#sys.stderr.write("TEMP CACHE")
		#sys.stderr.write("TEMP CACHE")
		#sys.stderr.write("TEMP CACHE")
		#sys.stderr.write("TEMP CACHE")
		#sys.stderr.write("TEMP CACHE")
		#sys.stderr.write("TEMP CACHE")
		#timStampFil = 0


		# Check the timestamp, if too old, start fresh. One week.
		delta = 7 * 24 * 3600
		if timStampNow - timStampFil > delta :
			sys.stderr.write("Info cache reset\n")
			self.m_cacheDict = {}
		else:
			sys.stderr.write("Info cache reload\n")
			# Otherwise load the content
			cacheFile = open(self.m_cacheFileName,"r") 
			content = cacheFile.read()
			self.m_cacheDict = JsonLoads( content )
			cacheFile.close()

	# TODO: If too many calls to VirtualValue, then return a special 'Status',
	# saved in the cache. Next time the value will be needed, an actual call
	# to VirtualValue() will be done, but not yet.
	def CachedValue(self,keyWithArgs):
		# Removes the CGI arguments. We may keep them but the number
		# of combinations would be too big.
		key = keyWithArgs.split('?')[0]

		if key in self.m_cacheDict:
			return self.m_cacheDict[ key ]
		# This must be virtual, and returns None if no value.
		val = self.VirtualValue(key)
		self.m_cacheDict[ key ] = val
		self._Flush()
		return val;

	# New data are written at each change. It should be done in the
	# destructor of the cache, but it is called too late, when some
	# libraries are already closed.
	def _Flush(self):
		# TODO: Flush the cache in the destructor, so it will happen
		# only once.
		sys.stderr.write("FLUSHING InfoCacheFile=%s\n" % self.m_cacheFileName )
		cacheFile = open(self.m_cacheFileName,"w") 
		strJson = json.dumps(self.m_cacheDict)
		cacheFile.write(strJson)
		cacheFile.close()

	def Clean(self):
		sys.stderr.write("CLEANING InfoCacheFile=%s\n" % self.m_cacheFileName )
		cacheFile = open(self.m_cacheFileName,"w") 
		cacheFile.close()
		self.m_cacheDict = {}

################################################################################

class InfoCache(CacheFile):
	def __init__(self):
		CacheFile.__init__(self,"Info")
		self.m_errCount = 0

	# Tries to get the "info" json aggregate by executing locally the script,
	# if is is on the same server as ours.
	# This is faster because no need of localhost network connection.
	# ALSO: Needed when the HTTP server is single-threaded.
	# keySfx = "/entity.py?xid=com_type_lib:654646545"
	# lib_util.uriRoot = "http://127.0.0.1/PythonStyle/htbin"
	# lib_util.uriRoot = "http://127.0.0.1:8000/htbin"
	def FromScript(self,keySfx):
		fulScriptNam = lib_common.pathRoot + keySfx
		sys.stderr.write("fulScriptNam=%s\n" % fulScriptNam)

		# This passes to the script, the only needed CGI value.
		bckQUERY_STRING = os.environ['QUERY_STRING']
		os.environ['QUERY_STRING'] = "mode=info"
		jsonContent = []
		for lin in os.popen( "python " + fulScriptNam ):
			jsonContent.append( lin )
		os.environ['QUERY_STRING'] = bckQUERY_STRING
		sys.stderr.write("FromScript %s:%s\n" % ( keySfx, jsonContent ) )
		# Do not take the HTTP header, which is: "Content-Type: application/json\n\n"
		jsonLine = jsonContent[2]
		jsonDat = JsonLoads( jsonLine )
		sys.stderr.write("jsonDat=%s\n" % str(jsonDat) )
		return jsonDat

	# Apache http://127.0.0.1/PythonStyle/htbin/internals/print.py
	# Entity http://127.0.0.1/PythonStyle/htbin/entity.py
	# SCRIPT_NAME=/PythonStyle/htbin/internals/print.py
	# REMOTE_ADDR=127.0.0.1
	# SERVER_PORT=80
	# SCRIPT_FILENAME=D:/Projects/Divers/Reverse/PythonStyle/htbin/internals/print.py
	# REQUEST_URI=/PythonStyle/htbin/internals/print.py
	#
	# Script http://127.0.0.1:8000/htbin/internals/print.py
	# Entity http://127.0.0.1:8000/htbin/entity.py
	# REMOTE_ADDR=127.0.0.1
	# SERVER_PORT=8000
	# SCRIPT_NAME=/htbin/internals/print.py
	# PATH_TRANSLATED=D:\Projects\Divers\Reverse\PythonStyle
	#
	def KeySuffix(self,key):
		entName = "entity.py"
		scriptNam = os.environ['SCRIPT_NAME']
		scriptSplit = scriptNam.split('/')

		# Everything except the end which should be "entity.py"
		prefix = lib_util.uriRoot

		sys.stderr.write("SameServer prefix=%s key=%s\n" % ( prefix, key ) )
		if key.startswith( prefix ):
			return key[ len(prefix) : ]
		else:
			return ""

	def VirtualValue(self,key):

		# Mandatory to get "info" if running on a single-threaded server.
		# With Apache, this is not needed.
		infoDirectRun = True

		# This reads the information from a RDF script by executing it directly,
		# instead of loading its as an URL.
		if infoDirectRun:
			sys.stderr.write("Direct run\n")
			try:
				keySfx = self.KeySuffix(key)
				if keySfx != "" :
					return self.FromScript(keySfx)
			except Exception:
				exc = sys.exc_info()[1]
				sys.stderr.write("Exception %s when getting info for %s\n" % ( str(exc), key ) )
				pass

		# If too many errors happened when getting scripts information,
		# this is probable due to a time-out, itself maybe due to the
		# use of a simplistic web server.
		# Or: "urllib.error.HTTPError:HTTP Error 403: URLBlocked-Uncategorised-Unverified-HighPort"
		# In this case, this just return a dummy string.
		if self.m_errCount > 2 :
			self.m_errCount += 1
			return { "info" : "No info available (%d)" % self.m_errCount, "Status": False }
		infoDict = lib_common.DeserializeScriptInfo(key)
		sys.stderr.write("DeserializeScriptInfo => %s\n" % infoDict)
		try:
			infoStatus = infoDict["Status"]
		except KeyError:
			infoStatus = True

		if not infoStatus:
			self.m_errCount += 1
		else:
			self.m_errCount = 0
		return infoDict


