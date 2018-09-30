# This allows to easily handle Survol URLs in Jupyter or any other client.
import cgitb
cgitb.enable(format="txt")

import os
import sys
import json
import heapq
import urllib
import inspect

import lib_util
import lib_kbase
import lib_common
import lib_naming
from lib_properties import pc
import entity_dirmenu_only

################################################################################

try:
	# For Python 3.0 and later
	from urllib.request import urlopen
except ImportError:
	# Fall back to Python 2's urllib2
	from urllib2 import urlopen

try:
	# Python 2
	from urlparse import urlparse, parse_qs
except ImportError:
	from urllib.parse import urlparse, parse_qs


DEBUG("Tests")

################################################################################

# A SourceBase is a Survol URL or a script which returns a graph of urls
# of CIM objects, linked by properties. This graph can be formatted in XML-RDF,
# in JSON, in SVG, D3 etc...
# This URL or this script has no arguments, or, it comes with a CIM class name
# and the key-value pairs describing an unique CIM object.
class SourceBase (object):
	def __init__(self):
		self.m_current_triplestore = None

	# This returns the merge of the two urls.
	# Easy of two urls. What of one script and one url ?
	# TODO: Modify merge_scripts.py so it can handle urls and scripts.
	#
	def __add__(self, otherSource):
		return SourceMergePlus(self,otherSource)

	def __sub__(self, otherSource):
		return SourceMergeMinus(self,otherSource)

	# So it can be used with rdflib and its Sparql component.
	def content_rdf(self):
		return self.get_content_moded("rdf")

	# This returns a Json object.
	def content_json(self):
		strJson = self.get_content_moded("json")
		url_content = json.loads(strJson)
		return url_content

	# In the general case, it gets the content in RDF format and converts it
	# again to a triplestore. This always works if this is a remote host.
	def GetTriplestore(self):
		docXmlRdf = self.get_content_moded("rdf")

		grphKBase = lib_kbase.triplestore_from_rdf_xml(docXmlRdf)
		return TripleStore(grphKBase)

	# If it does not have the necessary CGI args,
	# then loop on the existing objects of this class.
	# It is always True for merged sources,
	# because they do not have CGI arguments.
	def IsCgiComplete(self):
		#print("SourceCgi.IsCgiComplete")
		return True

# If it has a class, then it has CGI arguments.
class SourceCgi (SourceBase):
	def __init__(self,className = None,**kwargs):
		self.m_className = className
		self.m_kwargs = kwargs
		super(SourceCgi, self).__init__()

	def UrlQuery(self,mode=None):
		suffix = ",".join( [ "%s=%s" % (k,v) for k,v in self.m_kwargs.items() ])
		if self.m_className:
			restQry = self.m_className + "." + suffix
		else:
			restQry = suffix
		quotedRest = urllib.quote(restQry)

		# TODO: See lib_util.xidCgiDelimiter = "?xid="
		qryArgs = "xid=" + quotedRest
		if mode:
			qryArgs += "&mode=" + mode

		return qryArgs

	# TODO: For the moment, this assumes that all CGI arguments are there.
	def IsCgiComplete(self):
		#print("SourceCgi.IsCgiComplete")
		return True

def LoadModedUrl(urlModed):
	DEBUG("LoadModedUrl.get_content_moded urlModed=%s",urlModed)
	response = urlopen(urlModed)
	data = response.read().decode("utf-8")
	return data


# Server("127.0.0.1:8000").CIM_Process(Handle=1234) and Server("192.168.0.1:8000").CIM_Datafile(Name='/tmp/toto.txt')
#
class SourceRemote (SourceCgi):
	def __init__(self,anUrl,className = None,**kwargs):
		self.m_url = anUrl
		super(SourceRemote, self).__init__(className,**kwargs)

	def __str__(self):
		return "URL=" + self.Url()

	def Url(self):
		return self.m_url + "?" + self.UrlQuery()

	def __url_with_mode(self,mode):
		qryQuoted = self.UrlQuery(mode)
		fullQry = self.m_url + "?" + qryQuoted
		return fullQry

	def get_content_moded(self,mode):
		the_url = self.__url_with_mode(mode)
		data = LoadModedUrl(the_url)
		return data

def CreateStringStream():
	try:
		# Python 3
		from io import StringIO
	except ImportError:
		try:
			from cStringIO import StringIO
		except ImportError:
			from StringIO import StringIO
	return StringIO()
	#from io import BytesIO
	#return BytesIO

class SourceLocal (SourceCgi):
	def __init__(self,aScript,className = None,**kwargs):
		self.m_script = aScript
		super(SourceLocal, self).__init__(className,**kwargs)

	def __str__(self):
		return "SCRIPT=" + self.m_script + "?" + self.UrlQuery()

	# This executes the script and return the data in the right format.
	def __execute_script_with_mode(self,mode):
		# Sets an envirorment variable then imports the script and execute it.
		# TODO: "?" or "&"

		urlDirNam = os.path.dirname(self.m_script)

		# The directory of the script is used to build a Python module name.
		moduNam = urlDirNam.replace("/",".")

		urlFilNam = os.path.basename(self.m_script)

		modu = lib_util.GetScriptModule(moduNam, urlFilNam)

		# SCRIPT_NAME=/survol/print_environment_variables.py
		os.environ["SCRIPT_NAME"] = "/" + self.m_script
		# QUERY_STRING=xid=class.k=v
		os.environ["QUERY_STRING"] = self.UrlQuery(mode)

		# This technique of replacing the output object is also used by WSGI
		class OutputMachineString:
			def __init__(self):
				self.m_output = CreateStringStream()
				#sys.stderr.write("OutputMachineString init type=%s\n"%type(self.m_output).__name__)

			# Do not write the header.
			def HeaderWriter(self,mimeType,extraArgs= None):
				#sys.stderr.write("OutputMachineString HeaderWriter:%s\n"%mimeType)
				pass

			# The output will be available in a string.
			def OutStream(self):
				#sys.stderr.write("OutputMachineString OutStream type=%s\n"%type(self.m_output).__name__)
				return self.m_output

			def GetStringContent(self):
				strResult = self.m_output.getvalue()
				self.m_output.close()
				return strResult

		DEBUG("__execute_script_with_mode before module=%s",modu.__name__)
		outmachString = OutputMachineString()
		originalOutMach = lib_util.globalOutMach
		lib_util.globalOutMach = outmachString
		try:
			modu.Main()
		except Exception as ex:
			ERROR("__execute_script_with_mode before module=%s: Caught:%s",modu.__name__,ex)

		# Restores the original stream.
		lib_util.globalOutMach = originalOutMach

		strResult = outmachString.GetStringContent()
		# sys.stderr.write("__execute_script_with_mode strResult=%s\n"%strResult[:30])
		return strResult

	# This returns a string.
	# It runs locally: When using only the local node, no web server is needed.
	def get_content_moded(self,mode):
		data_content = self.__execute_script_with_mode(mode)
		return data_content

	# TODO: At the moment, this serializes an rdflib triplestore into a XML-RDF buffer,
	# TODO: which is parsed again by rdflib into a triplestore,
	# TODO: and then this triplestore is looped on, to extract the instances.
	# TODO: It would be much faster to avoid this useless serialization/deserialization.
	def GetTriplestore(self):
		docXmlRdf = self.get_content_moded("rdf")

		grphKBase = lib_kbase.triplestore_from_rdf_xml(docXmlRdf)
		return TripleStore(grphKBase)


class SourceMerge (SourceBase):
	def __init__(self,srcA,srcB,operatorTripleStore):
		if not srcA.IsCgiComplete():
			raise Exception("Left-hand-side URL must be complete")
		self.m_srcA = srcA
		self.m_srcB = srcB
		# Plus or minus
		self.m_operatorTripleStore = operatorTripleStore
		super(SourceMerge, self).__init__()

	def GetTriplestore(self):
		triplestoreA = self.m_srcA.GetTriplestore()
		if self.IsCgiComplete():
			triplestoreB = self.m_srcB.GetTriplestore()

			return self.m_operatorTripleStore(triplestoreA,triplestoreB)

		else:
			# The class cannot be None because the url is not complete

			objsList = lib_kbase.enumerate_instances(triplestoreA)

			for instanceUrl in objsList:
				( entity_label, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(instanceUrl)
				if entity_label == self.m_srcB.m_class:
					urlDerived = self.m_srcB.DeriveUrl(instanceUrl)
					triplestoreB = urlDerived.GetTriplestore()
					triplestoreA = self.m_operatorTripleStore(triplestoreA,triplestoreB)
			return TripleStore(triplestoreA)

	def get_content_moded(self,mode):
		tripstore = self.GetTriplestore()
		if mode == "rdf":
			strStrm = CreateStringStream()
			tripstore.ToStreamXml(strStrm)
			strResult = strStrm.getvalue()
			strStrm.close()
			return strResult

		raise Exception("get_content_moded: Cannot yet convert to %s"%mode)

# Function UrlToMergeD3()

class SourceMergePlus (SourceMerge):
	def __init__(self,srcA,srcB):
		super(SourceMergePlus, self).__init__(srcA,srcB,TripleStore.__add__)

class SourceMergeMinus (SourceMerge):
	def __init__(self,srcA,srcB):
		super(SourceMergeMinus, self).__init__(srcA,srcB,TripleStore.__sub__)

################################################################################

# A bit simpler because it is not needed to explicitely handle the url.
def CreateSource(script,className = None,urlRoot = None,**kwargs):
	if urlRoot:
		return SourceRemote(urlRoot,className,**kwargs)
	else:
		return SourceLocal(script,className,**kwargs)
################################################################################

# https://stackoverflow.com/questions/15247075/how-can-i-dynamically-create-derived-classes-from-a-base-class

class BaseCIMClass(object):
	def __init__(self,agentUrl, entity_id):
		self.m_agentUrl = agentUrl
		self.m_entity_id = entity_id

	# TODO: This could be __repr__ also.
	def __str__(self):
		return self.__class__.__name__ + "." + self.m_entity_id

	# This returns the list of Sources (URL or local sources) usable for this entity.
	# This can be a tree ? Or a flat list ?
	# Each source can return a triplestore.
	# This allows the discovery of a machine and its neighbours,
	# discovery with A* algorithm or any exploration heuristic etc....
	def GetScripts(self):
		if self.m_agentUrl:
			return self.GetScriptsRemote()
		else:
			return self.GetScriptsLocal()

	def GetScriptsRemote(self):
		# We expect a contextual menu in JSON format, not a graph.
		urlScripts = self.m_agentUrl + "/survol/entity_dirmenu_only.py" + "?xid=" + self.__class__.__name__ + "." + self.m_entity_id + "&mode=menu"
		DEBUG("GetScriptsRemote self.m_agentUrl=%s urlScripts=%s",self.m_agentUrl,urlScripts)

		# Typical content:
		# {
		# 	"http://rchateau-HP:8000/survol/sources_types/CIM_Directory/dir_stat.py?xid=CIM_Directory.Name%3DD%3A": {
		# 		"name": "Directory stat information",
		# 		"url": "http://rchateau-HP:8000/survol/sources_types/CIM_Directory/dir_stat.py?xid=CIM_Directory.Name%3DD%3A"
		# 	},
		# 	"http://rchateau-HP:8000/survol/sources_types/CIM_Directory/file_directory.py?xid=CIM_Directory.Name%3DD%3A": {
		# 		"name": "Files in directory",
		# 		"url": "http://rchateau-HP:8000/survol/sources_types/CIM_Directory/file_directory.py?xid=CIM_Directory.Name%3DD%3A"
		# 	}
		# }
		dataJsonStr = LoadModedUrl(urlScripts)
		dataJson = json.loads(dataJsonStr)

		# The scripts urls are the keys of the Json object.
		listSources = [ ScriptUrlToSource(oneScr) for oneScr in dataJson]
		return listSources

	# This is much faster than using the URL of a local server.
	# Also: Such a server is not necessary.
	def GetScriptsLocal(self):
		#sys.stdout.write("GetScriptsLocal: class=%s entity_id=%s\n"%(self.__class__.__name__,self.m_entity_id))

		listScripts = []

		# This function is called for each script which applies to the given entity.
		# It receives a triplet: (subject,property,object) and the depth in the tree.
		# Here, this simply stores the scripts in a list. The depth is not used yet.
		def CallbackGrphAdd( trpl, depthCall ):
			#sys.stdout.write("CallbackGrphAdd:%s %d\n"%(str(trpl),depthCall))
			aSubject,aPredicate,anObject = trpl
			if aPredicate == pc.property_script:
				# Directories of scripts are also labelled with the same predicate
				# although they are literates and not urls.
				if not lib_kbase.IsLiteral(anObject):
					listScripts.append( anObject )
					#sys.stdout.write("CallbackGrphAdd: anObject=%s %s\n"%(str(type(anObject)),str(anObject)))

		flagShowAll = False

		# Beware if there are subclasses.
		entity_type = self.__class__.__name__
		entity_host = None # To start with
		rootNode = None # The top-level is script is not necessary.

		#sys.stdout.write("lib_util.gblTopScripts=%s\n"%lib_util.gblTopScripts)

		entity_dirmenu_only.DirToMenu(CallbackGrphAdd,rootNode,entity_type,self.m_entity_id,entity_host,flagShowAll)

		listSources = [ ScriptUrlToSource(oneScr) for oneScr in listScripts]
		return listSources


	# Survol is a graph database: https://en.wikipedia.org/wiki/Graph_database
	# On top of this, each instance points to a scripts which can return instances,
	# and enrich the graph database: This is necesary because the quantity of information
	# varies at each moment, and is of infinite size.
	# This explores the scripts of each instance, uses the A* algorithm.
	def FindPathToInstance(self,instanceDestination,maxDepth):

		print("TODO: %s Not implemented yet"%inspect.stack()[0][3])

		# Heuristiques tres specifiques: On utilise des regles pour trier la liste.
		# Utiliser les protections pour savoir si un process peut atteindre un fichier.
		# Liens symboliques.
		# Creer une espece de distance entre deux instances. Qui tient compte des hosts.
		# Mais aussi, il faut pouvoir suggerer un script plutot qu'un autre:
		# Si process et fichier, suggerer de chercher aussi dans les noms de fichiers
		# qui apparaissent dans la memoire du process.

		# chercher de A vers B mais aussi de B vers A ?



		listSteps = []
		return listSteps


	def InstanceGrepFromContent(self,searchString):
		"""This returns a list of StringOccurrenceBase derived objects.
		It could return an iterator, if the research is very slow."""

		# Each instance has a list of objects deriving from this base class,
		# which model the occurrence of a specific string in a CIM object.
		# Indexed by instances, possibly several occurrences, with the context.
		# TODO: Or maybe should return a list of instances ?
		# TODO: What can we do with a list of detected strings ?
		# TODO: ... display them as an information snippet ? Survol does not have this concept (yet).
		class StringOccurrenceBase:
			def __str__(self):
				# This is completely specific to the CIM class, for example:
				# - CIM_DataFile: Line or offset number.
				# - CIM_Process: Memory segment, or environment variable ?
				# - Oracle table: Which record, which column.
				return ""

		# It is not very elegant to give a this method to BaseCIMClass when its legitimate derived classes
		# must use a "static" function from their module.


		entity_type = self.__class__.__name__
		entity_module = lib_util.GetEntityModule(entity_type)
		if entity_module:
			try:
				# This function searches for a string or a regular expression,
				# and returns the occurrences as list subclasses of StringOccurrenceBase.
				# The search mechanism is different, depending on the class: Search from a file, a database etc...
				entity_module.ModuleGrepFromContent(entity_type, self.m_entity_id, searchString)
			except AttributeError:
				exc = sys.exc_info()[1]
				INFO("No ModuleGrepFromContent for module=%s %s %s: %s", entity_module.__name__, entity_type, self.m_entity_id, str(exc) )

		return []


	# This might be a regular expression ?
	# What to do with RDB and SQL expressions ?
	def FindStringFromNeighbour(self,searchString,maxDepth):
		# Heuristics and specialization per class.

		mapInstancesToOccurrences = {}

		priorityQueue = []
		visitedInstances = set()

		def LessThan(selfInstance, otherInstance):
			"""This is for the heap priority queue when walking on the triplestores graph.
			This models the reasonable probabily to find a specific string.
			Some criterias:
			- Not many strings in binary files.
			- Database tables with only numeric tables.
			- A directory always comes at the end because it does not contain anything.
			"""
			# TODO: It is very difficult to sort instances with no idea of the context, the type of string to search etc...
			# TODO: The sort function would be very different when searching for a path between two instances.
			print("self=%s"%selfInstance)
			print("other=%s"%otherInstance)
			print("TODO: %s Not implemented yet"%inspect.stack()[0][3])
			exit(0)

			return False


		def PushInstance(theInst,theDepth):
			theInst.m_current_depth = theDepth
			theInst.__lt__ = LessThan
			heapq.heappush( priorityQueue, theInst)

		PushInstance( self, 0 )

		# Search in the instance based on a specific function.
		# If found, add to the list of results.

		while True:
			try:
				bestInstance = heapq.heappop(priorityQueue)
			except IndexError:
				# Empty priority queue.
				break
			visitedInstances.add(bestInstance)

			listOccurrences = bestInstance.InstanceGrepFromContent(searchString)
			if listOccurrences:
				# Maybe it found some occurrences.
				# TODO: It could be very slow, so we could instead store asynchronous iterators,
				# TODO: which would be calculated while we are iterating on other nodes.
				# TODO: Consider a map-reduce framework ...
				# TODO: ... but beware of accessibility.
				mapInstancesToOccurrences[bestInstance] = listOccurrences

			currDepth = bestInstance.m_current_depth + 1

			if currDepth < maxDepth:
				lstScripts = bestInstance.GetScripts()
				INFO("bestInstance=%s",bestInstance)
				for oneScript in lstScripts:
					INFO("oneScript=%s",oneScript)
					lib_common.ErrorMessageEnable(False)
					try:
						lstScriptInstances = oneScript.GetTriplestore().GetInstances()
					except Exception as ex:
						ERROR("FindStringFromNeighbour: %s",ex)
					lib_common.ErrorMessageEnable(True)
					for oneInstance in lstScriptInstances:
						DEBUG("bestInstance=%s currDepth=%d Script=%s",bestInstance,currDepth,oneInstance)
						if oneInstance not in visitedInstances:
							try:
								# If the node is already seen, and closer as expected.
								# We might have rejected it before ?
								if oneInstance.m_current_depth > currDepth:
									oneInstance.m_current_depth = currDepth
							except AttributeError:
								PushInstance( oneInstance, currDepth )

		return mapInstancesToOccurrences

def KWArgsToEntityId(**kwargs):
	entity_id = ""
	delim = ""
	for key, value in kwargs.items():
		# TODO: The values should be encoded !!!
		entity_id += delim + "%s=%s" % (key,value)
		delim = ","
	return entity_id

def CIMClassFactoryNoCache(className):
	def __init__(self, agentUrl, **kwargs):
		"""This function will be used as a constructor for the new class."""
		for key, value in kwargs.items():
			setattr(self, key, value)
		entity_id = KWArgsToEntityId(**kwargs)
		BaseCIMClass.__init__(self,agentUrl, entity_id)

	if sys.version_info < (3,0):
		# Python 2 does not want Unicode class name.
		className = className.encode()

	# sys.stderr.write("className: %s/%s\n"%(str(type(className)),className))
	newclass = type(className, (BaseCIMClass,),{"__init__": __init__})
	return newclass

cacheCIMClasses = {}

def CreateCIMClass(agentUrl,className,**kwargs):
	global cacheCIMClasses
	entity_id = KWArgsToEntityId(**kwargs)

	instanceRepr = className + "." + entity_id
	if instanceRepr.startswith("CIM_Directory.Name=C:\\"):
		exit(0)
	DEBUG("CREATE className%s %s",className,instanceRepr)

	try:
		newCIMClass = cacheCIMClasses[className]
		DEBUG("Found class=%s",className)

		try:
			newInstance = newCIMClass.m_instancesCache[instanceRepr]
			DEBUG("Found instance class=%s instance=%s",className,instanceRepr)
			return newInstance
		except KeyError:
			INFO("Creating instance=%s",instanceRepr)
			# This instanceis not yet created.
			pass
	except KeyError:
		# This class is not yet created.
		# TODO: If entity_label contains slashes, submodules must be imported.
		INFO("Creating class=%s",className)
		newCIMClass = CIMClassFactoryNoCache(className)
		cacheCIMClasses[className] = newCIMClass
		newCIMClass.m_instancesCache = {}

	# Now, it creates a new instance and stores it in the cache of the CIM class.
	newInstance = newCIMClass(agentUrl, **kwargs)
	newCIMClass.m_instancesCache[instanceRepr] = newInstance
	return newInstance

################################################################################
# instanceUrl="http://LOCAL_MODE:80/NotRunningAsCgi/entity.py?xid=Win32_Group.Domain=local_mode,Name=Replicator"
# instanceUrl=http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=addr.Id=127.0.0.1:427
# instanceUrl="http://rchateau-hp:8000/survol/sources_types/memmap/memmap_processes.py?xid=memmap.Id%3DC%3A%2FWindows%2FSystem32%2Fen-US%2Fkernel32.dll.mui"
def InstanceUrlToAgentUrl(instanceUrl):
	DEBUG("InstanceUrlToAgentUrl instanceUrl=%s",instanceUrl)

	parse_url = urlparse(instanceUrl)
	if parse_url.path.startswith(lib_util.prefixLocalScript):
		return None

	idxSurvol = instanceUrl.find("/survol")
	agentUrl = instanceUrl[:idxSurvol]

	DEBUG("InstanceUrlToAgentUrl agentUrl=%s",agentUrl)
	if agentUrl and agentUrl.endswith("hos"):
		exit(0)
	return agentUrl

# This wraps rdflib triplestore.
# rdflib objects and subjects can be handled as WMI or WBEM objects.
class TripleStore:
	# In this context, this is most likely a rdflib object.
	def __init__(self,grphKBase = None):
		self.m_triplestore = grphKBase

	def ToStreamXml(self,strStrm):
			lib_kbase.triplestore_to_stream_xml(self.m_triplestore,strStrm)

	# This merges two triplestores. The package rdflib does exactly that,
	# but it is better to isolate from it, just in case another triplestores
	# implementation would be preferable.
	def __add__(self, otherTriple):
		return TripleStore(lib_kbase.triplestore_add(self.m_triplestore,otherTriple.m_triplestore))

	def __sub__(self, otherTriple):
		return TripleStore(lib_kbase.triplestore_sub(self.m_triplestore,otherTriple.m_triplestore))

	def __len__(self):
		return len(self.m_triplestore)

	# This executes simple WQL queries, whether this is WBEM or WMI or Survol data,
	# or all mixed together.
	def QueryWQL(self,className,**kwargs):
		return None

	def QuerySPARQL(self,qrySparql):
		return None

	# This creates a CIM object for each unique URL, subject or object found in a triplestore.
	# If needed, the CIM class is created on-the-fly.
	def GetInstances(self):
		#import cgitb
		#cgitb.enable(format="txt")

		INFO("GetInstances")
		objsSet = lib_kbase.enumerate_instances(self.m_triplestore)
		lstInstances = []
		for instanceUrl in objsSet:
			# sys.stderr.write("GetInstances instanceUrl=%s\n"%instanceUrl)
			( entity_label, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(instanceUrl)
			# Tries to extract the host from the string "Key=Val,Name=xxxxxx,Key=Val"
			# BEWARE: Some arguments should be decoded.
			DEBUG("GetInstances instanceUrl=%s entity_graphic_class=%s entity_id=%s",instanceUrl,entity_graphic_class,entity_id)

			xidDict = { sp[0]:sp[2] for sp in [ ss.partition("=") for ss in entity_id.split(",") ] }

			# This parsing that all urls are not scripts but just define an instance
			# and therefore have the form "http://.../entity.py?xid=...",
			agentUrl = InstanceUrlToAgentUrl(instanceUrl)

			newInstance = CreateCIMClass(agentUrl,entity_graphic_class, **xidDict)
			lstInstances.append(newInstance)
		return lstInstances


################################################################################

# This receives an URL, parses it and creates a Source object.
# It is able to detect if the URL is local or not.
# Input examples:
# "http://LOCAL_MODE:80/NotRunningAsCgi/sources_types/Win32_UserAccount/Win32_NetUserGetGroups.py?xid=Win32_UserAccount.Domain%3Drchateau-hp%2CName%3Drchateau"
# "http://rchateau-HP:8000/survol/sources_types/CIM_Directory/doxygen_dir.py?xid=CIM_Directory.Name%3DD%3A"
def ScriptUrlToSource(callingUrl):

	parse_url = urlparse(callingUrl)
	query = parse_url.query

	params = parse_qs(query)

	xidParam = params['xid'][0]
	# sys.stdout.write("ScriptUrlToSource xidParam=%s\n"%xidParam)
	(entity_type,entity_id,entity_host) = lib_util.ParseXid( xidParam )
	# sys.stdout.write("ScriptUrlToSource entity_id=%s\n"%entity_id)
	entity_id_dict = lib_util.SplitMoniker(entity_id)
	# sys.stdout.write("entity_id_dict=%s\n"%str(entity_id_dict))

	# parse_url.path=/NotRunningAsCgi/sources_types/Win32_UserAccount/Win32_NetUserGetInfo.py
	# This is a very simple method to differentiate local from remote scripts
	if parse_url.path.startswith(lib_util.prefixLocalScript):
		# This also chops the leading slash.
		pathScript = parse_url.path[len(lib_util.prefixLocalScript)+1:]
		objSource = SourceLocal(pathScript,entity_type,**entity_id_dict)

		# Note: This should be True: parse_url.netloc.startswith("LOCAL_MODE")
	else:
		objSource = SourceRemote(callingUrl,entity_type,**entity_id_dict)

	return objSource

################################################################################

# This models a Survol agent, or the local execution of survol scripts.
class Agent:
	def __init__(self,agent_url = None):
		self.m_agent_url = agent_url

	# This allows the creation of CIM instances.
	def __getattr__(self, attribute_name):

		class CallDispatcher(object):
			def __init__(self, caller, agent_url, name):
				#sys.stdout.write("CallDispatcher.__init__ agent=%s name=%s\n"%(str(type(agent_url)),name))
				#sys.stdout.flush()
				self.m_name = name
				self.m_caller = caller
				self.m_agent_url = agent_url

			def __call__(self, *argsCall, **kwargsCall):
				#sys.stdout.write("CallDispatcher.__call__ class=%s url=%s\n"%(self.m_name,str(type(self.m_agent_url))))
				#sys.stdout.flush()
				newInstance = CreateCIMClass(self.m_agent_url, self.m_name, **kwargsCall)
				return newInstance

			def __getattr__(self, attribute_name):
				#sys.stdout.write("CallDispatcher.__getattr__ attr=%s\n"%(str(attribute_name)))
				#sys.stdout.flush()
				return CallDispatcher(self, self.m_agent_url, self.m_name + "/" + attribute_name)

		#sys.stdout.write("Agent.__getattr__ attr=%s\n"%(str(attribute_name)))
		return CallDispatcher(self, self.m_agent_url, attribute_name)


################################################################################

# TODO: Connect to a Jupyter Python kernel which will execute the Python scripts.
# Jupyter kernel is now a new type of agent, after Survol, WMI, WBEM and local execution in lib_client.
# Find a way to detect a Jupyter Kernel socket address. Or start it on request.

# TODO: Create the merge URL. What about a local script ?
# Or: A merged URL needs an agent anyway.

################################################################################

