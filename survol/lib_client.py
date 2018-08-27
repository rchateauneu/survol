# This allows to easily handle Survol URLs in Jupyter or any other client.

import os
import sys
import json
import urllib

import lib_kbase
import lib_util
import lib_common

try:
	# For Python 3.0 and later
	from urllib.request import urlopen
except ImportError:
	# Fall back to Python 2's urllib2
	from urllib2 import urlopen

################################################################################

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
	def get_triplestore(self):
		docXmlRdf = self.get_content_moded("rdf")

		grphKBase = lib_kbase.triplestore_from_rdf_xml(docXmlRdf)
		return TripleStore(grphKBase)

	# If it does not have the necessary CGI args,
	# then loop on the existing objects of this class.
	# It is always True for merged sources,
	# because they do not have CGI arguments.
	def IsCgiComplete(self):
		print("SourceCgi.IsCgiComplete")
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
		print("SourceCgi.IsCgiComplete")
		return True


# Server("127.0.0.1:8000").CIM_Process(Handle=1234) and Server("192.168.0.1:8000").CIM_Datafile(Name='/tmp/toto.txt')
#
class SourceUrl (SourceCgi):
	def __init__(self,anUrl,className = None,**kwargs):
		self.m_url = anUrl
		super(SourceUrl, self).__init__(className,**kwargs)

	def Url(self):
		return self.m_url + "?" + self.UrlQuery()

	def __url_with_mode(self,mode):
		qryQuoted = self.UrlQuery(mode)
		fullQry = self.m_url + "?" + qryQuoted
		return fullQry

	def get_content_moded(self,mode):
		the_url = self.__url_with_mode(mode)

		sys.stderr.write("get_content_moded the_url=%s\n"%the_url)
		response = urlopen(the_url)
		data = response.read().decode("utf-8")
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

class SourceScript (SourceCgi):
	def __init__(self,aScript,className = None,**kwargs):
		self.m_script = aScript
		super(SourceScript, self).__init__(className,**kwargs)

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

		# This technique is also used by WSGI
		class OutputMachineString:
			def __init__(self):
				self.m_output = CreateStringStream()
				sys.stderr.write("OutputMachineString init type=%s\n"%type(self.m_output).__name__)

			# Do not write the header.
			def HeaderWriter(self,mimeType,extraArgs= None):
				sys.stderr.write("OutputMachineString HeaderWriter:%s\n"%mimeType)
				pass

			# The output will be available in a string.
			def OutStream(self):
				sys.stderr.write("OutputMachineString OutStream type=%s\n"%type(self.m_output).__name__)
				return self.m_output

			def GetStringContent(self):
				strResult = self.m_output.getvalue()
				self.m_output.close()
				return strResult

		sys.stderr.write("__execute_script_with_mode before render=%s\n"%lib_util.globalOutMach.__class__.__name__)
		outmachString = OutputMachineString()
		originalOutMach = lib_util.globalOutMach
		lib_util.globalOutMach = outmachString
		modu.Main()
		sys.stderr.write("__execute_script_with_mode before restore=%s\n"%lib_util.globalOutMach.__class__.__name__)

		# Restores the original stream.
		lib_util.globalOutMach = originalOutMach

		strResult = outmachString.GetStringContent()
		sys.stderr.write("__execute_script_with_mode strResult=%s\n"%strResult[:30])
		return strResult

	# This returns a string.
	def get_content_moded(self,mode):
		data_content = self.__execute_script_with_mode(mode)
		return data_content

	# TODO: It will be MUCH FASTER to return the content as a triplestore.
	# TODO: It will be MUCH FASTER to return the content as a triplestore.
	# TODO: It will be MUCH FASTER to return the content as a triplestore.
	# ... because no serialization will be needed.
	def get_triplestore(self):
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

	def get_triplestore(self):
		triplestoreA = self.m_srcA.get_triplestore()
		if self.IsCgiComplete():
			triplestoreB = self.m_srcB.get_triplestore()

			return self.m_operatorTripleStore(triplestoreA,triplestoreB)

		else:
			# The class cannot be None because the url is not complete

			def PredicateInstance(instanceUrl):
				( entity_label, entity_graphic_class, entity_id ) = lib_util.ParseEntityUri(instanceUrl)
				return entity_label == self.m_srcB.m_class

			objsList = lib_kbase.enumerate_class_instances(triplestoreA,PredicateInstance)

			for anObj in objsList:
				urlDerived = self.m_srcB.DeriveUrl(anObj)
				triplestoreB = urlDerived.get_triplestore()
				triplestoreA = self.m_operatorTripleStore(triplestoreA,triplestoreB)
			return TripleStore(triplestoreA)

	def get_content_moded(self,mode):
		tripstore = self.get_triplestore()
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
		super(SourceMergePlus, self).__init__(srcA,srcB,TripleStore.__plus__)

class SourceMergeMinus (SourceMerge):
	def __init__(self,srcA,srcB):
		super(SourceMergeMinus, self).__init__(srcA,srcB,TripleStore.__minus__)

################################################################################

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
		return TripleStore(lib_kbase.triplestore_add(self.m_triplestore,otherTriple.m_triplestore))

	# This executes simple WQL queries, whether this is WBEM or WMI or Survol data,
	# or all mixed together.
	def QueryWQL(self,className,**kwargs):
		return None

	def QuerySPARQL(self,qrySparql):
		return None

	# This creates an object for each unique URL, and if needed, its class.
	def GetInstances(self):
		return []


################################################################################

# TODO: Connect to a Jupyter Python kernel which will execute the Python scripts.
# Jupyter kernel is now a new type of agent, after Survol, WMI, WBEM and local execution in lib_client.
# Find a way to detect a Jupyter Kernel socket address. Or start it on request.

# TODO: Create the merge URL. What about a local script ?
# Or: A merged URL needs an agent anyway.