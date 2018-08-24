# This allows to easily handle Survol URLs in Jupyter or any other client.

import os
import json
import lib_kbase
import lib_util

try:
	# For Python 3.0 and later
	from urllib.request import urlopen
except ImportError:
	# Fall back to Python 2's urllib2
	from urllib2 import urlopen


class SourceBase (object):
	def __init__(self):
		self.m_current_triplestore = None

	# from IPython.display import HTML
	# HTML(url="http://vps516494.ovh.net/Survol/survol/sources_types/enumerate_CIM_Process.py?xid=.&mode=html")
	# Call this with **kwargs operator: HTML( **mySource.pair_html() )
	def pair_html(self,mode):
		return self.__pair_display("html")

	# from IPython.display import SVG
	# SVG(url='http://vps516494.ovh.net/Survol/survol/entity.py?xid=Linux/cgroup.Name=memory')
	# Call this with **kwargs operator: SVG( **mySource.pair_svg() )
	def pair_svg(self,mode):
		return self.__pair_display("svg")

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

	def content_json(self):
		return self.get_content_moded("json")

	def get_triplestore(self):
		docXmlRdf = self.get_content_moded("rdf")

		return lib_kbase.triplestore_from_rdf_xml(docXmlRdf)

	# It has to calculate the content, except if all sub-sources are URLs
	# on the same Survol server, and in this calse only it can combine them
	# with the script merge_scripts.py .
	# In the general case, we are sure to have the content in RDF mode.
	def __pair_display(self,mode):
		aTriplestore = self.get_triplestore()
		# This is done in lib_common when displaying a RDF triplestore.
		contentModed = lib_common.triplestore_to_mode(aTriplestore,mode)

		return { "data" : contentModed }

# If it has a class, then it has CGI arguments.
class SourceCgi (SourceBase):
	def __init__(self,className = None,**kwargs):
		self.m_className = className
		self.m_kwargs = kwargs
		super(SourceCgi, self).__init__()

	def Query(self):
		suffix = ",".join( [ "%s=%s" % (k,v) for k,v in self.m_kwargs.items() ])
		if self.m_className:
			return "?xid=" + self.m_className + "." + suffix
		else:
			return "?xid=." + suffix


	# If it does not have the necessary CGI args,
	# then loop on the existing objects of this class.
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
		return self.m_url + self.Query()

	def __url_with_mode(self,mode):
		fullQry = self.m_url
		fullQry += self.Query()
		if fullQry.find("&") < 0 and fullQry.find("?") < 0:
			return fullQry + "?mode=" + mode
		else:
			return fullQry + "&mode=" + mode

	# Output formats HTML, SVG, JSON, RDF. All are processed differently, so there is no need to unify.
	def __pair_display(self,mode):
		the_url = self.__url_with_mode(mode)

		# Add the extension "?mode=html" or "svg" etc...
		return { "url" : the_url }

	def get_content_moded(self,mode):
		the_url = self.__url_with_mode(mode)

		print("get_content_moded the_url=%s"%the_url)
		response = urlopen(the_url)
		data = response.read().decode("utf-8")
		url_content = json.loads(data)
		return url_content

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
		# aScript = "local_scripts_prefix/" + self.m_script + "?mode=" + mode
		# print("aScript=",aScript)

		# On change la socket, ca ne va pas ecrire dans stdout mais dans un socket a nous dont
		print("on prendra le contenu apres Main()")

		modu.Main()

	# Output formats HTML, SVG, JSON, RDF. All are processed differently, so there is no need to unify.
	def __pair_display(self,mode):
		data_content = self.__execute_script_with_mode("html")
		return { "data" : data_content }

	def get_content_moded(self,mode):
		data_content = self.__execute_script_with_mode(mode)
		return data_content

	def get_triplestore(self):
		ExecutethecodelocallyandreturntheRDFobject()


class SourceMerge (SourceBase):
	def __init__(self,srcA,srcB):
		if not srcA.IsCgiComplete():
			raise Exception("Left-hand-side URL must be complete")
		self.m_srcA = srcA
		self.m_srcB = srcB
		super(SourceMerge, self).__init__()

	def get_content(self,current_triplestore):
		triplestoreA = self.m_srcA.get_triplestore()
		if self.IsCgiComplete():
			triplestoreB = self.m_src_B.get_triplestore()

			return self.combine_triplestores(triplestoreA,triplestoreB)

		else:
			# The class cannot be None because the url is not complete
			objsList = lib_kbase.enumerate_objects_from_class(triplestoreA,self.m_src_B.m_class)

			for anObj in objsList:
				urlDerived = self.m_src_B.DeriveUrl(anObj)
				triplestoreB = urlDerived.get_triplestore()
				triplestoreA = self.combine_triplestores(triplestoreA,triplestoreB)
			return triplestoreA



# Function UrlToMergeD3()

class SourceMergePlus (SourceMerge):
	def __init__(self,srcA,srcB):
		super(SourceMergePlus, self).__init__(srcA,srcB)

	@staticmethod
	def combine_triplestores(triplestoreA,triplestoreB):
		return triplestoreA + triplestoreB

class SourceMergeMinus (SourceMerge):
	def __init__(self,srcA,srcB):
		super(SourceMergeMinus, self).__init__(srcA,srcB)

	@staticmethod
	def combine_triplestores(triplestoreA,triplestoreB):
		return triplestoreA - triplestoreB



# TODO: Connect to a Jupyter Python kernel which will execute the Python scripts.
# Jupyter kernel is now a new type of agent, after Survol, WMI, WBEM and local execution in lib_client.
# Find a way to detect a Jupyter Kernel socket address. Or start it on request.

# TODO: Create the merge URL. What about a local script ?
# Or: A merged URL needs an agent anyway.